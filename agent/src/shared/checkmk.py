# --- Checkmk-agent bridge, shared by both lines (§25/DR-10) ------------------
# The agent runs a Checkmk agent script and ships its raw output; parsing (or
# forwarding) is the dashboard's job. Each line defines, before this block:
#   _CHECKMK_PLATFORMS     platforms this line runs the script on
#   _CHECKMK_DEPLOY_PATH   where checkmk.update writes our signed copy
#   _CHECKMK_CANDIDATES    scripts to try, first usable wins
#   _CHECKMK_TRANSPORT_ONLY  True = the dashboard must not read values from
#                          the output (it only forwards it)
#   _checkmk_argv(path)    how to start the script
#   _checkmk_wanted()      whether to run at all right now
#   _checkmk_failure(rc, raw)  why a finished run does not count, or None
_CHECKMK_TIMEOUT = 30  # stock sections finish in ~1-3s; local plugins get headroom
_CHECKMK_MAX = 2_000_000  # raw cap — a runaway plugin must not blow the WS frame
# Own clock (not every push): the script runs at most once per interval and the
# payload says so, so the dashboard (and anything it forwards the output to) knows
# when the next one is due. A push in between ships no output; the dashboard keeps
# the last run's sections until then.
_CHECKMK_INTERVAL = 60
# status.refresh runs collect_all in an executor thread next to the push loop; a
# second run must never start while one is going.
_CHECKMK_LOCK = threading.Lock()
_CHECKMK_SECTION_RE = re.compile(rb"^<<<[^<>\n]+>>>\r?$", re.M)


def _checkmk_script() -> str | None:
    """Path of the first usable Checkmk agent script, or None."""
    for path in _CHECKMK_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _checkmk_script_sha() -> str:
    """sha256 of our managed Checkmk script ('' when absent / other platform).

    Always the managed copy, also while an installed agent is the one that
    runs: the backend compares this with the script it serves and pushes
    checkmk.update on a difference, so an installed agent's sha would make
    it push on every connect.
    """
    if detect_platform() not in _CHECKMK_PLATFORMS:
        return ""
    try:
        with open(_CHECKMK_DEPLOY_PATH, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return ""


def _cmd_checkmk_update(params: dict) -> dict:
    """Deploy/refresh the vendored Checkmk agent script (§25/DR-10).

    Root-executed code from the server — same trust chain as agent.update:
    the sha256 must match AND the Ed25519 signature must verify against the
    baked _UPDATE_PUBKEY (dev skip only via the explicit opt-ins), BEFORE
    anything is written. Writes atomically (tmp + rename) so a crashed deploy
    never leaves a torn script.
    """
    if detect_platform() not in _CHECKMK_PLATFORMS:
        return {"success": False, "output": "checkmk deploy is not supported on this platform"}
    try:
        code = base64.b64decode(params.get("code", ""), validate=True)
    except (ValueError, TypeError):
        return {"success": False, "output": "invalid code encoding"}
    if not code:
        return {"success": False, "output": "empty code"}
    sha = hashlib.sha256(code).hexdigest()
    if sha != (params.get("sha256") or "").lower():
        return {"success": False, "output": "sha256 mismatch"}
    if not _skip_sig_check() and not _signature_ok(code, params.get("signature", "")):
        return {"success": False, "output": "signature verification failed"}
    directory = os.path.dirname(_CHECKMK_DEPLOY_PATH)
    try:
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".checkmk-")
        with os.fdopen(fd, "wb") as f:
            f.write(code)
        os.chmod(tmp, 0o755)
        os.replace(tmp, _CHECKMK_DEPLOY_PATH)
    except OSError as exc:
        return {"success": False, "output": "write failed: %s" % exc}
    return {"success": True, "output": "check_mk_agent deployed (%s)" % sha[:12], "sha256": sha}


def collect_checkmk() -> dict:
    """Raw Checkmk-agent output for the dashboard (section ``checkmk_raw``).

    Pure transport (DR-10): run the Checkmk agent script, ship stdout as
    gzip+base64. Other platform / not wanted / no script / failure / empty /
    oversize → {} so the backend never sees a checkmk_raw section and emits no
    checks (absent data must never alarm). Oversize output is dropped, not
    truncated — a cut section boundary would parse as garbage.

    Runs at most once per _CHECKMK_INTERVAL and never twice at the same time;
    a push in between gets {} (the dashboard carries the last run's sections).
    Every run leaves its verdict in _STATE.checkmk_status (collect_checkmk_status).
    """
    if detect_platform() not in _CHECKMK_PLATFORMS or not _checkmk_wanted():
        return {}
    if not _CHECKMK_LOCK.acquire(blocking=False):
        return {}  # a run is still going (status.refresh next to the push loop)
    try:
        now = time.monotonic()
        if _STATE.checkmk_ts and now - _STATE.checkmk_ts < _CHECKMK_INTERVAL:
            return {}
        _STATE.checkmk_ts = now
        payload, status = _run_checkmk()
        _STATE.checkmk_status = status
        return payload
    finally:
        _CHECKMK_LOCK.release()


def collect_checkmk_status() -> dict:
    """Verdict of the run of this cycle (section ``checkmk_status``), else {}:
    {"ok", "reason", "sections", "interval"} — a reason in a few words, never
    the output."""
    status, _STATE.checkmk_status = _STATE.checkmk_status, None
    return dict(status) if status else {}


def _checkmk_status(ok: bool, reason: str = "", sections: int = 0) -> dict:
    return {"ok": ok, "reason": reason, "sections": sections, "interval": _CHECKMK_INTERVAL}


def _checkmk_sections(raw: bytes) -> int:
    """Number of section headers (<<<name>>>; piggyback <<<<host>>>> not counted)."""
    return len(_CHECKMK_SECTION_RE.findall(raw))


def _checkmk_exec(argv: list) -> tuple:
    """(exit code, stdout) of the script; raises subprocess.TimeoutExpired.

    Own process group, killed whole on timeout: the script's pipelines and
    subshells must not outlive it."""
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        out, _err = proc.communicate(timeout=_CHECKMK_TIMEOUT)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        raise
    return proc.returncode, out or b""


def _run_checkmk() -> tuple:
    """One run of the Checkmk script → (checkmk_raw payload or {}, status)."""
    script = _checkmk_script()
    if script is None:
        return {}, _checkmk_status(False, "script missing")
    try:
        rc, raw = _checkmk_exec(_checkmk_argv(script))
    except subprocess.TimeoutExpired:
        return {}, _checkmk_status(False, "timed out after %d s" % _CHECKMK_TIMEOUT)
    except OSError:
        return {}, _checkmk_status(False, "could not start the script")
    if not raw:
        return {}, _checkmk_status(False, "no output")
    if len(raw) > _CHECKMK_MAX:
        log.warning("checkmk output skipped: %d bytes exceeds cap", len(raw))
        return {}, _checkmk_status(False, "output larger than 2 MB")
    sections = _checkmk_sections(raw)
    failure = _checkmk_failure(rc, raw)
    if failure:
        return {}, _checkmk_status(False, failure, sections)
    payload = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "output_gz_b64": base64.b64encode(gzip.compress(raw)).decode(),
        "interval": _CHECKMK_INTERVAL,
    }
    if _CHECKMK_TRANSPORT_ONLY:
        payload["transport_only"] = True
    return payload, _checkmk_status(True, "", sections)
