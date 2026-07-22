# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
def _self_path() -> str:
    return os.environ.get("AGENT_SELF_PATH") or os.path.abspath(__file__)


def _marker_path() -> str:
    return _self_path() + ".updating"


def _backup_path() -> str:
    return _self_path() + ".bak"


# --- Update signing (Ed25519, pure stdlib verify) ----------------------------
# Set → every self-update must carry a valid Ed25519 signature over the code, so a
# compromised dashboard cannot push forged code (the private key is offline, never
# on the dashboard). Sign each release with scripts/sign_agent.py (just sign-agent),
# which writes orbit_agent.py.sig; the dashboard relays it. Empty disables enforcement.
# IMPORTANT: never release a build with this set but no matching .sig served — the
# agent would reject every subsequent update.
_UPDATE_PUBKEY = "082a588e9b9e4aec7eb3799f18ff545878be235b3158a07562db335a006cdedd"

_ED_P = 2**255 - 19
_ED_D = (-121665 * pow(121666, _ED_P - 2, _ED_P)) % _ED_P
_ED_I = pow(2, (_ED_P - 1) // 4, _ED_P)


def _ed_recover_x(y: int) -> int:
    xx = (y * y - 1) * pow(_ED_D * y * y + 1, _ED_P - 2, _ED_P)
    x = pow(xx, (_ED_P + 3) // 8, _ED_P)
    if (x * x - xx) % _ED_P != 0:
        x = (x * _ED_I) % _ED_P
    if x % 2 != 0:
        x = _ED_P - x
    return x


_ED_BY = (4 * pow(5, _ED_P - 2, _ED_P)) % _ED_P
_ED_B = (_ed_recover_x(_ED_BY) % _ED_P, _ED_BY % _ED_P)


def _ed_add(pt1: tuple[int, int], pt2: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = pt1
    x2, y2 = pt2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _ED_D * x1 * x2 * y1 * y2, _ED_P - 2, _ED_P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _ED_D * x1 * x2 * y1 * y2, _ED_P - 2, _ED_P)
    return (x3 % _ED_P, y3 % _ED_P)


def _ed_mul(pt: tuple[int, int], e: int) -> tuple[int, int]:
    if e == 0:
        return (0, 1)
    q = _ed_mul(pt, e // 2)
    q = _ed_add(q, q)
    if e & 1:
        q = _ed_add(q, pt)
    return q


def _ed_bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _ed_decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2**i * _ed_bit(s, i) for i in range(255))
    x = _ed_recover_x(y)
    if x & 1 != _ed_bit(s, 255):
        x = _ED_P - x
    if (-x * x + y * y - 1 - _ED_D * x * x * y * y) % _ED_P != 0:
        raise ValueError("point not on curve")
    return (x, y)


def _ed25519_verify(signature: bytes, message: bytes, public_key: bytes) -> bool:
    """RFC 8032 Ed25519 verify — pure Python (slow ref; run once per update)."""
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        r = _ed_decodepoint(signature[:32])
        a = _ed_decodepoint(public_key)
    except (ValueError, IndexError):
        return False
    s = sum(2**i * _ed_bit(signature[32:], i) for i in range(256))
    h = hashlib.sha512(signature[:32] + public_key + message).digest()
    hh = sum(2**i * _ed_bit(h, i) for i in range(512))
    return _ed_mul(_ED_B, s) == _ed_add(r, _ed_mul(a, hh))


def _signature_ok(code: bytes, signature_b64: str) -> bool:
    """True if signing is disabled, or the Ed25519 signature over ``code`` is valid."""
    if not _UPDATE_PUBKEY:
        return True  # signing not enforced (dev / no baked key)
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        pub = bytes.fromhex(_UPDATE_PUBKEY)
    except (ValueError, TypeError):
        return False
    return _ed25519_verify(sig, code, pub)


def _skip_sig_check() -> bool:
    """DEV ONLY: True if signature enforcement is explicitly disabled.

    Honors the AGENT_INSECURE_SKIP_SIG=1 env var (locally-run agent) and the
    ``insecure_skip_sig`` config flag (installed agent). Logs loudly so an accidental
    prod use is obvious. Never returns True on its own — both channels are opt-in.
    """
    env_on = os.environ.get("AGENT_INSECURE_SKIP_SIG") == "1"
    # Read the active config (_STATE.config). The old globals().get("cfg") always
    # returned None (no module-level `cfg`), so the config flag was dead.
    cfg_on = bool(getattr(_STATE.config, "insecure_skip_sig", False))
    if env_on or cfg_on:
        log.warning(
            "INSECURE: self-update signature verification DISABLED "
            "(%s) — dev only, never use in production",
            "env AGENT_INSECURE_SKIP_SIG" if env_on else "config insecure_skip_sig",
        )
        return True
    return False


def _verify_update_code(code: bytes, expected_sha256: str) -> bool:
    """Integrity (sha256) + syntax (compile) check before any swap.

    Note: compile() only catches syntax errors, not runtime failures — the real
    health gate is the probation reconnect below.
    """
    if hashlib.sha256(code).hexdigest() != (expected_sha256 or "").lower():
        return False
    try:
        compile(code, "<agent-update>", "exec")
    except (SyntaxError, ValueError):
        return False
    return True


_CODE_VERSION_RE = re.compile(rb"""__version__\s*=\s*["']([0-9][0-9.]*)["']""")


def _version_tuple(version: str) -> tuple[int, ...]:
    """Numeric SemVer-ish tuple; leading digits of each dotted part (rest ignored)."""
    out: list[int] = []
    for part in version.split("."):
        m = re.match(r"\d+", part)
        out.append(int(m.group()) if m else 0)
    return tuple(out)


def _code_version(code: bytes) -> str | None:
    """The ``__version__`` embedded in pushed agent source — the version that will
    actually run after the swap. The signature covers ``code``, so reading the
    version from it binds the anti-rollback check to authenticated content; the
    unsigned ``version`` push param could otherwise be forged over old signed code."""
    m = _CODE_VERSION_RE.search(code)
    return m.group(1).decode() if m else None


def _is_forward_update(code: bytes) -> bool:
    """True only if the pushed code's embedded version is strictly newer than ours.

    Anti-rollback: every prior release is validly signed, so signature checks alone
    don't stop a compromised dashboard from replaying an old (vulnerable) build as an
    "update". Refuse anything not strictly forward, and refuse code with no version."""
    pushed = _code_version(code)
    if pushed is None:
        return False
    return _version_tuple(pushed) > _version_tuple(__version__)


def _apply_update(code: bytes, version: str) -> None:
    """Back up the running agent, atomically swap in new code, set the marker.

    The temp file is written in the target directory so os.replace stays atomic
    (same filesystem). Errors propagate so a half-write never goes live.
    """
    target = _self_path()
    tmp = target + ".new"
    with open(tmp, "wb") as f:
        f.write(code)
        f.flush()
        os.fsync(f.fileno())
    with contextlib.suppress(OSError):
        os.replace(target, _backup_path())
    os.replace(tmp, target)
    Path(_marker_path()).write_text(version)


def _rollback() -> bool:
    """Restore the backup over the agent file and clear the marker."""
    bak = _backup_path()
    if not os.path.exists(bak):
        return False
    try:
        os.replace(bak, _self_path())
    except OSError:
        return False
    with contextlib.suppress(OSError):
        os.remove(_marker_path())
    return True


def _clear_probation() -> None:
    """Probation passed: drop the marker and the backup."""
    with contextlib.suppress(OSError):
        os.remove(_marker_path())
    with contextlib.suppress(OSError):
        os.remove(_backup_path())


async def _handle_self_update(ws: WebSocket, request_id: str, params: dict) -> None:
    """Verify + stage a pushed update, ack, then exit for the supervisor to respawn.

    The unsigned ``version`` param is intentionally ignored — anti-rollback gates on
    the version embedded in the signature-covered code (see ``_is_forward_update``).
    """
    try:
        code = base64.b64decode(params.get("code", ""), validate=True)
    except (ValueError, TypeError):
        await _send_update_result(ws, request_id, False, "invalid base64 code")
        return
    if not _verify_update_code(code, params.get("sha256", "")):
        await _send_update_result(ws, request_id, False, "verification failed (sha256/syntax)")
        return
    if not _skip_sig_check() and not _signature_ok(code, params.get("signature", "")):
        await _send_update_result(ws, request_id, False, "signature verification failed")
        return
    # Anti-rollback: gate on the version embedded in the (signature-covered) code,
    # not the unsigned `version` param — refuse a replay of an older signed build.
    if not _is_forward_update(code):
        pushed = _code_version(code) or "unknown"
        await _send_update_result(
            ws,
            request_id,
            False,
            f"downgrade refused: pushed {pushed} not newer than {__version__}",
        )
        return
    staged = _code_version(code)  # validated forward above
    try:
        await asyncio.get_event_loop().run_in_executor(None, _apply_update, code, staged)
    except OSError as exc:
        await _send_update_result(ws, request_id, False, f"apply failed: {exc}")
        return
    await _send_update_result(ws, request_id, True, f"update staged to {staged}, restarting")
    log.info("self-update: staged %s, exiting for supervisor respawn", staged)
    await ws.close()
    os._exit(_UPDATE_RESTART_CODE)


async def _send_update_result(ws: WebSocket, request_id: str, success: bool, output: str) -> None:
    await ws.send(json.dumps({
        "type": "command_result",
        "request_id": request_id,
        "action": "agent.update",
        "result": {"success": success, "output": output},
    }))
