# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
def _derive_enroll_url(dashboard_url: str) -> str:
    """Turn the WS dashboard_url into the HTTP(S) enroll endpoint, or '' if unknown."""
    parts = urlsplit(dashboard_url)
    if not parts.netloc:
        return ""
    scheme = {"wss": "https", "ws": "http"}.get(parts.scheme, parts.scheme or "https")
    path = parts.path
    if path.endswith("/ws/agent"):
        path = path[: -len("/ws/agent")] + "/agent/enroll"
    else:
        path = "/api/agent/enroll"
    return f"{scheme}://{parts.netloc}{path}"


def _persist_token(cfg: Config, token: str) -> None:
    """Write the obtained token into the config file and drop the spent code.

    Critical: the enrollment code is single-use, so the token MUST survive a
    restart — otherwise the next boot re-enrolls with a consumed code and the
    agent can never reconnect.
    """
    try:
        p = Path(cfg.path)
        data = json.loads(p.read_text()) if p.exists() else {}
        data["agent_token"] = token
        data.pop("enroll_code", None)
        # Config holds agent_token + local_api_secret — write 0600 (no world-readable
        # window). write_text would create with root's umask (0644).
        _write_private(p, json.dumps(data, indent=4))
    except (OSError, ValueError) as exc:
        log.warning("enroll: could not persist token to %s: %s", cfg.path, exc)


def _enroll(cfg: Config) -> bool:
    """Exchange enroll_code for an agent_token before connecting, then persist it.

    Skips when an agent_token already exists (prefer it — a stored token must never
    be replaced by a re-enroll) or no code is configured. Returns True on success.
    """
    if cfg.agent_token or not cfg.enroll_code:
        return False
    url = cfg.enroll_url or _derive_enroll_url(cfg.dashboard_url)
    if not url:
        log.error("enroll: cannot derive enroll URL from dashboard_url")
        return False
    body = json.dumps({"code": cfg.enroll_code}).encode()
    try:
        # Remote dashboard: MUST verify TLS — this exchanges the one-time enroll
        # code (bootstrap secret) for the long-lived agent token.
        status, _, data = _http_request(
            url, "POST", {"Content-Type": "application/json"}, body, timeout=15, verify=True
        )
    except (OSError, http.client.HTTPException) as exc:
        log.error("enroll: request to %s failed: %s", url, exc)
        return False
    if status != 200:
        log.error("enroll: server rejected code (HTTP %s)", status)
        return False
    try:
        token = json.loads(data).get("agent_token", "")
    except ValueError:
        token = ""
    if not token:
        log.error("enroll: no token in response")
        return False
    cfg.agent_token = token
    _persist_token(cfg, token)
    log.info("enroll: obtained and persisted agent token")
    return True
