# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
def _run(cmd: list[str], timeout: int = 5) -> str:
    """Run a shell command and return stdout."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


# Values that end up in the argv of a root-run tool (ping, tcpdump) come from
# the dashboard. A leading "-" turns such a value into an OPTION (security
# hotfix, test_option_injection.py: `-f` flood ping, tcpdump `-w … -z cmd`).
# Only IP literals and plain names pass; callers also end options with "--".
_PLAIN_ARG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_IFACE_ARG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$")


def _safe_host_arg(value) -> str:
    """``value`` if it is an IP literal or a plain host name, else ""."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        pass
    return text if _PLAIN_ARG_RE.match(text) else ""


def _safe_iface_arg(value) -> str:
    """``value`` if it is a plain interface name (no leading "-"), else ""."""
    text = str(value or "").strip()
    return text if _IFACE_ARG_RE.match(text) else ""


def _tcpdump_filter_args(filt: str) -> list:
    """The BPF expression as ONE argument after "--" — never split into argv
    tokens, where its words would be parsed as tcpdump options."""
    return ["--", filt] if filt else []
