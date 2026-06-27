"""Root-executed helper scripts must be written to private, unpredictable paths.

A fixed /tmp name (no fs.protected_symlinks on FreeBSD) let a local unprivileged
user pre-plant a symlink and redirect the root write/exec. _write_root_script uses
mkstemp (O_CREAT|O_EXCL, random name, mode 0600).
"""

from __future__ import annotations

import os
import stat

import orbit_agent as agent


def test_write_root_script_is_private_random_and_exact() -> None:
    p = agent._write_root_script("echo hello\n", ".sh")
    try:
        assert p.startswith("/tmp/orbit-")  # unpredictable, not a fixed name
        assert p.endswith(".sh")
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600  # private from creation
        with open(p) as f:
            assert f.read() == "echo hello\n"
    finally:
        os.unlink(p)


def test_write_root_script_paths_are_unique() -> None:
    a = agent._write_root_script("a\n", ".php")
    b = agent._write_root_script("b\n", ".php")
    try:
        assert a != b  # random names → no predictable target to pre-plant
    finally:
        os.unlink(a)
        os.unlink(b)
