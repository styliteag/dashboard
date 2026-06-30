"""Fixed user-role taxonomy.

Three roles, no per-resource scoping:

- ``admin``     — everything, incl. config (settings, API keys, LLM, log config,
  notification selection rules) and user management.
- ``user``      — every operational write (firewall instance CRUD, firmware apply,
  bulk push, connectivity, agent ops, system, ipsec, check-ack) but no config.
- ``view_only`` — reads everything, mutates nothing.
"""

from __future__ import annotations

from typing import Final, Literal

Role = Literal["admin", "user", "view_only"]

ROLE_ADMIN: Final = "admin"
ROLE_USER: Final = "user"
ROLE_VIEW_ONLY: Final = "view_only"

# Roles permitted to perform mutations (everything except ``view_only``).
WRITE_ROLES: Final[frozenset[str]] = frozenset({ROLE_ADMIN, ROLE_USER})

# All valid role tokens — used to validate role input on the user-management API.
ALL_ROLES: Final[frozenset[str]] = frozenset({ROLE_ADMIN, ROLE_USER, ROLE_VIEW_ONLY})
