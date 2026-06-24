# TODO

Active backlog lives in `docs/agent-architecture.md` (§11 Offene Punkte, §14 Bekannte Lücken).

## Done

- ~~Agent should auto-discover the local API port (4444 is admin-configurable, not fixed).~~
  Done — `_discover_local_api_url()` reads `<system><webgui>` from `config.xml`; pin with
  `local_api_url` in the agent config to override.
