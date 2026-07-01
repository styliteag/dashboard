# TODO

- Runtime of agent (maybe its sections) as metric visibe (WARN if logner than 10s)
- checkmk: "3 revoked keys hidden." -> delete them
- 2FA passkey do not work
- AI could include:
    grep -A20 "connections {" /usr/local/etc/swanctl/swanctl.conf or the whole conf file?
- Active backlog lives in `docs/agent-architecture.md` (§11 Offene Punkte, §14 Bekannte Lücken).


## Done

- ~~Agent should auto-discover the local API port (4444 is admin-configurable, not fixed).~~
  Done — `_discover_local_api_url()` reads `<system><webgui>` from `config.xml`; pin with
  `local_api_url` in the agent config to override.
