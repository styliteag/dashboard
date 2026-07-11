---
name: ship-agent-change
description: Full done-pipeline for any change to agent/orbit_agent.py or agent/* — version-bump check, Python-3.8 runtime scan, stdlib/FreeBSD scan, agent tests, Ed25519 re-sign + verify, wiring checklists, commit assembly, and optional canary rollout. Use after ANY edit to agent/ and BEFORE declaring the change done.
---

# /ship-agent-change

The agent runs as **root on customer firewalls** and deploys itself via signed
self-update. A mistake here doesn't fail a test — it silently never deploys, or it
bricks boxes that can only be recovered by manual `scp` per box. Run every gate below
in order; stop at the first failure and fix it. Report a one-line verdict per gate.

## Gate 1 — Version bump (the fix must be able to deploy)

```bash
git diff agent/orbit_agent.py | grep '__version__'
```

Required output: a `-`/`+` pair showing a **strictly newer** version.

- Purely numeric dotted only (`2.9.8`). A suffix like `-rc1` or `2.9.8b` makes the
  agent's anti-rollback parser (`_CODE_VERSION_RE`) return None and **refuse ALL
  updates**, not just this one.
- Strictly newer by numeric tuple compare — the backend no-ops a same-version push
  and the agent refuses non-forward versions with a sticky "update rejected" error.
- Even a rework of an already-shipped change needs a NEW version: boxes that pulled
  the first build of X will never re-pull an amended X.
- Convention: when the next product release number is known, align `__version__` to it
  (see commit 8a8904b: 2.7.19 → 2.9.7); otherwise patch-bump.

No matching diff line = **not done**. If the diff touches only `agent/tests/`,
`install.sh`, `rc.d/`, or `run-agent.sh`, the bump is not required — but see Gate 6.

## Gate 2 — Python 3.8 runtime scan (no local gate catches this)

Old pfSense boxes run Python 3.8. The lab boxes run 3.11, the test suite runs 3.13 —
**tests structurally cannot catch this bug class**. `from __future__ import
annotations` makes annotations (`list[dict]`, `X | None`) safe; only runtime
calls/statements break.

```bash
# Should return ONLY the known NB comment near line 2140:
grep -nE 'removeprefix\(|removesuffix\(|asyncio\.to_thread|functools\.cache|zoneinfo|graphlib|math\.lcm|isqrt\(|bit_count\(' agent/orbit_agent.py

# dict merge operators on dict literals/vars (3.9+) — must be empty:
grep -nE '\} \| \{|\|= *\{' agent/orbit_agent.py

# match/case statements (3.10+) — must be empty:
grep -nE '^\s*match .+:$' agent/orbit_agent.py

# 3.11+ datetime.UTC import (crash-looped 3.8 agents once, commit 93761f4) — must be empty:
grep -nE 'from datetime import.*\bUTC\b|datetime\.UTC' agent/orbit_agent.py

# Syntax-level floor check (catches match/case, walrus misuse, but NOT AttributeErrors):
python3.8 -c "import ast; ast.parse(open('agent/orbit_agent.py').read())" 2>/dev/null \
  || echo "no python3.8 on this machine — grep scan above is the real gate"
```

Also eyeball the **diff** (not just the file) for anything from the list — new code is
where regressions enter. Past incidents: `str.removesuffix()` silenced a pfSense agent
(">120s silent"); `from datetime import UTC` crash-looped 3.8 agents, recovery was
manual scp to every affected box because a crash-looping agent cannot self-update.

## Gate 3 — Stdlib-only + FreeBSD scan

```bash
# New imports in the diff must all be Python stdlib:
git diff agent/orbit_agent.py | grep -E '^\+\s*(import |from \S+ import)'

# Linux-isms — all must be empty:
grep -n '/proc/' agent/orbit_agent.py
grep -nE 'systemctl|systemd' agent/orbit_agent.py
```

For any **new shell command** in the diff:
- FreeBSD flag spellings (`ping -t <deadline> -S <src>`, not GNU `-w`/`-I`); there is
  no `timeout` binary on these boxes — enforce limits in Python.
- pfSense PHP: `function_exists`-guard any 2.7+ accessor (`config_get_path` is 2.7+,
  the fleet has CE 2.6 — use the `_PF_CONFIG_COMPAT` shim) and guard every
  `write_config()` on a populated `$config`.
- Anything registered to run at boot keeps `>/dev/null 2>&1` (removing it hangs
  pfSense boot at rc.bootup — incident b218830).
- Platform-specific tools go behind `detect_platform()` dispatch.
- Verify genuinely new command invocations live on a lab box (see `/lab-verify`).

## Gate 4 — Wiring checklists (only if applicable)

**New collector** (`collect_<name>()`):
- [ ] Registered in `_SNAPSHOT_SECTIONS` as a **name string** pair
      (`("key", "collect_name")`) — never a function reference (globals()-resolved so
      tests can monkeypatch).
- [ ] `agent/tests/test_collect_timing.py`: `_SECTIONS` and `_STUB_FN` extended with
      the same key (a set-equality assert fails otherwise).
- [ ] Interval-throttled? Its gate variable is zeroed in the `refresh.full` branch of
      `_listen_loop_inner`, or the dashboard "Refresh now" button silently serves
      stale data for this section.
- [ ] Multi-item loops catch per item — one bad cert/log must not blank the push.
- [ ] Backend side: `handle_metrics` cache write uses a documented guard (truthy for
      failure-prone lists, presence for empty-is-meaningful) and the section is added
      to `_snapshot_for` + `hydrate_instance` symmetrically.

**New command** (`_cmd_<name>(params) -> dict`):
- [ ] Returns at least `{"success": bool, "output": str}`; registered in `_COMMANDS`
      under a dotted action name.
- [ ] Handler is sync and never touches the WebSocket (it runs in an executor).
      Needs the WS or process lifecycle? → inline branch in `_listen_loop_inner`.
- [ ] Long-running work is bounded with explicit Python-side timeouts; subprocesses
      terminated + force-killed in `finally`.
- [ ] Disk writes with secrets via `_write_private()`; root-run /tmp scripts via
      `_write_root_script()` (fixed /tmp names = symlink attack on FreeBSD).
- [ ] Privileged (credentials/curated params)? Dedicated backend route + action string
      added to `_INTERNAL_AGENT_ACTIONS` in `agent_hub/routes/management.py`.
- [ ] Test in `agent/tests/` driving it via `execute_command("<action>", params)` with
      `agent._run` monkeypatched to return verbatim real-box output.

**Security-gate style checks:** any operator on/off switch must be re-read per use
(function call), never captured at module import (incident 37d74e1).

## Gate 5 — Tests

```bash
just agent-test
```

Never raw pytest — the recipe runs from the backend venv with `-o asyncio_mode=auto`;
without it every bare `async def` test fails. Expect all green in ~2s.

## Gate 6 — Sign and stage

```bash
just sign-agent
just sign-agent --verify   # must print: signature verifies against baked _UPDATE_PUBKEY. OK
git add agent/orbit_agent.py agent/orbit_agent.py.sig
```

- The key auto-loads from the gitignored repo-root `.env` (`DASH_AGENT_SIGNING_KEY`).
  If it's absent, say so — release.sh will re-sign at release, but the committed state
  should still carry a fresh .sig when possible.
- The dev stack (`just dev-up` etc.) auto-re-signs via `_sign-if-key` — a modified
  `.sig` in `git status` is legitimate; commit it with the agent change, never revert it.
- **Never** hand-edit the `.sig`.

**If the change touched `run-agent.sh`, `rc.d/orbit_agent`, or `install.sh`:** these
are OUTSIDE the self-update path — agent.update pushes only `orbit_agent.py` bytes.
State an explicit rollout plan (manual ssh/reinstall per box) in the commit body, or
better: rework the fix to self-heal from inside orbit_agent.py at startup (pattern:
`_ensure_pfsense_boot_persistence`). Preserve the supervisor contract: exit 42 =
update respawn; marker + <60s runtime + `.bak` = rollback; `daemon -f` in rc.d.

## Gate 7 — Changelog + commit

- [ ] User-visible → bullet under `## [Unreleased]` in CHANGELOG.md, staged in the
      same commit.
- [ ] Subject `fix(agent):` / `feat(agent):` with the new agent version named in
      subject or body (`"… (agent 2.9.8)"` or "Bump __version__ 2.9.7 → 2.9.8 and re-sign").
- [ ] Body for fixes: symptom → root cause → fix → proof (lab box + version tested).
- [ ] Stage explicit paths only (shared working tree — never `git add -A`).

## Gate 8 — Canary rollout (when deploying, not just committing)

Never bulk-update first. Sequence (details in `/lab-verify`):

1. Push to ONE box: `POST /api/instances/{id}/agent/update` (or the UI button).
2. Watch for the log line `self-update: probation passed (healthy connect)` and the
   new version in `GET /api/agents/connected`. The agent auto-rolls-back if no healthy
   `welcome` arrives within 60s — a rollback means your change broke startup.
3. For pfSense-path changes, canary on pf1 (10.20.1.200) as well as an OPNsense box.
4. Only then update-all (it re-checks live versions to avoid same-version re-push).

## Output

```
ship-agent-change: version=✓(2.9.8) py38=✓ stdlib/bsd=✓ wiring=✓|n/a tests=✓(281) sign=✓ changelog=✓ canary=✓|pending
```

Any ✗ → not done. Report the failing gate with its exact output.
