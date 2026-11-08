# Orbit

The STYLiTE Orbit dashboard — Phoenix + LiveView, server-rendered. Everything runs
in containers; see the repo README for the dev loop (`just dev-up`) and the
`just orbit-*` recipes.

## Reading the docstrings

Many modules describe themselves as a *port* or *mirror* of a path under
`backend/src/app/…`. That tree was the FastAPI implementation this app replaced;
it was deleted in the cutover commit and is **not** on disk any more. The
references are provenance, not live pointers — to read the original, check the
file out from a commit before the cutover:

```bash
git log --diff-filter=D --oneline -- backend/src/app/auth/scope.py   # find the deleting commit
git show <commit>^:backend/src/app/auth/scope.py
```

`Orbit.Auth.Scope` is marked **CHANGE-FROZEN**, and the modules that build on it
(`Orbit.ApiKeys`, `Orbit.Accounts.ApiKey`, `Orbit.Accounts.Admin`) carry the same
warning: the group-scoping semantics are pinned by tests and must not be
"simplified". Read the repo `CLAUDE.md` before touching them.

## State machines

Each state below has one pure, table-tested owner. Read state through it;
never re-derive it in a LiveView or a pro module.

| State | Owner | Notes |
|---|---|---|
| Check state 0=OK 1=WARN 2=CRIT 3=UNKNOWN | `Orbit.Checks.ServiceCheck` | `severity/1` = rank CRIT > WARN > UNKNOWN > OK (never compare raw ints); `label/1` + `badge_class/1` for display — anything outside 0..3 reads UNKNOWN, like the Checkmk export |
| Alert lifecycle (insert / touch / resolve, ack, snooze) | `Orbit.Alerts.Lifecycle` | `plan/3` is the reconciler; a severity *rank* increase breaks a live snooze; `bucket/2` → `:active \| :acked \| :snoozed` for the Alerts page. Design: `docs/alert-lifecycle.md` |
| Instance availability | `Orbit.Availability.classify/3` | `:online \| :degraded \| :offline`; push boxes by live WS connection, polled boxes by the 5-minute success/error window. `Orbit.Instances.status_bucket/3` is its string form. `online?/2` is the separate last-outcome edge detector for offline/recovered alerts; `Orbit.Checks.Staleness` is the separate data-freshness verdict |

## Phoenix upstream docs

* Official website: https://www.phoenixframework.org/
* Guides: https://phoenix.hexdocs.pm/overview.html
* Docs: https://phoenix.hexdocs.pm
* Forum: https://elixirforum.com/c/phoenix-forum
* Source: https://github.com/phoenixframework/phoenix
