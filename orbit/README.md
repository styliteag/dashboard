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

## Phoenix upstream docs

* Official website: https://www.phoenixframework.org/
* Guides: https://phoenix.hexdocs.pm/overview.html
* Docs: https://phoenix.hexdocs.pm
* Forum: https://elixirforum.com/c/phoenix-forum
* Source: https://github.com/phoenixframework/phoenix
