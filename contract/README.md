# API contract suite (strangler migration M1)

Black-box HTTP tests that pin the API contract of the dashboard backend —
the regression net for the Elixir migration (docs/elixir-migration-plan.md).
Unlike `backend/tests` (DB-free unit tests), this suite deliberately talks to
a **running** backend and asserts observable behavior only: status codes,
response shapes, error semantics.

## Run

```sh
just dev-up          # suite needs the live dev stack
just contract-test   # against the Python backend (:8000)

CONTRACT_BASE_URL=http://localhost:4000 just contract-test   # against server_ex
```

Config (env):

| Var | Default | Meaning |
|---|---|---|
| `CONTRACT_BASE_URL` | `http://localhost:8000` | backend under test |
| `CONTRACT_ADMIN_USER` | `admin` | bootstrap admin (password-only login) |
| `CONTRACT_ADMIN_PASSWORD` | `admin` | its password |

## Rules

- A route migrated to `server_ex` must pass the SAME tests against both
  base URLs before its nginx/Vite routing flips (plan §7).
- Tests assert the contract, not implementation: exact JSON keys where the
  frontend mirrors types, status codes, 404-not-403 scoping semantics,
  lowercase human error details.
- Never mutate state the dev stack can't shrug off; use throwaway objects
  and clean up in the test when a mutation is unavoidable.
- `docs/api-contract/openapi.json` is the frozen route inventory; the drift
  test fails when routes appear/disappear without the snapshot being
  regenerated deliberately (see test_openapi_drift.py for the refresh command).
