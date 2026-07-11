---
name: verify-backend
description: Run the full backend done-criteria — ruff lint, pytest, and verify a matching Alembic migration exists for any model change. Use after any change in backend/.
---

# /verify-backend

Run these gates in order and stop at the first failure. Report concrete output per step.

## 1. Lint

```bash
just backend-lint
```

If it fails, fix the reported issues (or run `just backend-fmt` for purely formatting fixes), then re-run.

## 2. Tests

```bash
just backend-test
```

If it fails, debug the failure — do not skip or `xfail` tests to make this pass.

## 3. Migration check (only if models changed)

Determine whether any SQLAlchemy model files changed in this session:

```bash
git diff --name-only HEAD -- 'backend/app/**/models.py' 'backend/app/**/db.py' 'backend/app/**/orm*.py'
git diff --cached --name-only -- 'backend/app/**/models.py' 'backend/app/**/db.py' 'backend/app/**/orm*.py'
```

If any output:

1. Confirm a new file exists in `backend/alembic/versions/` numbered higher than the previous max (e.g., if `006_*.py` is the last on `main`, look for `007_*.py`).
2. If missing, tell the user the change needs a migration and suggest running `/new-migration "<message>"`.
3. If present, open it and sanity-check that it actually reflects the model change (added column, new table, etc.) — autogenerate is not always trustworthy.

## Output

Print a one-line summary:

```
verify-backend: lint=✓ tests=✓ migration=✓|n/a|MISSING
```

If anything failed or is missing, stop and ask before proceeding with downstream work.
