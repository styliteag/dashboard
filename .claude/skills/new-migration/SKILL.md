---
name: new-migration
description: Scaffold the next Alembic migration in backend/alembic/versions/ following the project numbering convention (NNN_<slug>.py with revision="NNN", down_revision=previous). Pass a short message as $ARGUMENTS.
disable-model-invocation: true
---

# /new-migration <message>

Create the next Alembic migration with the project's conventions. **Do not** run `alembic revision --autogenerate` blindly — this repo numbers revisions sequentially as plain strings ("001", "002", …) and uses `NNN_<slug>.py` filenames.

## Steps

1. Find the current max revision:

   ```bash
   ls backend/alembic/versions | sort | tail -1
   ```

   Parse the leading number (e.g., `006_partial_unique_name.py` → `006`). The new revision is `next = format(int(prev) + 1, "03d")`.

2. Build the slug from `$ARGUMENTS`:
   - lowercase
   - replace whitespace with `_`
   - strip non-`[a-z0-9_]`
   - cap at ~40 chars

   Filename: `backend/alembic/versions/<next>_<slug>.py`.

3. Write the file using this template (do NOT include autogenerate output — write the upgrade/downgrade body yourself based on the actual model change):

   ```python
   """<the message from $ARGUMENTS>

   Revision ID: <next>
   Revises: <prev>
   Create Date: <YYYY-MM-DD today>
   """
   from __future__ import annotations

   from collections.abc import Sequence

   import sqlalchemy as sa
   from alembic import op

   revision: str = "<next>"
   down_revision: str | None = "<prev>"
   branch_labels: str | Sequence[str] | None = None
   depends_on: str | Sequence[str] | None = None


   def upgrade() -> None:
       # TODO: write the schema change here
       ...


   def downgrade() -> None:
       # TODO: reverse the upgrade
       ...
   ```

4. Tell the user the file path, the revision number, and that they need to fill in the `upgrade` / `downgrade` bodies (or ask Claude to do it based on the model diff). Remind them migrations apply automatically on `just up` via the entrypoint — no manual `alembic upgrade head`.

## Don'ts

- Don't use `alembic revision --autogenerate` — it produces UUID-style revision IDs that don't match this repo's numbering.
- Don't number the revision string with anything other than the zero-padded integer (e.g., `"007"`, not `"7"` or `"v007"`).
- Don't skip the `down_revision` — it must point to the previous max.
