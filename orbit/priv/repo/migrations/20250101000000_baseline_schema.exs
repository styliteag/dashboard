defmodule Orbit.Repo.Migrations.BaselineSchema do
  @moduledoc """
  The baseline schema orbit adopts at cutover — the exact CREATE TABLE set the
  Alembic head produced, captured to priv/repo/baseline_schema.sql and made
  idempotent (CREATE TABLE IF NOT EXISTS). Effect per database:

    - already-migrated (cutover): every statement is a no-op, and this version
      is simply recorded in schema_migrations — orbit now owns the schema.
    - empty (greenfield): the whole schema is created here.

  Every schema change AFTER this point is a normal, additive Ecto migration.
  """

  use Ecto.Migration

  # FK-safety comes from the SQL's table ORDER (parents before children), not
  # from the `SET FOREIGN_KEY_CHECKS = 0` line: that session flag does NOT
  # persist across statements here, because each execute/1 runs as its own
  # query and MariaDB auto-commits every DDL, so the connection/session resets
  # between CREATE TABLEs (an alphabetical order failed on apikey_groups →
  # groups, errno 150). Dependency ordering makes creation succeed on any
  # connection model; the FK-check line is just belt-and-suspenders.

  def up do
    "repo/baseline_schema.sql"
    |> baseline_path()
    |> File.read!()
    |> statements()
    |> Enum.map(&refuse_destructive!/1)
    |> Enum.each(&execute/1)
  end

  # The baseline is a no-op on an existing database — that is its whole contract.
  # mariadb-dump emits `DROP TABLE IF EXISTS` per table by DEFAULT, and the dump
  # recipe's comment filter does not strip it; a regenerated baseline carrying
  # DROPs would delete every table on the first boot against a populated DB.
  # That shipped once (the SQL was committed with 27 DROPs) and only failed
  # harmlessly because FOREIGN_KEY_CHECKS = 0 does not survive between
  # statements, so the first DROP hit an FK and aborted the migration.
  # Do not remove: `just orbit-dump-baseline` passing --skip-add-drop-table is
  # the fix, this is the backstop for when someone regenerates it by hand.
  defp refuse_destructive!(sql) do
    if Regex.match?(~r/^\s*(DROP|TRUNCATE|DELETE|RENAME)\b/i, sql) do
      raise Ecto.MigrationError,
        message:
          "baseline_schema.sql contains a destructive statement: #{String.slice(sql, 0, 80)}. " <>
            "The baseline must be pure CREATE TABLE IF NOT EXISTS. " <>
            "Regenerate it with `just orbit-dump-baseline` (--skip-add-drop-table)."
    end

    sql
  end

  # Irreversible: rolling the baseline back would drop every table (all data).
  # A teardown is a DB reset, never a down-migration.
  def down do
    raise Ecto.MigrationError, message: "the baseline schema migration is irreversible"
  end

  defp baseline_path(rel), do: Application.app_dir(:orbit, ["priv", rel])

  # One SQL statement per element: drop comment/blank lines, then split on the
  # statement-terminating ';'. No ';' appears inside the DDL (the single
  # generated column uses case/when/end), so a plain split is safe.
  defp statements(sql) do
    sql
    |> String.split("\n")
    |> Enum.reject(&(String.starts_with?(String.trim(&1), "--") or String.trim(&1) == ""))
    |> Enum.join("\n")
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end
end
