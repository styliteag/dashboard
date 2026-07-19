defmodule Orbit.Repo.BaselineSchemaTest do
  @moduledoc """
  The baseline schema must stay a no-op on an existing database.

  Regression: baseline_schema.sql shipped with 27 `DROP TABLE IF EXISTS`
  statements (mariadb-dump emits them by default; the dump recipe's comment
  filter did not strip them). On the first orbit boot against the populated dev
  database the migration tried to drop every table — it only failed harmlessly
  because `SET FOREIGN_KEY_CHECKS = 0` does not survive between statements, so
  the first DROP hit an FK constraint (errno 1451) and aborted the migration,
  leaving orbit in a crash loop instead of an empty database.

  This test reads the SQL that actually ships and fails on the pre-fix file.
  """
  use ExUnit.Case, async: true

  @destructive ~r/^\s*(DROP|TRUNCATE|DELETE|RENAME)\b/i

  defp baseline_sql do
    Path.join([__DIR__, "..", "..", "..", "priv", "repo", "baseline_schema.sql"])
    |> Path.expand()
    |> File.read!()
  end

  defp statements(sql) do
    sql
    |> String.split("\n")
    |> Enum.reject(&(String.starts_with?(String.trim(&1), "--") or String.trim(&1) == ""))
    |> Enum.join("\n")
    |> String.split(";")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  test "carries no destructive statement" do
    offenders =
      baseline_sql()
      |> statements()
      |> Enum.filter(&Regex.match?(@destructive, &1))
      |> Enum.map(&String.slice(&1, 0, 60))

    assert offenders == [],
           "baseline_schema.sql must be a no-op on an existing DB, but contains: " <>
             Enum.join(offenders, ", ")
  end

  test "creates tables only via IF NOT EXISTS" do
    creates =
      baseline_sql()
      |> statements()
      |> Enum.filter(&String.starts_with?(String.upcase(&1), "CREATE TABLE"))

    refute creates == [], "expected the baseline to create tables"

    for stmt <- creates do
      assert String.starts_with?(String.upcase(stmt), "CREATE TABLE IF NOT EXISTS"),
             "unguarded CREATE TABLE: #{String.slice(stmt, 0, 60)}"
    end
  end
end
