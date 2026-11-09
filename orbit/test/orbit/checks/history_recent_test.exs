defmodule Orbit.Checks.HistoryRecentTest do
  @moduledoc """
  `History.recent/2`: the last transitions of an instance across all its
  checks (Checks tab, refreshed every 5 s while the page is open).

  It used to be `ORDER BY id DESC` on the detail page, which the
  `(instance_id, ts)` index cannot serve: MariaDB sorted every event of the
  box on each refresh. Ordering by `ts, id` reads the index backwards and
  stops after the limit.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Checks.History

  @inst 4101
  @other 4102

  setup do
    Orbit.Repo.query!("INSERT IGNORE INTO `groups` (id, name) VALUES (911, ?)", ["recent-a"])

    for id <- [@inst, @other] do
      Orbit.Repo.query!("DELETE FROM check_events WHERE instance_id = ?", [id])
      Orbit.Repo.query!("DELETE FROM instances WHERE id = ?", [id])

      Orbit.Repo.query!(
        "INSERT INTO instances (id, name, base_url, api_key_enc, api_secret_enc, slug, " <>
          "group_id, transport, device_type, created_at, updated_at) " <>
          "VALUES (?, ?, ?, '', '', ?, 911, 'direct', 'securepoint', NOW(), NOW())",
        [id, "recent-#{id}", "https://recent-#{id}.invalid/", "recent-#{id}"]
      )
    end

    on_exit(fn ->
      for id <- [@inst, @other] do
        Orbit.Repo.query!("DELETE FROM check_events WHERE instance_id = ?", [id])
        Orbit.Repo.query!("DELETE FROM instances WHERE id = ?", [id])
      end
    end)

    :ok
  end

  defp event(instance_id, ts, key, old, new) do
    Orbit.Repo.query!(
      "INSERT INTO check_events (instance_id, ts, check_key, old_state, new_state, summary) " <>
        "VALUES (?, ?, ?, ?, ?, ?)",
      [instance_id, ts, key, old, new, "#{key} #{old}->#{new}"]
    )
  end

  test "newest by time first, across checks, only this instance, capped" do
    # inserted out of time order: a late-written event must not jump ahead
    event(@inst, ~N[2026-11-09 10:00:00], "cpu", 0, 1)
    event(@inst, ~N[2026-11-09 12:00:00], "memory", 0, 2)
    event(@inst, ~N[2026-11-09 11:00:00], "disk", 0, 1)
    event(@other, ~N[2026-11-09 13:00:00], "cpu", 0, 2)

    assert [
             [~N[2026-11-09 12:00:00], "memory", 0, 2, "memory 0->2"],
             [~N[2026-11-09 11:00:00], "disk", 0, 1, "disk 0->1"]
           ] = History.recent(@inst, 2)

    assert length(History.recent(@inst)) == 3
  end

  test "equal timestamps keep the later insert first" do
    event(@inst, ~N[2026-11-09 10:00:00], "first", 0, 1)
    event(@inst, ~N[2026-11-09 10:00:00], "second", 1, 0)

    assert [[_, "second" | _], [_, "first" | _]] = History.recent(@inst)
  end

  test "the read walks ix_check_event_lookup, no filesort" do
    for i <- 1..50,
        do: event(@inst, NaiveDateTime.add(~N[2026-11-09 00:00:00], i * 60), "k", 0, 1)

    %{rows: rows, columns: cols} =
      Orbit.Repo.query!("EXPLAIN " <> History.recent_sql(20), [@inst])

    plan = Enum.map(rows, &Map.new(Enum.zip(cols, &1)))
    assert [%{"key" => "ix_check_event_lookup", "Extra" => extra}] = plan
    refute (extra || "") =~ "filesort"
  end

  test "an unknown instance has no history" do
    assert History.recent(-1) == []
  end
end
