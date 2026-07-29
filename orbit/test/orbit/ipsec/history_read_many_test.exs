defmodule Orbit.Ipsec.HistoryReadManyTest do
  @moduledoc """
  The fleet reader must carry pre-window state (regression: fleet lanes
  opened grey).

  `read/4` has always fetched the newest events BEFORE the window
  (`preceding/3`) so `lanes/4` knows what a tunnel was doing when the window
  opened. `read_many/3` was window-only: a tunnel up for a month with one
  flap inside the 7d window drew grey "no data" from the left edge to the
  flap on the fleet graph, while the single-tunnel dialog drew the same
  window correctly.
  """
  use Orbit.DataCase, async: false

  alias Orbit.Ipsec.History

  @iid 4101

  setup do
    Orbit.Repo.query!("INSERT IGNORE INTO `groups` (id, name) VALUES (911, ?)", ["fleet-hist"])
    Orbit.Repo.query!("DELETE FROM instances WHERE id = ?", [@iid])

    Orbit.Repo.query!(
      "INSERT INTO instances (id, name, base_url, api_key_enc, api_secret_enc, slug, " <>
        "group_id, transport, device_type, created_at, updated_at) " <>
        "VALUES (?, ?, ?, '', '', ?, 911, 'direct', 'opnsense', NOW(), NOW())",
      [@iid, "fleet-hist", "https://fleet-hist.invalid/", "fleet-hist"]
    )

    :ok
  end

  defp event(tunnel_id, event_type, old_value, new_value) do
    %{
      tunnel_id: tunnel_id,
      child_name: "",
      event_type: event_type,
      old_value: old_value,
      new_value: new_value
    }
  end

  test "read_many carries the newest pre-window events, so fleet lanes open in colour" do
    now = DateTime.utc_now()

    # Came up 10 days ago (before the 7d window), dropped 1 day ago (inside).
    History.record(@iid, DateTime.add(now, -10 * 86_400), [
      event("con1", "phase1_up", "down", "established")
    ])

    History.record(@iid, DateTime.add(now, -1 * 86_400), [
      event("con1", "phase1_down", "established", "down")
    ])

    since = DateTime.add(now, -7 * 86_400)
    events = History.read_many([@iid], since)[{@iid, "con1"}]

    assert Enum.any?(events, &(&1.event_type == "phase1_up")),
           "pre-window event missing — lanes/4 has no carried state"

    %{phase1: lane} =
      History.lanes(events, %{up: false, phase2_up: 0, phase2_total: 1}, now, since)

    # Window opens :up (carried in), not grey :unknown.
    assert %{state: :up} = Enum.min_by(lane, & &1.left)
  end

  test "read_many without a window still returns everything, ungrouped by time" do
    now = DateTime.utc_now()

    History.record(@iid, DateTime.add(now, -10 * 86_400), [
      event("con2", "phase1_up", "down", "established")
    ])

    events = History.read_many([@iid], nil)[{@iid, "con2"}]
    assert Enum.any?(events, &(&1.event_type == "phase1_up"))
  end
end
