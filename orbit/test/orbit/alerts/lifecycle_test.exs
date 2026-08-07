defmodule Orbit.Alerts.LifecycleTest do
  @moduledoc """
  The pure reconciler state machine (docs/alert-lifecycle.md DR-LC2/4) —
  DB-free over plan/3, house style.
  """
  use ExUnit.Case, async: true

  alias Orbit.Alerts.Lifecycle
  alias Orbit.Alerts.State

  @now ~U[2026-08-07 12:00:00Z]

  defp state(attrs) do
    struct!(
      %State{id: 1, instance_id: 1, check_key: "cpu", severity: 1},
      attrs
    )
  end

  test "an unseen computed alert becomes an insert with identity key" do
    plan = Lifecycle.plan(%{{1, "cpu"} => 2}, [], @now)

    assert plan.insert == [{{1, "cpu"}, 2}]
    assert plan.touch == []
    assert plan.resolve == []
  end

  test "a still-present alert is touched, not re-inserted" do
    s = state(%{})
    plan = Lifecycle.plan(%{{1, "cpu"} => 1}, [s], @now)

    assert plan.insert == []
    assert [{^s, 1, false}] = plan.touch
  end

  test "a severity increase breaks a LIVE snooze, an expired one is moot" do
    live = state(%{snoozed_until: DateTime.add(@now, 3600)})
    expired = state(%{id: 2, check_key: "mem", snoozed_until: DateTime.add(@now, -60)})

    plan =
      Lifecycle.plan(
        %{{1, "cpu"} => 2, {1, "mem"} => 2},
        [live, expired],
        @now
      )

    touches = Map.new(plan.touch, fn {s, sev, unsnooze?} -> {s.check_key, {sev, unsnooze?}} end)
    assert touches["cpu"] == {2, true}
    assert touches["mem"] == {2, false}
  end

  test "same or lower severity never touches a snooze" do
    live = state(%{severity: 2, snoozed_until: DateTime.add(@now, 3600)})
    plan = Lifecycle.plan(%{{1, "cpu"} => 1}, [live], @now)
    assert [{_, 1, false}] = plan.touch
  end

  test "a vanished alert resolves — and a reappearing one would insert fresh" do
    s = state(%{acked_by: "admin", acked_at: @now})
    plan = Lifecycle.plan(%{}, [s], @now)
    assert plan.resolve == [s]

    # after the resolve the next computation inserts a NEW un-acked row
    plan2 = Lifecycle.plan(%{{1, "cpu"} => 2}, [], @now)
    assert [{{1, "cpu"}, 2}] = plan2.insert
  end
end
