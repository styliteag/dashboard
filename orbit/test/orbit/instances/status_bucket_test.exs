defmodule Orbit.Instances.StatusBucketTest do
  @moduledoc """
  statusBucket parity (InstancesPage.tsx): the KPI tiles and the row badges
  read the same function, and its semantics must match the react original —
  agent-mode boxes bucket by the live WS connection, polled boxes by the
  5-minute success/error window.
  """
  use ExUnit.Case, async: true

  alias Orbit.Instances
  alias Orbit.Instances.Instance

  @now ~U[2026-07-18 12:00:00Z]

  defp polled(attrs) do
    struct!(
      %Instance{transport: "direct", agent_token: nil, last_success_at: nil, last_error_at: nil},
      attrs
    )
  end

  defp ago(seconds), do: DateTime.add(@now, -seconds)

  test "agent-mode boxes bucket by the live connection, timestamps ignored" do
    inst = %Instance{transport: "push", agent_token: "t", last_success_at: nil}
    assert Instances.status_bucket(inst, true, @now) == "online"
    assert Instances.status_bucket(inst, false, @now) == "offline"
  end

  test "polled: fresh success and no (or older) error is online" do
    assert Instances.status_bucket(polled(last_success_at: ago(60)), false, @now) == "online"

    assert Instances.status_bucket(
             polled(last_success_at: ago(60), last_error_at: ago(120)),
             false,
             @now
           ) == "online"
  end

  test "polled: fresh success AND fresh error at-or-after it is degraded" do
    assert Instances.status_bucket(
             polled(last_success_at: ago(120), last_error_at: ago(60)),
             false,
             @now
           ) == "degraded"
  end

  test "polled: stale success or no success at all is offline" do
    assert Instances.status_bucket(polled(last_success_at: ago(600)), false, @now) == "offline"
    assert Instances.status_bucket(polled([]), false, @now) == "offline"
  end
end
