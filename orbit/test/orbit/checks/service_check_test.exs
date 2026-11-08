defmodule Orbit.Checks.ServiceCheckTest do
  @moduledoc """
  The one place a Checkmk state becomes a label, a badge colour or a sort
  rank. Anything outside 0..3 (nil, garbage) renders as UNKNOWN — the same
  coercion the checkmk plugin applies (agent_styliteorbit.py `_local_line`).
  """
  use ExUnit.Case, async: true

  alias Orbit.Checks.ServiceCheck

  @unknown_class "bg-base-300 text-base-content/70"

  for {state, label, class} <- [
        {0, "OK", "bg-primary/20 text-primary"},
        {1, "WARN", "bg-warning/20 text-warning"},
        {2, "CRIT", "bg-error/20 text-error"},
        {3, "UNKNOWN", @unknown_class},
        {nil, "UNKNOWN", @unknown_class},
        {4, "UNKNOWN", @unknown_class},
        {-1, "UNKNOWN", @unknown_class},
        {"2", "UNKNOWN", @unknown_class}
      ] do
    test "state #{inspect(state)} → #{label}" do
      assert ServiceCheck.label(unquote(state)) == unquote(label)
      assert ServiceCheck.badge_class(unquote(state)) == unquote(class)
    end
  end

  test "severity/1 ranks CRIT > WARN > UNKNOWN > OK" do
    ranked = Enum.sort_by([0, 1, 2, 3], &ServiceCheck.severity/1, :desc)
    assert ranked == [2, 1, 3, 0]
  end
end
