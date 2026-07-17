defmodule Orbit.SelectionTest do
  @moduledoc "Pure resolve port of selection/model.py — most-specific-wins ranks."

  use ExUnit.Case, async: true

  alias Orbit.Selection

  # Rules: {consumer, instance_id | nil, selector, mode}
  test "base default is OFF for every consumer" do
    refute Selection.is_on("telegram", "gateway:WAN", 1, [])
  end

  test "global category include turns a family on" do
    rules = [{"telegram", nil, "gateway", "include"}]
    assert Selection.is_on("telegram", "gateway:WAN", 1, rules)
    assert Selection.is_on("telegram", "gateway:LTE", 2, rules)
    refute Selection.is_on("telegram", "cpu", 1, rules)
    refute Selection.is_on("mattermost", "gateway:WAN", 1, rules)
  end

  test "specific key beats category; instance beats global (ranks 4>3>2>1)" do
    rules = [
      {"telegram", nil, "gateway", "include"},
      {"telegram", nil, "gateway:WAN", "exclude"}
    ]

    refute Selection.is_on("telegram", "gateway:WAN", 1, rules)
    assert Selection.is_on("telegram", "gateway:LTE", 1, rules)

    rules2 = rules ++ [{"telegram", 1, "gateway:WAN", "include"}]
    assert Selection.is_on("telegram", "gateway:WAN", 1, rules2)
    refute Selection.is_on("telegram", "gateway:WAN", 2, rules2)
  end

  test "instance category overrides a global specific include" do
    rules = [
      {"mattermost", nil, "ipsec:5", "include"},
      {"mattermost", 7, "ipsec", "exclude"}
    ]

    refute Selection.is_on("mattermost", "ipsec:5", 7, rules)
    assert Selection.is_on("mattermost", "ipsec:5", 8, rules)
  end

  test "availability is its own category token" do
    rules = [{"email", nil, "availability", "include"}]
    assert Selection.is_on("email", "availability", 3, rules)
  end
end
