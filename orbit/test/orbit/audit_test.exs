defmodule Orbit.AuditTest do
  @moduledoc """
  Structured audit log-line building (DB-free). Regression: an allowlisted
  detail key crashed log_meta/1 — @detail_keys are strings but the meta
  keyword needs atoms, so Keyword.merge/2 raised on every audit carrying
  detail (comment.set, instance.delete, geoip.config.update, …). The DB
  row was written first, so it surfaced only as a caller-process crash.
  """
  use ExUnit.Case, async: true

  test "an allowlisted detail key maps to an atom-keyed meta entry (no raise)" do
    meta =
      Orbit.Audit.log_meta(
        action: "comment.set",
        result: "ok",
        user_id: 7,
        target_type: "instance",
        target_id: 1,
        detail: %{"kind" => "ipsec", "entity_key" => "con1"}
      )

    assert meta[:result] == "ok"
    assert meta[:user_id] == 7
    assert meta[:target] == "instance:1"
    assert meta[:kind] == "ipsec"
    assert meta[:entity_key] == "con1"
    # Every key is an atom — the exact thing Keyword.merge needs.
    assert Enum.all?(meta, fn {k, _} -> is_atom(k) end)
  end

  test "non-allowlisted detail keys are dropped from the log line" do
    meta = Orbit.Audit.log_meta(action: "x", result: "ok", detail: %{"secret" => "nope"})
    refute Keyword.has_key?(meta, :secret)
  end

  test "no detail → just the base fields, nil ones removed" do
    meta = Orbit.Audit.log_meta(action: "x", result: "ok", user_id: 3)
    assert meta == [result: "ok", user_id: 3]
  end
end
