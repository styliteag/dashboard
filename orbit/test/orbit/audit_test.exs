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

  describe "safe_detail/1 — allowlist enforced on the persisted row (invariant 3)" do
    test "keys outside the allowlist never reach the database" do
      # Before this filter the DB row kept whatever map a caller passed; the
      # allowlist governed only the mirrored log line. One route passing a
      # raw params map would have written secrets into a table admins read.
      detail = %{
        "name" => "opn1",
        "api_secret" => "s3cr3t",
        "agent_token" => "tok",
        "ssh_private_key" => "-----BEGIN",
        "password" => "hunter2"
      }

      assert Orbit.Audit.safe_detail(detail) == %{"name" => "opn1"}
    end

    test "a detail with nothing allowlisted becomes nil, not an empty object" do
      assert Orbit.Audit.safe_detail(%{"api_secret" => "s3cr3t"}) == nil
    end

    test "nil and non-map details are passed through as nil" do
      assert Orbit.Audit.safe_detail(nil) == nil
      assert Orbit.Audit.safe_detail("just a string") == nil
    end

    test "the keys real callers use survive the filter" do
      # Regression guard: adding the filter must not silently blank the
      # details existing mutations already record.
      detail = %{
        "reason" => "r",
        "name" => "n",
        "kind" => "k",
        "mode" => "m",
        "selector" => "s",
        "consumer" => "c",
        "channel" => "ch",
        "entity_key" => "e",
        "interface" => "em0",
        "capture_id" => "42",
        "uuid" => "u",
        "version" => "1.2.3",
        "country" => "DE",
        "seconds" => 30,
        "why" => "w",
        "from_group_id" => 1,
        "to_group_id" => 2
      }

      assert Orbit.Audit.safe_detail(detail) == detail
    end
  end
end
