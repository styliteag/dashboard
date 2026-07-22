defmodule Orbit.Access.StoreTest do
  @moduledoc """
  Pure buffer-transition tests (DB-free house style) — the flood-proofing
  and data-minimisation contract of DR-AL2/AL8 plus the last_seen stamp
  throttle of DR-AL3. The flush/expiry/prune DB path is proven live.
  """

  use ExUnit.Case, async: true

  alias Orbit.Access.Store

  @now ~U[2026-07-17 12:00:00Z]

  defp add(buffers, ptype, pkey, opts) do
    Store.add_request(
      buffers,
      ptype,
      pkey,
      Keyword.get(opts, :ip, "192.0.2.1"),
      "GET",
      "/instances",
      200,
      Map.new(Keyword.take(opts, [:user_id, :sid])),
      Keyword.get(opts, :now, @now),
      Keyword.get(opts, :mono, 0)
    )
  end

  test "aggregate counts every request; user sample capped at 50" do
    buffers =
      Enum.reduce(1..500, Store.empty_buffers(), fn i, acc ->
        add(acc, "user", "1", user_id: 1, mono: i)
      end)

    assert buffers.agg == %{{"user", "1"} => 500}
    assert length(buffers.events) == 50
  end

  test "anon aggregates without event rows and keeps no last_ip (DR-AL8)" do
    buffers = add(Store.empty_buffers(), "anon", "anon", ip: nil)
    assert buffers.agg == %{{"anon", "anon"} => 1}
    assert buffers.events == []
    assert buffers.last_ip == %{}
  end

  test "last_ip tracks the most recent non-empty ip per principal" do
    buffers =
      Store.empty_buffers()
      |> add("user", "1", ip: "192.0.2.1", user_id: 1)
      |> add("user", "1", ip: "192.0.2.2", user_id: 1)
      |> add("user", "1", ip: nil, user_id: 1)

    assert buffers.last_ip == %{{"user", "1"} => "192.0.2.2"}
  end

  test "last_seen stamps are throttled to one per session per 60s" do
    b0 = add(Store.empty_buffers(), "user", "1", user_id: 1, sid: "s1", mono: 0)
    assert map_size(b0.seen) == 1

    # 30s later: throttled, no new stamp even at a later timestamp.
    b1 = add(b0, "user", "1", user_id: 1, sid: "s1", mono: 30_000, now: ~U[2026-07-17 12:00:30Z])
    assert b1.seen == b0.seen

    # 61s later: stamped again with the newer timestamp.
    b2 = add(b1, "user", "1", user_id: 1, sid: "s1", mono: 61_000, now: ~U[2026-07-17 12:01:01Z])
    assert b2.seen["s1"] == ~U[2026-07-17 12:01:01Z]

    # A different session has its own throttle window.
    b3 = add(b2, "user", "2", user_id: 2, sid: "s2", mono: 61_500)
    assert map_size(b3.seen) == 2
  end

  test "touch stamps last_seen without counting a request (LiveView socket path)" do
    # Regression 2026-07-22: live_session navigation never passes the HTTP
    # pipeline, so an operator working purely inside LiveViews went stale
    # after 5 minutes and the Access tab showed "Online now 0" while they
    # were actively clicking. Connected LiveViews stamp via touch instead.
    b0 = Store.touch(Store.empty_buffers(), "s1", @now, 0)
    assert b0.seen == %{"s1" => @now}
    assert b0.agg == %{}
    assert b0.events == []

    # 30s later: throttled (shares the 60s window with the HTTP path).
    b1 = Store.touch(b0, "s1", ~U[2026-07-17 12:00:30Z], 30_000)
    assert b1.seen == b0.seen

    # 61s later: stamped again with the newer timestamp.
    b2 = Store.touch(b1, "s1", ~U[2026-07-17 12:01:01Z], 61_000)
    assert b2.seen["s1"] == ~U[2026-07-17 12:01:01Z]
  end

  test "touch without a sid is a no-op" do
    assert Store.touch(Store.empty_buffers(), nil, @now, 0) == Store.empty_buffers()
  end

  test "long fields truncate to column widths" do
    buffers =
      Store.add_request(
        Store.empty_buffers(),
        "user",
        "1",
        String.duplicate("1", 60),
        "OPTIONSXYZ",
        String.duplicate("/p", 200),
        200,
        %{user_id: 1},
        @now,
        0
      )

    [e] = buffers.events
    assert String.length(e.ip) == 45
    assert String.length(e.method) == 8
    assert String.length(e.path) == 255
  end

  test "new_sid is 32 lowercase hex chars (uuid4-hex parity)" do
    sid = Store.new_sid()
    assert sid =~ ~r/^[0-9a-f]{32}$/
    refute sid == Store.new_sid()
  end

  test "regression: 7-arg record_request goes to the global store, not ptype-as-server" do
    # A double-default head once bound server="user" → GenServer.cast("user", …)
    # FunctionClauseError inside before_send — every page answered 500.
    # Without the global store running this must degrade to a silent no-op.
    assert :ok = Store.record_request("user", "1", "192.0.2.1", "GET", "/", 200, user_id: 1)
    assert :ok = Store.record_request("anon", "anon", nil, "GET", "/", 200)
  end
end
