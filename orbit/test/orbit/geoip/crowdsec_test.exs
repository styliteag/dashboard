defmodule Orbit.GeoIP.CrowdsecTest do
  @moduledoc """
  Blocklist cache + stream sync (Req.Test plug — no real LAPI). async: false:
  mutates crowdsec application env and the named ETS table via the GenServer.
  """

  use ExUnit.Case, async: false

  alias Orbit.GeoIP.Crowdsec

  setup do
    previous = %{
      key: Application.get_env(:orbit, :crowdsec_api_key),
      disable: Application.get_env(:orbit, :crowdsec_disable),
      plug: Application.get_env(:orbit, :crowdsec_req_plug)
    }

    on_exit(fn ->
      Application.put_env(:orbit, :crowdsec_api_key, previous.key)
      Application.put_env(:orbit, :crowdsec_disable, previous.disable)

      if previous.plug,
        do: Application.put_env(:orbit, :crowdsec_req_plug, previous.plug),
        else: Application.delete_env(:orbit, :crowdsec_req_plug)
    end)

    :ok
  end

  defp fresh_table do
    :ets.new(:crowdsec_test_bans, [:public, :set])
  end

  describe "apply_decisions/3 — pure delta folding" do
    test "single IPs are O(1) members, ranges carry their cidr" do
      t = fresh_table()

      Crowdsec.apply_decisions(
        t,
        [
          %{"type" => "ban", "value" => "203.0.113.7"},
          %{"type" => "ban", "value" => "10.0.0.0/8"},
          %{"type" => "captcha", "value" => "1.1.1.1"},
          %{"type" => "ban", "value" => "junk!!"}
        ],
        []
      )

      assert :ets.member(t, {:ip, "203.0.113.7"})
      assert [[_, {_, 8}]] = :ets.match(t, {{:range, :"$1"}, :"$2"})
      # captcha decision and junk value never land.
      refute :ets.member(t, {:ip, "1.1.1.1"})
      assert :ets.info(t, :size) == 2
    end

    test "deletes remove exactly their entry; delete wins ordering like python" do
      t = fresh_table()
      Crowdsec.apply_decisions(t, [%{"value" => "203.0.113.7"}], [])

      # One delta carrying both delete and re-add: python folds deleted
      # first, then new — the re-add survives.
      Crowdsec.apply_decisions(t, [%{"value" => "203.0.113.7"}], [%{"value" => "203.0.113.7"}])
      assert :ets.member(t, {:ip, "203.0.113.7"})

      Crowdsec.apply_decisions(t, [], [%{"value" => "203.0.113.7"}])
      refute :ets.member(t, {:ip, "203.0.113.7"})
    end
  end

  describe "sync via GenServer (Req.Test)" do
    setup do
      Application.put_env(:orbit, :crowdsec_api_key, "test-bouncer-key")
      Application.put_env(:orbit, :crowdsec_disable, false)
      Application.put_env(:orbit, :crowdsec_req_plug, {Req.Test, __MODULE__})
      :ok
    end

    test "startup pull fills the cache; failure keeps bans (stale beats empty)" do
      test_pid = self()

      Req.Test.stub(__MODULE__, fn conn ->
        conn = Plug.Conn.fetch_query_params(conn)
        send(test_pid, {:startup_param, conn.params["startup"]})

        Req.Test.json(conn, %{
          "new" => [%{"type" => "ban", "value" => "198.51.100.9"}],
          "deleted" => []
        })
      end)

      pid = start_supervised!({Crowdsec, name: nil, sync_on_start: false})
      Req.Test.allow(__MODULE__, self(), pid)
      send(pid, :sync)
      assert_receive {:startup_param, "true"}, 2_000

      wait_until(fn -> Crowdsec.is_banned("198.51.100.9") end)
      refute Crowdsec.is_banned("198.51.100.10")

      # LAPI outage: the cache keeps the last known bans.
      Req.Test.stub(__MODULE__, fn conn -> Plug.Conn.send_resp(conn, 500, "boom") end)
      send(pid, :sync)
      wait_until(fn -> match?(%{ok: false}, GenServer.call(pid, :last)) end)
      assert Crowdsec.is_banned("198.51.100.9")
      assert %{detail: "LAPI HTTP 500"} = GenServer.call(pid, :last)
    end
  end

  describe "active?/0" do
    test "key turns it on, disable turns it off without losing the key" do
      Application.put_env(:orbit, :crowdsec_api_key, nil)
      refute Crowdsec.active?()

      Application.put_env(:orbit, :crowdsec_api_key, "k")
      Application.put_env(:orbit, :crowdsec_disable, false)
      assert Crowdsec.active?()

      Application.put_env(:orbit, :crowdsec_disable, true)
      refute Crowdsec.active?()
    end
  end

  defp wait_until(fun, attempts \\ 100) do
    cond do
      fun.() ->
        :ok

      attempts == 0 ->
        flunk("condition never became true")

      true ->
        Process.sleep(10)
        wait_until(fun, attempts - 1)
    end
  end
end
