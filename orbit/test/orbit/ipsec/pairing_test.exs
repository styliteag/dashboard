defmodule Orbit.Ipsec.PairingTest do
  @moduledoc """
  Peer matching, grouping and pair health for the fleet VPN page — parity
  with the retired React overview (_attach_peers / buildGroups / pairHealth,
  old backend test_vpn_pairing.py).
  """

  use ExUnit.Case, async: true

  alias Orbit.Ipsec.Pairing

  defp tunnel(overrides) do
    Map.merge(
      %{
        instance_id: 1,
        id: "con1",
        instance_name: "box1",
        up: true,
        stale: false,
        local: "",
        remote: "",
        ike_init_spi: "",
        ike_resp_spi: "",
        uptime_s: 0,
        children: []
      },
      Map.new(overrides)
    )
  end

  describe "attach_peers/1" do
    test "matches by the shared IKE cookie pair (NAT-safe primary key)" do
      a = tunnel(instance_id: 1, ike_init_spi: "aa", ike_resp_spi: "bb")
      b = tunnel(instance_id: 2, ike_init_spi: "aa", ike_resp_spi: "bb")
      [pa, pb] = Pairing.attach_peers([a, b])
      assert pa.peer_key == "2:con1"
      assert pb.peer_key == "1:con1"
    end

    test "falls back to the reversed transport-IP pair (down tunnels have no SPI)" do
      a = tunnel(instance_id: 1, local: "1.1.1.1", remote: "2.2.2.2")
      b = tunnel(instance_id: 2, local: "2.2.2.2", remote: "1.1.1.1")
      [pa, pb] = Pairing.attach_peers([a, b])
      assert pa.peer_key == "2:con1"
      assert pb.peer_key == "1:con1"
    end

    test "never matches a tunnel on the same instance (self/sibling)" do
      a = tunnel(instance_id: 1, id: "con1", ike_init_spi: "aa", ike_resp_spi: "bb")
      sibling = tunnel(instance_id: 1, id: "con2", ike_init_spi: "aa", ike_resp_spi: "bb")
      [pa, ps] = Pairing.attach_peers([a, sibling])
      assert pa.peer_key == nil
      assert ps.peer_key == nil
    end

    test "no match leaves peer_key nil" do
      [p] = Pairing.attach_peers([tunnel(local: "1.1.1.1", remote: "2.2.2.2")])
      assert p.peer_key == nil
    end
  end

  describe "build_groups/1" do
    test "pairs two visible ends; a filtered-out peer leaves a singleton" do
      a = tunnel(instance_id: 1, local: "1.1.1.1", remote: "2.2.2.2")
      b = tunnel(instance_id: 2, local: "2.2.2.2", remote: "1.1.1.1")
      solo = tunnel(instance_id: 3, id: "con9")
      [pa, pb, psolo] = Pairing.attach_peers([a, b, solo])

      assert [%{paired: true, members: [_, _]}, %{paired: false}] =
               Pairing.build_groups([pa, pb, psolo])

      # peer hidden by a filter → singleton, the hidden row is not smuggled in
      assert [%{paired: false, members: [one]}] = Pairing.build_groups([pa])
      assert one.instance_id == 1
    end

    test "group_key is stable regardless of member order" do
      a = tunnel(instance_id: 1)
      b = tunnel(instance_id: 2)
      assert Pairing.group_key(%{members: [a, b]}) == Pairing.group_key(%{members: [b, a]})
    end
  end

  describe "pair_health/2" do
    test "stale beats everything — a stale pair must not collapse as healthy" do
      a = tunnel(stale: true)
      b = tunnel([])
      assert {:warn, "stale"} = Pairing.pair_health(a, b)
    end

    test "status mismatch and both down" do
      assert {:error, "status mismatch"} =
               Pairing.pair_health(tunnel(up: true), tunnel(up: false))

      assert {:muted, "both down"} = Pairing.pair_health(tunnel(up: false), tunnel(up: false))
    end

    test "both up folds the ping monitors in" do
      ok = tunnel(children: [%{"ping_state" => "ok"}])
      fail = tunnel(children: [%{"ping_state" => "fail"}])
      err = tunnel(children: [%{"ping_state" => "error"}])
      none = tunnel(children: [])

      assert {:ok, "both up"} = Pairing.pair_health(ok, ok)
      assert {:error, "ping fail"} = Pairing.pair_health(ok, fail)
      # symmetric failure is the usual outage shape — worst across both ends
      assert {:error, "ping fail"} = Pairing.pair_health(fail, fail)
      # two-sided disagreement ranks as mismatch; error only when not a mismatch
      assert {:warn, "ping mismatch"} = Pairing.pair_health(ok, err)
      assert {:warn, "ping error"} = Pairing.pair_health(err, err)
      assert {:warn, "ping error"} = Pairing.pair_health(err, none)
      # a one-sided probe is not a mismatch — one side just pings
      assert {:ok, "both up"} = Pairing.pair_health(ok, none)
    end
  end

  describe "dup rollup" do
    test "collects only persisted duplicates, with selector and count" do
      children = [
        %{"local_ts" => "10.0.0.0/24", "remote_ts" => "10.1.0.0/24"},
        %{
          "local_ts" => "10.0.0.0/24",
          "remote_ts" => "10.2.0.0/24",
          "phase2_dup_persistent" => true,
          "dup_count" => 3
        },
        %{"remote_ts" => "10.3.0.0/24", "phase2_dup_persistent" => true}
      ]

      dups = Pairing.dup_selectors(children)
      assert dups == [{"10.0.0.0/24", "10.2.0.0/24", 3}, {"?", "10.3.0.0/24", 2}]
      assert Pairing.dup_badge(dups) == "⚠ 3× SAs"
      assert Pairing.dup_title(dups) =~ "10.2.0.0/24: 3×"
      assert Pairing.dup_title(dups) =~ "10.3.0.0/24: 2×"
      assert Pairing.dup_selectors(nil) == []
    end
  end
end
