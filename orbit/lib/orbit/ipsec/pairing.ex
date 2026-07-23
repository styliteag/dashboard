defmodule Orbit.Ipsec.Pairing do
  @moduledoc """
  Pure fleet-view helpers around one tunnel seen from two managed boxes —
  port of the retired React overview's `_attach_peers` (views/routes.py) and
  `buildGroups`/`pairHealth` (lib/vpn-overview.ts).

  Peer matching: primary key is the IKE cookie pair (initiator+responder
  SPI) — both peers report the IDENTICAL pair and it survives NAT. Fallback
  is the reversed transport-IP pair (A.local==B.remote && A.remote==B.local),
  which also covers down / pre-establish tunnels that have no live SPI yet.
  SPIs rotate on rekey but both ends rotate together, so the refresh cadence
  keeps them in sync.

  Also home to the duplicate-CHILD_SA aggregation: the per-selector
  `phase2_dup_persistent` flags roll up to one tunnel-level badge, because
  the warning is about the tunnel's rekey behaviour, not about one selector
  row buried behind the expand toggle.
  """

  @doc "Stable row identity — matches the LiveView's expand key."
  def row_key(t), do: "#{t.instance_id}:#{t.id}"

  @doc """
  Resolve each tunnel's other end among `tunnels` and store it as
  `:peer_key` (a `row_key/1` value, or nil). Self-matches are impossible:
  a candidate on the same instance is never a peer.
  """
  def attach_peers(tunnels) do
    by_ike =
      tunnels
      |> Enum.filter(&(&1.ike_init_spi != "" and &1.ike_resp_spi != ""))
      |> Enum.group_by(&{&1.ike_init_spi, &1.ike_resp_spi})

    by_ep =
      tunnels
      |> Enum.filter(&(&1.local != "" and &1.remote != ""))
      |> Enum.group_by(&{&1.local, &1.remote})

    Enum.map(tunnels, fn t ->
      peer = ike_peer(by_ike, t) || ep_peer(by_ep, t)
      Map.put(t, :peer_key, peer && row_key(peer))
    end)
  end

  defp ike_peer(_by_ike, %{ike_init_spi: ""}), do: nil
  defp ike_peer(_by_ike, %{ike_resp_spi: ""}), do: nil

  defp ike_peer(by_ike, t),
    do: by_ike |> Map.get({t.ike_init_spi, t.ike_resp_spi}, []) |> other_end(t)

  defp ep_peer(_by_ep, %{local: ""}), do: nil
  defp ep_peer(_by_ep, %{remote: ""}), do: nil

  defp ep_peer(by_ep, t),
    do: by_ep |> Map.get({t.remote, t.local}, []) |> other_end(t)

  defp other_end(candidates, t), do: Enum.find(candidates, &(&1.instance_id != t.instance_id))

  @doc """
  Group the visible rows so the two ends of one tunnel render together:
  `%{members: [a, b], paired: true}` when both ends are in `rows`, else a
  `paired: false` singleton. Built from the FILTERED rows on purpose — a
  peer hidden by search/state filter leaves a singleton, never a group that
  smuggles a filtered-out row back onto the page.
  """
  def build_groups(rows) do
    by_key = Map.new(rows, &{row_key(&1), &1})

    {groups, _seen} =
      Enum.reduce(rows, {[], MapSet.new()}, fn t, {acc, seen} ->
        key = row_key(t)

        if MapSet.member?(seen, key) do
          {acc, seen}
        else
          peer = t.peer_key && Map.get(by_key, t.peer_key)

          if peer != nil and not MapSet.member?(seen, t.peer_key) do
            {[%{members: [t, peer], paired: true} | acc],
             seen |> MapSet.put(key) |> MapSet.put(t.peer_key)}
          else
            {[%{members: [t], paired: false} | acc], MapSet.put(seen, key)}
          end
        end
      end)

    Enum.reverse(groups)
  end

  @doc "Sort-stable group identity for the open/closed override sets."
  def group_key(%{members: members}),
    do: members |> Enum.map(&row_key/1) |> Enum.sort() |> Enum.join("|")

  @doc """
  Combined health of a paired link — `{level, label}` with level
  `:ok | :warn | :error | :muted`, for the group header badge.

  Staleness wins: if either end's agent is silent, this side's status is
  last-known, not live — never report a stale pair as "both up" (it must
  stay expanded, not collapse as healthy). Both Phase 1 up still folds the
  Phase-2 ping monitors in: "established" doesn't mean traffic flows, and
  the whole point of the collapse is to hide *healthy* pairs. Symmetric
  failure (both ends fail) is the usual outage shape, so rank by the worst
  end across both — a plain mismatch check misses it. A one-sided probe
  (the other end monitors nothing) is not a mismatch — one side just pings.
  """
  def pair_health(a, b) do
    cond do
      a.stale or b.stale -> {:warn, "stale"}
      a.up != b.up -> {:error, "status mismatch"}
      not a.up -> {:muted, "both down"}
      true -> ping_health(a.children, b.children)
    end
  end

  defp ping_health(ca, cb) do
    pa = worst_ping(ca)
    pb = worst_ping(cb)
    worst = worst_ping(ca ++ cb)

    cond do
      worst == "fail" -> {:error, "ping fail"}
      pa != "none" and pb != "none" and pa != pb -> {:warn, "ping mismatch"}
      worst == "error" -> {:warn, "ping error"}
      true -> {:ok, "both up"}
    end
  end

  @ping_rank %{"none" => 0, "ok" => 1, "error" => 2, "fail" => 3}

  @doc "Worst ping state across children — fail > error > ok > none."
  def worst_ping(children) do
    children
    |> Enum.map(&to_string(&1["ping_state"] || "none"))
    |> Enum.max_by(&Map.get(@ping_rank, &1, 0), fn -> "none" end)
  end

  @doc """
  The duplicated selectors of a tunnel, as `{local_ts, remote_ts, count}` —
  children whose `phase2_dup_persistent` survived the agent's debounce.
  """
  def dup_selectors(children) do
    for ch <- children || [], ch["phase2_dup_persistent"] == true do
      {to_string(ch["local_ts"] || "?"), to_string(ch["remote_ts"] || "?"),
       dup_n(ch["dup_count"])}
    end
  end

  defp dup_n(n) when is_number(n) and n >= 2, do: trunc(n)
  defp dup_n(_), do: 2

  @doc "Tunnel-level badge text for the worst duplicated selector."
  def dup_badge(dups), do: "⚠ #{dups |> Enum.map(&elem(&1, 2)) |> Enum.max()}× SAs"

  @doc "Tooltip naming every duplicated selector (the badge only shows the worst)."
  def dup_title(dups) do
    "Duplicate CHILD_SAs persisted over several pushes — usually a rekey leak: " <>
      Enum.map_join(dups, "; ", fn {l, r, n} -> "#{l} ⇄ #{r}: #{n}×" end)
  end
end
