defmodule Orbit.Ipsec.History do
  @moduledoc """
  IPsec tunnel state-transition history (ipsec/history.py +
  event_store.py port, on the RAW agent maps). The hub ingest diffs each
  push's ipsec section against the previous cache entry and appends the
  transitions to `ipsec_tunnel_events`; the VPN page's history dialog
  reads the most recent rows per tunnel.

  Ported event kinds: phase1_up / phase1_down / phase1_changed,
  phase2_changed, ping_ok / ping_fail, phase2_dup_on / phase2_dup_off
  (the latter fed by `annotate_dup/2` — the hub-side 3-push streak that
  debounces the agent's instantaneous dup_count).
  """

  @up ~w(up established installed connected 1 true yes)

  @doc """
  Transitions between two raw tunnel lists (pure). Children are keyed by
  name + selector pair — a multi-subnet Phase-2 shares one name across
  several CHILD_SAs, so name alone would collapse them last-wins.
  """
  def diff(prev_tunnels, new_tunnels)

  def diff(prev, new) when is_list(prev) and is_list(new) do
    prev_by_id = Map.new(prev, &{tunnel_key(&1), &1})

    Enum.flat_map(new, fn tunnel ->
      case prev_by_id[tunnel_key(tunnel)] do
        nil -> []
        pt -> tunnel_events(pt, tunnel)
      end
    end)
  end

  def diff(_prev, _new), do: []

  defp tunnel_key(t), do: to_string(t["id"] || t["description"] || "")

  defp tunnel_events(prev, new) do
    id = tunnel_key(new)

    phase1_events(id, prev, new) ++
      phase2_events(id, prev, new) ++ child_events(id, prev, new)
  end

  defp phase1_events(id, prev, new) do
    old_status = to_string(prev["status"] || "")
    new_status = to_string(new["status"] || "")

    cond do
      up?(old_status) != up?(new_status) ->
        kind = if up?(new_status), do: "phase1_up", else: "phase1_down"
        [event(id, "", kind, old_status, new_status)]

      old_status != new_status ->
        [event(id, "", "phase1_changed", old_status, new_status)]

      true ->
        []
    end
  end

  defp phase2_events(id, prev, new) do
    old = {num(prev["phase2_up"]), num(prev["phase2_total"])}
    cur = {num(new["phase2_up"]), num(new["phase2_total"])}

    if old == cur do
      []
    else
      [
        event(
          id,
          "",
          "phase2_changed",
          "#{elem(old, 0)}/#{elem(old, 1)}",
          "#{elem(cur, 0)}/#{elem(cur, 1)}"
        )
      ]
    end
  end

  defp child_events(id, prev, new) do
    prev_children =
      Map.new(prev["children"] || [], fn c -> {child_key(c), c} end)

    Enum.flat_map(new["children"] || [], fn child ->
      case prev_children[child_key(child)] do
        nil -> []
        pc -> ping_event(id, pc, child) ++ dup_event(id, pc, child)
      end
    end)
  end

  defp child_key(c), do: {to_string(c["name"] || ""), c["local_ts"], c["remote_ts"]}

  defp ping_event(id, prev, new) do
    old = to_string(prev["ping_state"] || "none")
    cur = to_string(new["ping_state"] || "none")

    cond do
      old == cur or cur == "none" -> []
      cur == "ok" -> [event(id, new["name"] || "", "ping_ok", old, cur)]
      cur in ["fail", "error"] -> [event(id, new["name"] || "", "ping_fail", old, cur)]
      true -> []
    end
  end

  # Persistent-duplicate note appearing/clearing (hub.py _annotate_dup_persistence
  # + history._dup_event). The selector pair rides in old_value so the
  # timeline reads on its own.
  defp dup_event(id, prev, new) do
    if truthy_flag(prev["phase2_dup_persistent"]) == truthy_flag(new["phase2_dup_persistent"]) do
      []
    else
      selector =
        String.trim(
          "#{new["local_ts"] || prev["local_ts"]} → #{new["remote_ts"] || prev["remote_ts"]}"
        )

      if truthy_flag(new["phase2_dup_persistent"]) do
        [event(id, new["name"] || "", "phase2_dup_on", selector, "#{new["dup_count"] || 2}× SAs")]
      else
        [event(id, new["name"] || "", "phase2_dup_off", selector, "resolved")]
      end
    end
  end

  defp truthy_flag(v), do: v == true

  # ---- dup persistence (hub-side streak, 3 consecutive pushes) --------------

  @dup_persist_polls 3

  @doc """
  Annotate `phase2_dup_persistent` on children whose duplicate Phase-2
  (agent's instantaneous dup_count > 1) survived #{@dup_persist_polls}
  consecutive pushes — a transient rekey blip never lights the note.
  Returns `{annotated_data, new_streaks}`; without an ipsec section the
  data AND the streaks pass through unchanged (collector failure).
  """
  def annotate_dup(%{"ipsec" => %{"tunnels" => tunnels} = ipsec} = data, prev_streaks)
      when is_list(tunnels) do
    {annotated, streaks} =
      Enum.map_reduce(tunnels, %{}, fn t, acc ->
        {children, acc} =
          Enum.map_reduce(t["children"] || [], acc, fn c, acc ->
            if num(c["dup_count"]) > 1 do
              key = "#{tunnel_key(t)}|#{c["local_ts"]}|#{c["remote_ts"]}"
              streak = Map.get(prev_streaks, key, 0) + 1

              {Map.put(c, "phase2_dup_persistent", streak >= @dup_persist_polls),
               Map.put(acc, key, streak)}
            else
              {Map.put(c, "phase2_dup_persistent", false), acc}
            end
          end)

        {Map.put(t, "children", children), acc}
      end)

    {put_in(data, ["ipsec"], Map.put(ipsec, "tunnels", annotated)), streaks}
  end

  def annotate_dup(data, prev_streaks), do: {data, prev_streaks}

  defp event(tunnel_id, child, kind, old, new) do
    %{
      tunnel_id: tunnel_id,
      child_name: to_string(child),
      event_type: kind,
      old_value: String.slice(to_string(old), 0, 255),
      new_value: String.slice(to_string(new), 0, 255)
    }
  end

  defp up?(status), do: String.downcase(status) in @up
  defp num(v) when is_number(v), do: trunc(v)
  defp num(_), do: 0

  # ---- persistence -----------------------------------------------------------

  @doc "Append diffed transitions at one shared timestamp. No-op on []."
  def record(_instance_id, _ts, []), do: 0

  def record(instance_id, %DateTime{} = ts, events) do
    naive = ts |> DateTime.to_naive() |> NaiveDateTime.truncate(:second)
    placeholders = Enum.map_join(events, ", ", fn _ -> "(?, ?, ?, ?, ?, ?, ?)" end)

    params =
      Enum.flat_map(events, fn e ->
        [instance_id, e.tunnel_id, e.child_name, naive, e.event_type, e.old_value, e.new_value]
      end)

    Orbit.Repo.query!(
      "INSERT INTO ipsec_tunnel_events " <>
        "(instance_id, tunnel_id, child_name, ts, event_type, old_value, new_value) VALUES " <>
        placeholders,
      params
    )

    length(events)
  end

  # ---- graph lanes (TunnelGraphDialog parity) --------------------------------

  @doc """
  Three state lanes (phase1 / phase2 / ping) for the graph: each lane is a
  list of `%{left, width, state}` segments (percent of the window, state in
  :up | :down | :partial | :unknown). Window = oldest event → now; the
  newest segment takes the tunnel's LIVE state so the right edge is always
  current. Answers only "was it up?" — dup notes are deliberately not a lane.
  """
  def lanes(events, live, %DateTime{} = now) do
    sorted = Enum.sort_by(events, & &1.ts, DateTime)

    window_start =
      case sorted do
        [first | _] -> first.ts
        [] -> DateTime.add(now, -3600)
      end

    span = max(DateTime.diff(now, window_start), 1)
    x = fn ts -> min(max(DateTime.diff(ts, window_start) / span * 100, 0.0), 100.0) end

    %{
      window_start: window_start,
      phase1: build_lane(sorted, &phase1_state/1, live_up_state(live.up), x),
      phase2: build_lane(sorted, &phase2_state/1, p2_state(live.phase2_up, live.phase2_total), x),
      ping: build_lane(sorted, &ping_state/1, nil, x)
    }
  end

  defp live_up_state(true), do: :up
  defp live_up_state(_), do: :down

  defp p2_state(_up, 0), do: :unknown
  defp p2_state(up, _total) when up <= 0, do: :down
  defp p2_state(up, total) when up >= total, do: :up
  defp p2_state(_up, _total), do: :partial

  defp phase1_state(%{event_type: "phase1_up"}), do: :up
  defp phase1_state(%{event_type: "phase1_down"}), do: :down

  defp phase1_state(%{event_type: "phase1_changed", new_value: v}) do
    if String.downcase(to_string(v)) in @up, do: :up, else: :down
  end

  defp phase1_state(_), do: nil

  defp phase2_state(%{event_type: "phase2_changed", new_value: v}) do
    case String.split(to_string(v), "/", parts: 2) do
      [up, total] -> p2_state(int(up), int(total))
      _ -> nil
    end
  end

  defp phase2_state(_), do: nil

  defp ping_state(%{event_type: "ping_ok"}), do: :up
  defp ping_state(%{event_type: "ping_fail"}), do: :down
  defp ping_state(_), do: nil

  defp int(s) do
    case Integer.parse(String.trim(s)) do
      {n, _} -> n
      _ -> 0
    end
  end

  # One lane: fold the mapped events into state cuts; unknown before the
  # first relevant event; live_state (when given) overrides the tail.
  defp build_lane(sorted_events, state_fn, live_state, x) do
    cuts =
      for e <- sorted_events, state = state_fn.(e), state != nil, do: {x.(e.ts), state}

    {segments, last_left, last_state} =
      Enum.reduce(cuts, {[], 0.0, :unknown}, fn {cut, state}, {acc, left, cur} ->
        {[%{left: left, width: cut - left, state: cur} | acc], cut, state}
      end)

    tail_state = live_state || last_state

    all =
      Enum.reverse([%{left: last_left, width: 100.0 - last_left, state: tail_state} | segments])

    Enum.reject(all, &(&1.width <= 0.0))
  end

  @doc "Most-recent-first history for one tunnel (capped; ix_ipsec_event_lookup)."
  def read(instance_id, tunnel_id, limit \\ 100) do
    Orbit.Repo.query!(
      "SELECT ts, child_name, event_type, old_value, new_value FROM ipsec_tunnel_events " <>
        "WHERE instance_id = ? AND tunnel_id = ? ORDER BY ts DESC, id DESC LIMIT #{limit}",
      [instance_id, tunnel_id]
    ).rows
    |> Enum.map(fn [ts, child, kind, old, new] ->
      %{
        ts: DateTime.from_naive!(ts, "Etc/UTC"),
        child_name: child,
        event_type: kind,
        old_value: old,
        new_value: new
      }
    end)
  rescue
    _ -> []
  end
end
