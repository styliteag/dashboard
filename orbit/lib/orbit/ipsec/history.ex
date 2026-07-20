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
  :up | :down | :partial | :unknown). The newest segment takes the tunnel's
  LIVE state so the right edge is always current. Answers only "was it up?" —
  dup notes are deliberately not a lane.

  `window_start` fixes the left edge. Passing it is what makes a 24h/7d/30d
  selector possible: without it the window is "oldest event → now", so a
  tunnel that flapped once last month and a tunnel that flapped twice this
  morning drew the same picture at different scales, and neither said over
  what period. Omitted (nil) keeps the old derive-from-the-data behaviour.
  """
  def lanes(events, live, now, window_start \\ nil)

  def lanes(events, live, %DateTime{} = now, window_start) do
    all = Enum.sort_by(events, & &1.ts, DateTime)

    # Events older than the window would place cuts at a negative offset,
    # which clamp to 0 and stack invisibly on the left edge. They are not
    # discarded though: the LAST one before the window is what the tunnel was
    # doing when the window opened. Dropping it would paint the first stretch
    # of every 7d view as "no data" for a tunnel that was simply up all along.
    {before, sorted} =
      case window_start do
        nil -> {[], all}
        ws -> Enum.split_with(all, &(DateTime.compare(&1.ts, ws) == :lt))
      end

    window_start =
      cond do
        window_start -> window_start
        sorted != [] -> hd(sorted).ts
        true -> DateTime.add(now, -3600)
      end

    span = max(DateTime.diff(now, window_start), 1)
    x = fn ts -> min(max(DateTime.diff(ts, window_start) / span * 100, 0.0), 100.0) end

    %{
      window_start: window_start,
      phase1:
        build_lane(
          sorted,
          &phase1_state/1,
          live_up_state(live.up),
          x,
          carried(before, &phase1_state/1)
        ),
      phase2:
        build_lane(
          sorted,
          &phase2_state/1,
          p2_state(live.phase2_up, live.phase2_total),
          x,
          carried(before, &phase2_state/1)
        ),
      ping: build_lane(sorted, &ping_state/1, nil, x, carried(before, &ping_state/1))
    }
  end

  @doc """
  Left edge for a named window, or nil for "all" (derive it from the data).

  Shared by both callers of the dialog so the fleet page and the instance page
  cannot end up meaning different things by "7d".
  """
  @spec window_start(String.t(), DateTime.t()) :: DateTime.t() | nil
  def window_start("24h", now), do: DateTime.add(now, -24 * 3600)
  def window_start("7d", now), do: DateTime.add(now, -7 * 24 * 3600)
  def window_start("30d", now), do: DateTime.add(now, -30 * 24 * 3600)
  def window_start(_all, _now), do: nil

  @doc """
  The phase-2 lane as NUMBERS: `%{left, width, label}` segments carrying the
  actual "up/total" the tunnel reported over that stretch.

  The colour lane answers "was it whole?" — amber for partial. But a tunnel
  with eight child SAs where one drops looks exactly like one with two where
  one drops, and the operator's next question is always "how many of how
  many?". Same geometry as `lanes/4` so the two read as one picture.
  """
  def phase2_numeric(events, live, %DateTime{} = now, window_start \\ nil) do
    all = Enum.sort_by(events, & &1.ts, DateTime)

    {before, within} =
      case window_start do
        nil -> {[], all}
        ws -> Enum.split_with(all, &(DateTime.compare(&1.ts, ws) == :lt))
      end

    window_start =
      cond do
        window_start -> window_start
        within != [] -> hd(within).ts
        true -> DateTime.add(now, -3600)
      end

    span = max(DateTime.diff(now, window_start), 1)
    x = fn ts -> min(max(DateTime.diff(ts, window_start) / span * 100, 0.0), 100.0) end

    initial =
      before
      |> Enum.reverse()
      |> Enum.find_value(nil, fn e ->
        if e.event_type == "phase2_changed", do: to_string(e.new_value)
      end)

    cuts =
      for e <- within, e.event_type == "phase2_changed", do: {x.(e.ts), to_string(e.new_value)}

    {segments, last_left, _last_label} =
      Enum.reduce(cuts, {[], 0.0, initial}, fn {cut, label}, {acc, left, cur} ->
        {[%{left: left, width: cut - left, label: cur} | acc], cut, label}
      end)

    # The tail is the LIVE count, like every other lane's right edge.
    live_label = "#{live.phase2_up}/#{live.phase2_total}"

    [%{left: last_left, width: 100.0 - last_left, label: live_label} | segments]
    |> Enum.reverse()
    |> Enum.reject(&(&1.width <= 0.0 or is_nil(&1.label)))
  end

  # The state this lane was in when the window opened: the newest event before
  # it that says anything about this lane.
  defp carried(before, state_fn) do
    before
    |> Enum.reverse()
    |> Enum.find_value(:unknown, fn e -> state_fn.(e) end)
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
  defp build_lane(sorted_events, state_fn, live_state, x, initial) do
    cuts =
      for e <- sorted_events, state = state_fn.(e), state != nil, do: {x.(e.ts), state}

    {segments, last_left, last_state} =
      Enum.reduce(cuts, {[], 0.0, initial}, fn {cut, state}, {acc, left, cur} ->
        {[%{left: left, width: cut - left, state: cur} | acc], cut, state}
      end)

    tail_state = live_state || last_state

    all =
      Enum.reverse([%{left: last_left, width: 100.0 - last_left, state: tail_state} | segments])

    all
    |> Enum.reject(&(&1.width <= 0.0))
    |> Enum.map(&widen/1)
    |> Enum.sort_by(&paint_rank/1)
  end

  # A two-minute drop inside a 30d window is 0.005 % wide and rounds away to
  # nothing — and a fleet graph exists precisely to show that drop. Give every
  # segment a floor, and paint the non-up ones last so a widened sliver is not
  # covered by the up stretch it now overlaps.
  @min_width 0.6

  defp widen(%{width: w} = seg) when w < @min_width, do: %{seg | width: @min_width}
  defp widen(seg), do: seg

  defp paint_rank(%{state: :up}), do: 0
  defp paint_rank(%{state: :unknown}), do: 1
  defp paint_rank(_), do: 2

  @doc """
  Most-recent-first history for one tunnel (capped; ix_ipsec_event_lookup).

  `since` is fetched one event WIDER than asked for: the newest event before
  the window is what tells `lanes/4` what the tunnel was doing when the window
  opened. Without it a 7d view of a tunnel that has been up for a month opens
  with a grey "no data" stretch.
  """
  def read(instance_id, tunnel_id, limit \\ 100, since \\ nil) do
    {clause, params} =
      case since do
        %DateTime{} = ts -> {" AND ts >= ?", [instance_id, tunnel_id, ts]}
        _ -> {"", [instance_id, tunnel_id]}
      end

    rows =
      Orbit.Repo.query!(
        "SELECT ts, child_name, event_type, old_value, new_value FROM ipsec_tunnel_events " <>
          "WHERE instance_id = ? AND tunnel_id = ?#{clause} ORDER BY ts DESC, id DESC " <>
          "LIMIT #{limit}",
        params
      ).rows

    (rows ++ preceding(instance_id, tunnel_id, since))
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
  catch
    # A pool checkout exits rather than raising; without this an empty
    # timeline would take the whole page down with it.
    _kind, _reason -> []
  end

  @doc """
  Events for MANY tunnels at once, grouped by `{instance_id, tunnel_id}`.

  The fleet graph draws one lane per tunnel, and doing that with the per-tunnel
  reader would fire one query per row — seventy boxes' worth on one page load.
  This is a single query over the instance ids, grouped in memory.

  Deliberately window-only (no per-tunnel row cap): a cap here would silently
  truncate the middle of somebody's timeline, and the window already bounds it.

  The overall `limit` is a runaway guard, not a display choice. If a fleet ever
  hits it the oldest events of some tunnels drop out and those lanes render as
  grey "no data" — silent truncation of exactly the kind the drawn-row cap
  warns about. It logs when that happens so the grey is explainable.
  """
  @spec read_many([integer()], DateTime.t() | nil, pos_integer()) :: %{
          {integer(), String.t()} => [map()]
        }
  def read_many(instance_ids, since, limit \\ 5_000)

  def read_many([], _since, _limit), do: %{}

  def read_many(instance_ids, since, limit) do
    placeholders = Enum.map_join(instance_ids, ", ", fn _ -> "?" end)

    {clause, params} =
      case since do
        %DateTime{} = ts -> {" AND ts >= ?", instance_ids ++ [ts]}
        _ -> {"", instance_ids}
      end

    Orbit.Repo.query!(
      "SELECT instance_id, tunnel_id, ts, child_name, event_type, old_value, new_value " <>
        "FROM ipsec_tunnel_events WHERE instance_id IN (#{placeholders})#{clause} " <>
        "ORDER BY ts DESC, id DESC LIMIT #{limit}",
      params
    ).rows
    |> tap(fn rows ->
      if length(rows) >= limit do
        require Logger

        Logger.warning(
          "ipsec.history_truncated rows=#{length(rows)} limit=#{limit} " <>
            "instances=#{length(instance_ids)} — older events dropped, some lanes will read as no-data"
        )
      end
    end)
    |> Enum.group_by(fn [iid, tid | _] -> {iid, to_string(tid)} end, fn [
                                                                          _iid,
                                                                          _tid,
                                                                          ts,
                                                                          child,
                                                                          kind,
                                                                          old,
                                                                          new
                                                                        ] ->
      %{
        ts: DateTime.from_naive!(ts, "Etc/UTC"),
        child_name: child,
        event_type: kind,
        old_value: old,
        new_value: new
      }
    end)
  rescue
    _ -> %{}
  catch
    _kind, _reason -> %{}
  end

  # One event per lane kind from before the window, so lanes/4 knows the state
  # the window opened in. Three rows at most, not the whole history.
  defp preceding(_instance_id, _tunnel_id, nil), do: []

  defp preceding(instance_id, tunnel_id, %DateTime{} = since) do
    Orbit.Repo.query!(
      "SELECT ts, child_name, event_type, old_value, new_value FROM ipsec_tunnel_events " <>
        "WHERE instance_id = ? AND tunnel_id = ? AND ts < ? ORDER BY ts DESC, id DESC LIMIT 12",
      [instance_id, tunnel_id, since]
    ).rows
  rescue
    _ -> []
  catch
    _kind, _reason -> []
  end
end
