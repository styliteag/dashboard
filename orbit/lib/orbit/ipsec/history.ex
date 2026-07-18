defmodule Orbit.Ipsec.History do
  @moduledoc """
  IPsec tunnel state-transition history (ipsec/history.py +
  event_store.py port, on the RAW agent maps). The hub ingest diffs each
  push's ipsec section against the previous cache entry and appends the
  transitions to `ipsec_tunnel_events`; the VPN page's history dialog
  reads the most recent rows per tunnel.

  Ported event kinds: phase1_up / phase1_down / phase1_changed,
  phase2_changed, ping_ok / ping_fail. The python `phase2_dup_*` pair is
  NOT ported yet — it rides a hub-side debounce flag
  (phase2_dup_persistent) the orbit hub doesn't compute.
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
        pc -> ping_event(id, pc, child)
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
