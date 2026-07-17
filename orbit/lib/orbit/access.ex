defmodule Orbit.Access do
  @moduledoc """
  Read side of the access accounting (ADR docs/access-log.md, DR-AL7) —
  summary aggregates and the merged event timeline for the Access tab.
  Query-only over the alembic-owned tables; the write side lives in
  Orbit.Access.Store.

  "Online" = registry session without ended_at whose last_seen is younger
  than 5 minutes (5× the stamp throttle, so an active session never
  flickers offline — DR-AL3).
  """

  @online_window_s 5 * 60
  # Instance-access audit actions surfaced as kind "access" (DR-AL7
  # Nachtrag) — extend when new instance-scoped audit actions appear.
  @access_action_prefixes ~w(agent.gui_open shell. capture. packet_capture. firewall.rule.)

  @doc "Aggregates for the Access tab header."
  def summary do
    %{
      online: online_sessions(),
      logins_24h: logins_24h(),
      blocks: blocks_by_reason(),
      principals_24h: principals_24h()
    }
  end

  @doc """
  Merged chronological event list (newest first): auth events + instance
  accesses (audit), geoip/crowdsec denials, sampled request rows. `types`
  filters the sources; request samples default OFF in the UI (polling
  noise, DR-AL7).
  """
  def timeline(types, limit \\ 100, opts \\ []) do
    usernames = usernames_by_id()
    # Free-text q filters AFTER the merge (covers who/ip/text uniformly,
    # incl. the attempted username already folded into `who`); fetch more
    # per source so a filtered view still fills up.
    q = opts |> Keyword.get(:q, "") |> String.trim() |> String.downcase()
    fetch = if q == "", do: limit, else: limit * 5

    []
    |> maybe(types, :auth, fn -> auth_events(fetch, usernames) end)
    |> maybe(types, :access, fn -> access_audit_events(fetch, usernames) end)
    |> maybe(types, :denial, fn -> denial_events(fetch) end)
    |> maybe(types, :request, fn -> request_events(fetch, usernames) end)
    |> within_hours(Keyword.get(opts, :hours))
    |> matching(q)
    |> Enum.sort_by(& &1.ts, {:desc, NaiveDateTime})
    |> Enum.take(limit)
  end

  @doc """
  Grouped view (DR-AL7 Nachtrag): one row per recurring event with count +
  last seen; numeric path segments and ids are masked to `#` so polling
  URLs collapse into one pattern.
  """
  def grouped(types, limit \\ 100, opts \\ []) do
    timeline(types, limit * 10, opts)
    |> Enum.group_by(&{&1.type, &1.who, mask_numbers(&1.text)})
    |> Enum.map(fn {{type, who, text}, events} ->
      %{
        type: type,
        who: who,
        text: text,
        count: length(events),
        last_ts: events |> Enum.map(& &1.ts) |> Enum.max(NaiveDateTime),
        ip: hd(events).ip
      }
    end)
    |> Enum.sort_by(& &1.count, :desc)
    |> Enum.take(limit)
  end

  defp within_hours(events, nil), do: events

  defp within_hours(events, hours) do
    cutoff = naive_ago(hours * 3600)
    Enum.filter(events, &(NaiveDateTime.compare(&1.ts, cutoff) == :gt))
  end

  defp matching(events, ""), do: events

  defp matching(events, q) do
    Enum.filter(events, fn e ->
      haystack = String.downcase("#{e.who} #{e.ip} #{e.text}")
      String.contains?(haystack, q)
    end)
  end

  defp mask_numbers(text) do
    text
    |> String.replace(~r{/\d+}, "/#")
    |> String.replace(~r/\b\d{2,}\b/, "#")
  end

  defp maybe(acc, types, type, fun), do: if(type in types, do: acc ++ fun.(), else: acc)

  defp online_sessions do
    cutoff = naive_ago(@online_window_s)

    query!(
      "SELECT s.user_id, u.username, s.ip, s.created_at, s.last_seen_at " <>
        "FROM auth_sessions s LEFT JOIN users u ON u.id = s.user_id " <>
        "WHERE s.ended_at IS NULL AND s.last_seen_at >= ? " <>
        "ORDER BY s.last_seen_at DESC",
      [cutoff]
    )
    |> Enum.map(fn [user_id, username, ip, created, seen] ->
      %{user_id: user_id, username: username, ip: ip, created_at: created, last_seen_at: seen}
    end)
  end

  defp logins_24h do
    rows =
      query!(
        "SELECT result, COUNT(*) FROM audit_log " <>
          "WHERE action = 'auth.login' AND ts >= ? GROUP BY result",
        [naive_ago(24 * 3600)]
      )

    ok = for([r, n] <- rows, r == "ok", do: n) |> Enum.sum()
    other = for([r, n] <- rows, r != "ok", do: n) |> Enum.sum()
    %{ok: ok, failed: other}
  end

  defp blocks_by_reason do
    query!(
      "SELECT reason, SUM(count) FROM geoip_denial_stats " <>
        "WHERE reason <> 'fail_open' GROUP BY reason ORDER BY SUM(count) DESC",
      []
    )
    |> Enum.map(fn [reason, n] -> %{reason: reason, count: to_int(n)} end)
  end

  defp principals_24h do
    usernames = usernames_by_id()

    query!(
      "SELECT principal_type, principal_key, SUM(count) FROM access_stats " <>
        "WHERE bucket >= ? GROUP BY principal_type, principal_key " <>
        "ORDER BY SUM(count) DESC LIMIT 10",
      [naive_ago(24 * 3600)]
    )
    |> Enum.map(fn [ptype, pkey, n] ->
      %{principal: principal_label(ptype, pkey, usernames), count: to_int(n)}
    end)
  end

  # SUM() over BIGINT comes back as a Decimal struct from myxql — normalise
  # to integer or Enum.sum and the HEEx render both crash on it.
  defp to_int(%Decimal{} = d), do: Decimal.to_integer(d)
  defp to_int(n) when is_integer(n), do: n
  defp to_int(nil), do: 0

  defp principal_label("user", pkey, usernames) do
    case Integer.parse(pkey) do
      {id, ""} -> usernames[id] || "user ##{pkey}"
      _ -> "user #{pkey}"
    end
  end

  defp principal_label(ptype, pkey, _usernames) when ptype == pkey, do: ptype
  defp principal_label(ptype, pkey, _usernames), do: "#{ptype} #{pkey}"

  defp auth_events(limit, usernames) do
    query!(
      "SELECT ts, action, result, user_id, source_ip, detail FROM audit_log " <>
        "WHERE action IN ('auth.login', 'auth.logout', 'auth.session_expired') " <>
        "ORDER BY id DESC LIMIT ?",
      [limit]
    )
    |> Enum.map(fn [ts, action, result, user_id, ip, detail] ->
      %{
        ts: ts,
        type: auth_type(action, result),
        who: usernames[user_id] || attempted_username(detail) || "—",
        ip: ip,
        text: "#{action} #{result}"
      }
    end)
  end

  defp auth_type("auth.login", "ok"), do: :login_ok
  defp auth_type("auth.login", _), do: :login_fail
  defp auth_type("auth.logout", _), do: :logout
  defp auth_type(_, _), do: :session_expired

  # Failed logins carry the attempted username only in the detail JSON.
  defp attempted_username(nil), do: nil

  defp attempted_username(detail) when is_binary(detail) do
    case Jason.decode(detail) do
      {:ok, %{"username" => name}} when is_binary(name) -> name
      _ -> nil
    end
  end

  defp attempted_username(%{"username" => name}) when is_binary(name), do: name
  defp attempted_username(_), do: nil

  defp access_audit_events(limit, usernames) do
    like = Enum.map_join(@access_action_prefixes, " OR ", fn _ -> "action LIKE ?" end)
    params = Enum.map(@access_action_prefixes, &(&1 <> "%")) ++ [limit]

    query!(
      "SELECT a.ts, a.action, a.result, a.user_id, a.source_ip, i.name " <>
        "FROM audit_log a LEFT JOIN instances i " <>
        "ON a.target_type = 'instance' AND i.id = CAST(a.target_id AS UNSIGNED) " <>
        "WHERE #{like} ORDER BY a.id DESC LIMIT ?",
      params
    )
    |> Enum.map(fn [ts, action, result, user_id, ip, instance] ->
      %{
        ts: ts,
        type: :access,
        who: usernames[user_id] || "—",
        ip: ip,
        text: "#{action} #{result}" <> if(instance, do: " · #{instance}", else: "")
      }
    end)
  end

  defp denial_events(limit) do
    query!(
      "SELECT ts, ip, country, path, reason FROM geoip_denial_events " <>
        "ORDER BY id DESC LIMIT ?",
      [limit]
    )
    |> Enum.map(fn [ts, ip, country, path, reason] ->
      %{
        ts: ts,
        type: :denial,
        who: country || "??",
        ip: ip,
        text: "#{reason} · #{path}"
      }
    end)
  end

  defp request_events(limit, usernames) do
    query!(
      "SELECT ts, user_id, ip, method, path, status FROM access_events " <>
        "ORDER BY id DESC LIMIT ?",
      [limit]
    )
    |> Enum.map(fn [ts, user_id, ip, method, path, status] ->
      %{
        ts: ts,
        type: :request,
        who: usernames[user_id] || "—",
        ip: ip,
        text: "#{method} #{path} → #{status}"
      }
    end)
  end

  defp usernames_by_id do
    query!("SELECT id, username FROM users", [])
    |> Map.new(fn [id, username] -> {id, username} end)
  end

  defp naive_ago(seconds) do
    DateTime.utc_now() |> DateTime.add(-seconds, :second) |> DateTime.to_naive()
  end

  defp query!(sql, params), do: Orbit.Repo.query!(sql, params).rows
end
