defmodule Orbit.Securepoint.Swanctl do
  @moduledoc """
  Parse `swanctl --list-sas/--list-conns --raw` into Orbit IPsec tunnel rows.

  Port of the deleted `backend/src/app/securepoint/swanctl.py`, which was itself
  a port of the identical parser in `agent/orbit_agent.py`. Securepoint has no
  on-box agent, so the dashboard runs swanctl over SSH and parses here — this is
  what yields the IKE cookies, ESP SPIs and byte counters the spcgi JSON API
  never exposes, i.e. the data needed to pair tunnel ends across NAT.

  Output shape is the one the agent pushes, so the checks engine, the VPN page
  and the detail page need no per-vendor branch: string-keyed maps with
  `id`, `description`, `remote`, `local`, `status`, `phase2_up`, `phase2_total`,
  `bytes_in`, `bytes_out`, `seconds_established`, `unique_id`,
  `ike_init_spi`, `ike_resp_spi` and `children`.

  ## Two deliberate divergences from a naive port

  1. **The vici tree is an ORDERED list of `{key, value}` pairs, not a map.**
     Python dicts preserve insertion order and this parser depends on it (child
     dedup keeps first-seen order; section iteration walks in file order).
     Elixir maps do not, so a map-based port would emit tunnels and Phase-2 rows
     in arbitrary order. The pair list also makes python's `key\\x00N`
     disambiguation hack unnecessary: colliding keys simply coexist.

  2. **Colliding sections are kept, never merged** — the reason the hack existed.
     swanctl emits one `… event { <conn> { <sa> } }` envelope per SA and repeats
     a connection name when a passive `%any` half-open responder SA sits beside
     the established one. Merging by key collapses the two: the later
     `CREATED`/`%any` record overwrites the live `ESTABLISHED` SA's host and IKE
     cookie fields, producing a Frankenstein tunnel — `CREATED`/`%any`, a zeroed
     responder SPI, yet `INSTALLED` children. The half-open is dropped in
     `parse_sas/1` instead.

  `agent/orbit_agent.py` still MERGES and therefore still has that bug. Mirroring
  this fix back is its own change: version bump, 3.8 scan, re-sign, canary.
  """

  # Marker keys unique to each record type — never present on the raw envelope.
  @ike_sa_markers ~w(uniqueid state local-host remote-host child-sas)
  @conn_markers ~w(local_addrs remote_addrs children)
  # Real child-SA modes carry traffic; PASS/DROP are policy shunts, not tunnels.
  @tunnel_child_modes ~w(TUNNEL TRANSPORT BEET)

  # -- public ---------------------------------------------------------------

  @doc "Merge live SA status onto configured connections → Orbit tunnel rows."
  def parse_ipsec(sas_raw, conns_raw) do
    sas = parse_sas(sas_raw)
    conns = parse_conns(conns_raw)

    sa_by_name = index_best(sas, & &1["name"])
    sa_by_ep = index_best(sas, &{&1["local"], &1["remote"]})

    {from_conns, used} =
      Enum.map_reduce(conns, {MapSet.new(), MapSet.new()}, fn c, {names, eps} ->
        sa = sa_by_name[c["name"]] || sa_by_ep[{c["local"], c["remote"]}]

        used =
          if sa,
            do: {MapSet.put(names, sa["name"]), MapSet.put(eps, {sa["local"], sa["remote"]})},
            else: {names, eps}

        {to_tunnel(c["name"], c, sa), used}
      end)

    {from_sas, _} =
      Enum.flat_map_reduce(sas, used, fn s, {names, eps} = acc ->
        ep = {s["local"], s["remote"]}

        if MapSet.member?(names, s["name"]) or MapSet.member?(eps, ep) do
          {[], acc}
        else
          best = sa_by_name[s["name"]] || s

          {[to_tunnel(best["name"], nil, best)],
           {MapSet.put(names, s["name"]), MapSet.put(eps, ep)}}
        end
      end)

    from_conns ++ from_sas
  end

  @doc """
  The `ipsec` hub section built from both raw dumps, matching the map shape an
  agent pushes (`%{"running" => bool, "tunnels" => [...]}`).
  """
  def status(sas_raw, conns_raw, running) when is_boolean(running) do
    %{"running" => running, "tunnels" => parse_ipsec(sas_raw, conns_raw)}
  end

  @doc """
  Decode Securepoint's `$XX` hex escaping in a swanctl connection name.

  Securepoint turns characters that aren't valid in a strongSwan section id
  (notably the space) into `$` + two hex digits — `Vendor$20Tunnel` is
  `Vendor Tunnel`. The ENCODED form stays the tunnel `id`, because `swanctl
  --ike` expects the section name verbatim; only the human `description` is
  decoded. Bytes are reassembled before UTF-8 decoding so a multi-byte escape
  (an umlaut as `$C3$BC`) round-trips instead of splitting into mojibake.
  """
  def unescape_conn_name(name) when is_binary(name) do
    if String.contains?(name, "$"), do: do_unescape(name, []), else: name
  end

  def unescape_conn_name(name), do: to_string(name)

  defp do_unescape(<<?$, a, b, rest::binary>>, acc) when a != ?$ do
    case Integer.parse(<<a, b>>, 16) do
      {byte, ""} -> do_unescape(rest, [byte | acc])
      _ -> do_unescape(<<a, b, rest::binary>>, [?$ | acc])
    end
  end

  defp do_unescape(<<c::utf8, rest::binary>>, acc) do
    do_unescape(rest, [<<c::utf8>> | acc])
  end

  defp do_unescape(<<>>, acc) do
    acc
    |> Enum.reverse()
    |> Enum.map(fn
      b when is_integer(b) -> <<b>>
      s -> s
    end)
    |> IO.iodata_to_binary()
    |> then(&if String.valid?(&1), do: &1, else: String.replace_invalid(&1))
  end

  # -- vici tree (ORDERED pair list) ----------------------------------------

  @doc false
  def tokenize(out) do
    out
    |> String.replace(~r/([{}\[\]])/, " \\1 ")
    |> String.split()
    |> parse_tokens()
  end

  # Returns an ordered list of {key, value}; value is a binary, a list of
  # binaries, or a nested ordered pair list.
  defp parse_tokens(tokens) do
    {tree, _rest} = parse_section(tokens, [])
    Enum.reverse(tree)
  end

  defp parse_section([], acc), do: {acc, []}

  defp parse_section(["}" | rest], acc), do: {acc, rest}
  defp parse_section(["]" | rest], acc), do: {acc, rest}

  defp parse_section([tok | rest], acc) do
    cond do
      # `key=` on its own opens the next `{`/`[` block.
      String.ends_with?(tok, "=") and match?(["{" | _], rest) ->
        key = String.trim_trailing(tok, "=")
        [_ | after_brace] = rest
        {child, rest2} = parse_section(after_brace, [])
        parse_section(rest2, [{key, Enum.reverse(child)} | acc])

      String.ends_with?(tok, "=") and match?(["[" | _], rest) ->
        key = String.trim_trailing(tok, "=")
        [_ | after_brack] = rest
        {items, rest2} = parse_list(after_brack, [])
        parse_section(rest2, [{key, items} | acc])

      String.contains?(tok, "=") ->
        [k, v] = String.split(tok, "=", parts: 2)
        parse_section(rest, [{k, v} | acc])

      # A bare name followed by a block: `<name> { ... }`.
      match?(["{" | _], rest) ->
        [_ | after_brace] = rest
        {child, rest2} = parse_section(after_brace, [])
        parse_section(rest2, [{tok, Enum.reverse(child)} | acc])

      match?(["[" | _], rest) ->
        [_ | after_brack] = rest
        {items, rest2} = parse_list(after_brack, [])
        parse_section(rest2, [{tok, items} | acc])

      true ->
        parse_section(rest, acc)
    end
  end

  defp parse_list(["]" | rest], acc), do: {Enum.reverse(acc), rest}
  defp parse_list([], acc), do: {Enum.reverse(acc), []}
  defp parse_list([tok | rest], acc), do: parse_list(rest, [tok | acc])

  # First value for `key` in an ordered pair list.
  defp get(pairs, key, default \\ nil) when is_list(pairs) do
    case List.keyfind(pairs, key, 0) do
      {^key, v} -> v
      nil -> default
    end
  end

  defp sections(pairs) when is_list(pairs) do
    for {k, v} <- pairs, is_list(v), not list_of_binaries?(v), do: {k, v}
  end

  defp sections(_), do: []

  defp list_of_binaries?(l), do: Enum.all?(l, &is_binary/1)

  # Every nested section carrying any of `markers`, depth-first, in file order.
  defp iter_sections(pairs, markers) do
    Enum.flat_map(sections(pairs), fn {name, sec} ->
      if Enum.any?(markers, &List.keymember?(sec, &1, 0)),
        do: [{name, sec}],
        else: iter_sections(sec, markers)
    end)
  end

  defp first(v) when is_list(v), do: if(v == [], do: "", else: to_string(hd(v)))
  defp first(v) when is_binary(v), do: v
  defp first(_), do: ""

  defp to_int(v) do
    case v |> to_string() |> Integer.parse() do
      {n, _} -> n
      :error -> 0
    end
  end

  # Normalize a strongSwan traffic selector to just the subnet.
  defp clean_ts(""), do: ""

  defp clean_ts(ts) do
    ts
    |> String.split("|", parts: 2)
    |> hd()
    |> String.split("[", parts: 2)
    |> hd()
    |> String.trim()
  end

  # -- SAs -------------------------------------------------------------------

  @doc false
  def parse_sas(out) when is_binary(out) do
    if String.trim(out) == "" do
      []
    else
      out
      |> tokenize()
      |> iter_sections(@ike_sa_markers)
      |> Enum.reject(&half_open?/1)
      |> Enum.map(&sa_row/1)
    end
  end

  def parse_sas(_), do: []

  # Passive `%any` / CREATED half-open responder SAs carry no usable host or
  # cookie. Down tunnels come from --list-conns instead.
  defp half_open?({_name, ike}) do
    get(ike, "local-host") == "%any" or
      ike |> get("state", "") |> to_string() |> String.upcase() == "CREATED"
  end

  defp sa_row({name, ike}) do
    children =
      ike
      |> get("child-sas", [])
      |> sections()
      |> Enum.map(&sa_child/1)
      |> dedupe_children()

    %{
      "name" => name,
      "remote" => get(ike, "remote-host", ""),
      "local" => get(ike, "local-host", ""),
      "status" => get(ike, "state", "unknown"),
      "phase2_up" => Enum.count(children, &(&1["state"] == "INSTALLED")),
      "phase2_total" => length(children),
      "seconds_established" => to_int(get(ike, "established")),
      "bytes_in" => Enum.sum(Enum.map(children, & &1["bytes_in"])),
      "bytes_out" => Enum.sum(Enum.map(children, & &1["bytes_out"])),
      "unique_id" => to_string(get(ike, "uniqueid", "")),
      "ike_init_spi" => to_string(get(ike, "initiator-spi", "")),
      "ike_resp_spi" => to_string(get(ike, "responder-spi", "")),
      "children" => children
    }
  end

  defp sa_child({ckey, child}) do
    %{
      "name" => first(get(child, "name", "")) |> fallback(Regex.replace(~r/-\d+$/, ckey, "")),
      "local_ts" => clean_ts(first(get(child, "local-ts", ""))),
      "remote_ts" => clean_ts(first(get(child, "remote-ts", ""))),
      "state" => child |> get("state", "") |> to_string() |> String.upcase(),
      "bytes_in" => to_int(get(child, "bytes-in")),
      "bytes_out" => to_int(get(child, "bytes-out")),
      "spi_in" => to_string(get(child, "spi-in", "")),
      "spi_out" => to_string(get(child, "spi-out", ""))
    }
  end

  defp fallback("", other), do: other
  defp fallback(v, _other), do: v

  # Collapse make-before-break child-SA rekey duplicates: one row per Phase-2.
  # Children without any selector can't be keyed and pass through untouched.
  defp dedupe_children(children) do
    {keyed, passthrough} =
      Enum.split_with(children, &(&1["local_ts"] != "" or &1["remote_ts"] != ""))

    best =
      Enum.reduce(keyed, [], fn c, acc ->
        sel = {c["local_ts"], c["remote_ts"]}

        case List.keyfind(acc, sel, 0) do
          nil ->
            acc ++ [{sel, c}]

          {^sel, cur} ->
            if child_rank(c) > child_rank(cur),
              do: List.keyreplace(acc, sel, 0, {sel, c}),
              else: acc
        end
      end)

    Enum.map(best, fn {_sel, c} -> c end) ++ passthrough
  end

  defp child_rank(c), do: {c["state"] == "INSTALLED", c["bytes_in"] + c["bytes_out"]}

  # -- connections -----------------------------------------------------------

  @doc false
  def parse_conns(out) when is_binary(out) do
    if String.trim(out) == "" do
      []
    else
      out
      |> tokenize()
      |> iter_sections(@conn_markers)
      |> Enum.reject(fn {_n, conn} -> shunt_conn?(get(conn, "children")) end)
      |> Enum.map(&conn_row/1)
    end
  end

  def parse_conns(_), do: []

  defp shunt_conn?(children) when is_list(children) do
    modes =
      children
      |> sections()
      |> Enum.map(fn {_k, c} -> c |> get("mode", "") |> to_string() |> String.upcase() end)

    modes != [] and not Enum.any?(modes, &(&1 in @tunnel_child_modes))
  end

  defp shunt_conn?(_), do: false

  defp conn_row({name, conn}) do
    child_sections = conn |> get("children", []) |> sections()

    %{
      "name" => name,
      "local" => first(get(conn, "local_addrs", "")),
      "remote" => first(get(conn, "remote_addrs", "")),
      "phase2_total" => length(child_sections),
      "children" =>
        Enum.map(child_sections, fn {ckey, child} ->
          %{
            "name" => ckey,
            "local_ts" => clean_ts(first(get(child, "local-ts", ""))),
            "remote_ts" => clean_ts(first(get(child, "remote-ts", "")))
          }
        end)
    }
  end

  # -- merge -----------------------------------------------------------------

  defp sa_rank(sa) do
    {sa["status"] |> to_string() |> String.upcase() == "ESTABLISHED", sa["phase2_up"] || 0,
     (sa["bytes_in"] || 0) + (sa["bytes_out"] || 0)}
  end

  defp index_best(sas, key_fun) do
    Enum.reduce(sas, %{}, fn s, acc ->
      k = key_fun.(s)

      case acc[k] do
        nil -> Map.put(acc, k, s)
        cur -> if sa_rank(s) > sa_rank(cur), do: Map.put(acc, k, s), else: acc
      end
    end)
  end

  defp child_row(cc, sc) do
    cc = cc || %{}
    sc = sc || %{}

    %{
      "name" => blank(cc["name"]) || blank(sc["name"]) || "",
      "local_ts" => blank(cc["local_ts"]) || blank(sc["local_ts"]) || "",
      "remote_ts" => blank(cc["remote_ts"]) || blank(sc["remote_ts"]) || "",
      "state" => sc["state"] || "",
      "bytes_in" => sc["bytes_in"] || 0,
      "bytes_out" => sc["bytes_out"] || 0,
      "spi_in" => sc["spi_in"] || "",
      "spi_out" => sc["spi_out"] || ""
    }
  end

  defp blank(nil), do: nil
  defp blank(""), do: nil
  defp blank(v), do: v

  # Configured children first (they carry the stable names), then any live child
  # SA that no configured entry claimed.
  defp merge_children(conn_children, sa_children) do
    by_name = Map.new(Enum.filter(sa_children, &(&1["name"] != "")), &{&1["name"], &1})
    by_sel = Map.new(sa_children, &{{&1["local_ts"], &1["remote_ts"]}, &1})

    {rows, used} =
      Enum.map_reduce(conn_children, MapSet.new(), fn cc, used ->
        sc = by_name[cc["name"]] || by_sel[{cc["local_ts"], cc["remote_ts"]}]
        used = if sc, do: MapSet.put(used, sc), else: used
        {child_row(cc, sc), used}
      end)

    rows ++
      (sa_children |> Enum.reject(&MapSet.member?(used, &1)) |> Enum.map(&child_row(nil, &1)))
  end

  defp to_tunnel(name, conn, nil) do
    conn = conn || %{}

    %{
      "id" => name,
      "description" => unescape_conn_name(name),
      "remote" => conn["remote"] || "",
      "local" => conn["local"] || "",
      "status" => "down",
      "phase2_up" => 0,
      "phase2_total" => conn["phase2_total"] || 0,
      "bytes_in" => 0,
      "bytes_out" => 0,
      "seconds_established" => 0,
      "unique_id" => "",
      "ike_init_spi" => "",
      "ike_resp_spi" => "",
      "children" => merge_children(conn["children"] || [], [])
    }
  end

  defp to_tunnel(name, conn, sa) do
    conn = conn || %{}

    %{
      "id" => name,
      "description" => unescape_conn_name(name),
      "remote" => blank(sa["remote"]) || conn["remote"] || "",
      "local" => blank(sa["local"]) || conn["local"] || "",
      "status" => sa["status"],
      "phase2_up" => sa["phase2_up"] || 0,
      # max(): Securepoint configures one Phase-2 with N remote subnets, which
      # strongSwan instantiates as N child SAs — the live count is the truth.
      "phase2_total" => max(conn["phase2_total"] || 0, sa["phase2_total"] || 0),
      "bytes_in" => sa["bytes_in"] || 0,
      "bytes_out" => sa["bytes_out"] || 0,
      "seconds_established" => sa["seconds_established"] || 0,
      "unique_id" => sa["unique_id"] || "",
      "ike_init_spi" => sa["ike_init_spi"] || "",
      "ike_resp_spi" => sa["ike_resp_spi"] || "",
      "children" => merge_children(conn["children"] || [], sa["children"] || [])
    }
  end
end
