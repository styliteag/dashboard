defmodule Orbit.GeoIP.Rules do
  @moduledoc """
  Pure GeoIP decision logic — port of geoip/rules.py. No DB, no I/O.

  The semantics are the contract of docs/geoip-access-restriction.md:
  DR-G3 (empty config = allow all, so there is no first-boot lockout path),
  DR-G4 (whitelist = CIDRs v4/v6 or DynDNS hostnames), DR-G5 (unknown
  country fails closed; a missing/broken mmdb fails OPEN so a bad DB update
  cannot lock the whole company out), DR-G8 (whitelist beats blocklist
  beats country-allow — the evaluation order in `decide/6` is part of the
  contract and tested).
  """

  defmodule Ruleset do
    @moduledoc "Parsed, immutable snapshot of the geoip_config row."
    defstruct enabled: false, countries: MapSet.new(), cidrs: [], hostnames: []

    @type t :: %__MODULE__{
            enabled: boolean(),
            countries: MapSet.t(String.t()),
            cidrs: [{:inet.ip_address(), pos_integer()}],
            hostnames: [String.t()]
          }
  end

  defmodule Decision do
    @moduledoc false
    defstruct [:allowed, :reason, :country]
  end

  # RFC 1123 hostname with at least one dot (a bare label is almost always a
  # typo for a CIDR entry, and DynDNS names are always fully qualified).
  @hostname_re ~r/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i

  def disabled, do: %Ruleset{}

  @doc "False when the config cannot block anything (DR-G3 allow-all)."
  def restricting?(%Ruleset{enabled: false}), do: false

  def restricting?(%Ruleset{} = r),
    do: MapSet.size(r.countries) > 0 or r.cidrs != [] or r.hostnames != []

  @doc """
  `{:cidr, {addr, prefix}}` or `{:hostname, name}` — `:error` otherwise.
  Single IPs are accepted and normalized to /32 (v4) or /128 (v6).
  """
  def classify_entry(entry) do
    text = String.trim(entry)

    cond do
      text == "" -> :error
      cidr = parse_cidr(text) -> {:cidr, cidr}
      Regex.match?(@hostname_re, text) -> {:hostname, String.downcase(text)}
      true -> :error
    end
  end

  @doc """
  DB row values → Ruleset. Tolerant: unparseable entries are dropped, not
  fatal — a bad row must degrade to "less restrictive", never crash the gate.
  """
  def parse_rules(enabled, countries_json, whitelist_json) do
    countries =
      for c <- decode_list(countries_json), is_binary(c), String.length(c) == 2 do
        String.upcase(c)
      end

    {cidrs, hostnames} =
      decode_list(whitelist_json)
      |> Enum.filter(&is_binary/1)
      |> Enum.reduce({[], []}, fn entry, {cidrs, hosts} ->
        case classify_entry(entry) do
          {:cidr, cidr} -> {[cidr | cidrs], hosts}
          {:hostname, host} -> {cidrs, [host | hosts]}
          :error -> {cidrs, hosts}
        end
      end)

    %Ruleset{
      enabled: enabled == true,
      countries: MapSet.new(countries),
      cidrs: Enum.reverse(cidrs),
      hostnames: Enum.reverse(hostnames)
    }
  end

  @doc "CIDR match (v4+v6) or membership in the DynDNS-resolved IP set."
  def ip_whitelisted?(ip, %Ruleset{} = rules, resolved_ips) do
    MapSet.member?(resolved_ips, ip) or
      case :inet.parse_strict_address(String.to_charlist(ip)) do
        {:ok, addr} -> Enum.any?(rules.cidrs, &addr_in_cidr?(addr, &1))
        {:error, _} -> false
      end
  end

  @doc """
  The single yes/no every enforcement point uses.

  Evaluation order matters and is part of the contract: whitelist first
  (DR-G4 — the operator rescue beats even the blocklist), then the CrowdSec
  blocklist (DR-G8 — `banned` is injected only when that separate switch is
  on, and applies even with the country restriction off), then
  disabled/empty-config allow (DR-G3), mmdb missing fails open (DR-G5), and
  finally the country allowlist with unknown-country failing closed.
  """
  def decide(ip, %Ruleset{} = rules, country, resolved_ips, db_available?, banned \\ nil) do
    restricting = restricting?(rules)

    cond do
      not restricting and is_nil(banned) ->
        %Decision{allowed: true, reason: "not_restricting"}

      ip_whitelisted?(ip, rules, resolved_ips) ->
        %Decision{allowed: true, reason: "whitelisted"}

      banned != nil and banned.(ip) ->
        %Decision{allowed: false, reason: "crowdsec_banned", country: country}

      not restricting ->
        %Decision{allowed: true, reason: "not_restricting"}

      not db_available? ->
        # Infrastructure failure, not a policy answer — allow, callers log loud.
        %Decision{allowed: true, reason: "db_unavailable"}

      country != nil and MapSet.member?(rules.countries, String.upcase(country)) ->
        %Decision{allowed: true, reason: "country_allowed", country: country}

      true ->
        reason = if country, do: "country_blocked", else: "no_country"
        %Decision{allowed: false, reason: reason, country: country}
    end
  end

  # -- CIDR helpers (stdlib only: :inet parsing + bitwise prefix compare) ----

  defp decode_list(json) do
    case Jason.decode(json || "[]") do
      {:ok, list} when is_list(list) -> list
      _ -> []
    end
  end

  defp parse_cidr(text) do
    {addr_text, prefix_text} =
      case String.split(text, "/", parts: 2) do
        [addr] -> {addr, nil}
        [addr, prefix] -> {addr, prefix}
      end

    with {:ok, addr} <- :inet.parse_strict_address(String.to_charlist(addr_text)),
         {:ok, prefix} <- parse_prefix(prefix_text, addr) do
      {addr, prefix}
    else
      _ -> nil
    end
  end

  defp parse_prefix(nil, addr), do: {:ok, max_prefix(addr)}

  defp parse_prefix(text, addr) do
    case Integer.parse(text) do
      {n, ""} when n >= 0 ->
        if n <= max_prefix(addr), do: {:ok, n}, else: :error

      _ ->
        :error
    end
  end

  defp max_prefix(addr) when tuple_size(addr) == 4, do: 32
  defp max_prefix(addr) when tuple_size(addr) == 8, do: 128

  defp addr_in_cidr?(addr, {net, prefix}) do
    tuple_size(addr) == tuple_size(net) and
      prefix_bits(addr, prefix) == prefix_bits(net, prefix)
  end

  defp prefix_bits(addr, prefix) do
    <<bits::bitstring-size(^prefix), _::bitstring>> = addr_to_binary(addr)
    bits
  end

  defp addr_to_binary({a, b, c, d}), do: <<a, b, c, d>>

  defp addr_to_binary({a, b, c, d, e, f, g, h}),
    do: <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
end
