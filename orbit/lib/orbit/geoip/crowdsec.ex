defmodule Orbit.GeoIP.Crowdsec do
  @moduledoc """
  CrowdSec bad-actor blocklist (DR-G8) — stream-mode bouncer, port of
  geoip/crowdsec.py. A 30s GenServer timer pulls ban decisions from the
  LAPI (`/v1/decisions/stream`): the first successful call fetches the full
  set (startup=true), later calls only deltas. The gate checks IPs against
  an ETS cache — never live HTTP in the request path. A LAPI outage keeps
  the last known bans (stale beats empty: dropping the list on a hiccup
  would un-ban every attacker at once); staleness is visible via `status/0`.

  Single IPs (the overwhelming majority of community-blocklist entries) are
  O(1) ETS members; genuine ranges (v4/v6) are scanned linearly.

  Same switch shape as GeoIP: configuring DASH_CROWDSEC_API_KEY turns it
  on, DASH_CROWDSEC_DISABLE=true turns it off without losing the key — and
  the blocklist bites even when the country restriction is off.
  """

  use GenServer

  require Logger

  alias Orbit.GeoIP.Rules

  @table :crowdsec_bans
  @sync_ms 30_000
  @sync_timeout_ms 15_000

  def start_link(opts) do
    GenServer.start_link(
      __MODULE__,
      Keyword.get(opts, :sync_on_start, true),
      name: Keyword.get(opts, :name, __MODULE__)
    )
  end

  @doc "True when the blocklist check should run at all."
  def active? do
    key = Application.get_env(:orbit, :crowdsec_api_key)
    key not in [nil, ""] and not Application.get_env(:orbit, :crowdsec_disable, false)
  end

  @doc "O(1) for single-IP bans, linear over the (few) range bans."
  def is_banned(ip) do
    :ets.member(@table, {:ip, ip}) or banned_by_range?(ip)
  rescue
    ArgumentError -> false
  end

  def banned_count do
    :ets.info(@table, :size)
  rescue
    ArgumentError -> 0
  end

  @doc "Sync health for status surfaces (python crowdsec.status parity)."
  def status(server \\ __MODULE__) do
    last =
      try do
        GenServer.call(server, :last)
      catch
        :exit, _ -> %{at: nil, ok: nil, detail: "not running"}
      end

    Map.merge(
      %{
        disabled: Application.get_env(:orbit, :crowdsec_disable, false),
        key_set: Application.get_env(:orbit, :crowdsec_api_key) not in [nil, ""],
        configured: active?(),
        banned_count: banned_count()
      },
      last
    )
  end

  @doc """
  Fold one stream delta into the ETS cache (pure state transition over the
  given table — testable). Only type=ban decisions count; junk values drop.
  """
  def apply_decisions(table \\ @table, new, deleted) do
    for {decisions, removing} <- [{deleted, true}, {new, false}],
        d <- decisions,
        (d["type"] || "ban") == "ban",
        norm = normalize(to_string(d["value"] || "")),
        norm != nil do
      case {norm, removing} do
        {{:ip, canonical}, true} -> :ets.delete(table, {:ip, canonical})
        {{:ip, canonical}, false} -> :ets.insert(table, {{:ip, canonical}})
        {{:range, canonical, _cidr}, true} -> :ets.delete(table, {:range, canonical})
        {{:range, canonical, cidr}, false} -> :ets.insert(table, {{:range, canonical}, cidr})
      end
    end

    :ok
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(sync_on_start) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    # First sync promptly (async — boot must not block on the LAPI).
    # sync_on_start=false is the test seam: Req.Test ownership must be
    # granted before the first pull.
    if sync_on_start, do: send(self(), :sync)
    {:ok, %{startup_done: false, last: %{at: nil, ok: nil, detail: "never synced"}}}
  end

  @impl true
  def handle_call(:last, _from, state), do: {:reply, state.last, state}

  @impl true
  def handle_info(:sync, state) do
    Process.send_after(self(), :sync, @sync_ms)

    if active?() do
      {:noreply, sync(state)}
    else
      {:noreply, state}
    end
  end

  defp sync(state) do
    url =
      Application.get_env(:orbit, :crowdsec_lapi_url, "http://crowdsec:8080")
      |> String.trim_trailing("/")
      |> Kernel.<>("/v1/decisions/stream")

    base_opts = [
      url: url,
      params: [startup: to_string(not state.startup_done)],
      headers: [{"x-api-key", Application.get_env(:orbit, :crowdsec_api_key)}],
      receive_timeout: @sync_timeout_ms,
      retry: false
    ]

    req_opts =
      case Application.get_env(:orbit, :crowdsec_req_plug) do
        nil -> base_opts
        plug -> Keyword.put(base_opts, :plug, plug)
      end

    case Req.get(req_opts) do
      {:ok, %{status: 200, body: body}} when is_map(body) ->
        apply_decisions(body["new"] || [], body["deleted"] || [])
        %{state | startup_done: true} |> finish(true, "#{banned_count()} active bans")

      {:ok, %{status: status}} ->
        # Keep the last known bans — stale beats empty (moduledoc).
        finish(state, false, "LAPI HTTP #{status}")

      {:error, error} ->
        finish(state, false, Exception.message(error))
    end
  end

  defp finish(state, ok, detail) do
    if ok do
      Logger.debug("geoip.crowdsec_sync detail=#{detail}")
    else
      Logger.warning("geoip.crowdsec_sync_failed detail=#{detail}")
    end

    %{state | last: %{at: DateTime.utc_now(), ok: ok, detail: detail}}
  end

  # Decision value → {:ip, canonical} | {:range, canonical, cidr} | nil.
  defp normalize(value) do
    case Rules.classify_entry(value) do
      {:cidr, {addr, prefix}} ->
        if prefix == max_prefix(addr) do
          {:ip, addr |> :inet.ntoa() |> to_string()}
        else
          canonical = "#{addr |> :inet.ntoa() |> to_string()}/#{prefix}"
          {:range, canonical, {addr, prefix}}
        end

      _ ->
        nil
    end
  end

  defp max_prefix(addr) when tuple_size(addr) == 4, do: 32
  defp max_prefix(addr) when tuple_size(addr) == 8, do: 128

  defp banned_by_range?(ip) do
    case :ets.match(@table, {{:range, :"$1"}, :"$2"}) do
      [] ->
        false

      ranges ->
        case :inet.parse_strict_address(String.to_charlist(ip)) do
          {:ok, addr} ->
            Enum.any?(ranges, fn [_canonical, cidr] -> Rules.addr_in_cidr?(addr, cidr) end)

          {:error, _} ->
            false
        end
    end
  end
end
