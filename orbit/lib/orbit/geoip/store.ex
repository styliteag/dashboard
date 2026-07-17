defmodule Orbit.GeoIP.Store do
  @moduledoc """
  Process-cached geoip_config snapshot. The gate consults `current_rules/0`
  on every request — it must never touch the DB, so the parsed Ruleset lives
  in :persistent_term (rare writes, constant-time reads).

  The python stack still owns the config editor until orbit grows its own
  superadmin surface, so this store re-polls the row every 60s: a save over
  there must reach this gate without an orbit restart. A load failure keeps
  the previous snapshot (never crash the gate, never silently widen it) —
  except at first boot, where it stays at the DISABLED default (DR-G3).
  """

  use GenServer

  require Logger

  alias Orbit.GeoIP.Rules

  @reload_ms 60_000
  @rules_key {__MODULE__, :rules}
  @throttle_table :geoip_log_throttle

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "The current parsed ruleset (DISABLED until first successful load)."
  def current_rules do
    :persistent_term.get(@rules_key, Rules.disabled())
  end

  @doc "Synchronous re-load (used by tests and future save paths)."
  def reload(server \\ __MODULE__), do: GenServer.call(server, :reload)

  @doc """
  Denial-log throttle: one line per IP per 10s window, so a scripted scanner
  cannot flood the log (middleware.py parity). Safe without the store (tests):
  missing table logs everything.
  """
  def should_log?(ip) do
    now = System.monotonic_time(:millisecond)

    if :ets.info(@throttle_table, :size) > 1000, do: :ets.delete_all_objects(@throttle_table)

    case :ets.lookup(@throttle_table, ip) do
      [{^ip, last}] when now - last < 10_000 ->
        false

      _ ->
        :ets.insert(@throttle_table, {ip, now})
        true
    end
  rescue
    ArgumentError -> true
  end

  # -- GenServer ------------------------------------------------------------

  @impl true
  def init(:ok) do
    :ets.new(@throttle_table, [:named_table, :public, :set, write_concurrency: true])
    load()
    Process.send_after(self(), :reload, @reload_ms)
    {:ok, %{}}
  end

  @impl true
  def handle_call(:reload, _from, state) do
    {:reply, load(), state}
  end

  @impl true
  def handle_info(:reload, state) do
    load()
    Process.send_after(self(), :reload, @reload_ms)
    {:noreply, state}
  end

  defp load do
    rules =
      case Orbit.Repo.get(Orbit.GeoIP.Config, 1) do
        nil -> Rules.disabled()
        row -> Rules.parse_rules(row.enabled, row.countries, row.whitelist)
      end

    previous = :persistent_term.get(@rules_key, nil)

    if previous == nil or previous != rules do
      :persistent_term.put(@rules_key, rules)

      Logger.info(
        "geoip.config_loaded enabled=#{rules.enabled} " <>
          "countries=#{inspect(Enum.sort(rules.countries))} " <>
          "cidrs=#{length(rules.cidrs)} hostnames=#{length(rules.hostnames)}"
      )

      # Hostname set may have changed — resolve promptly, not in ≤5 min.
      Orbit.GeoIP.Dyndns.refresh()
    end

    :ok
  rescue
    # Missing table / DB down: keep the previous snapshot (or the DISABLED
    # boot default) — the gate must not crash and must not silently widen.
    error ->
      Logger.error("geoip.config_load_failed error=#{Exception.message(error)}")
      :error
  end
end
