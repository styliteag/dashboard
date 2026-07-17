defmodule Orbit.Settings do
  @moduledoc """
  Runtime settings: DB overrides (`app_settings`, shared with the python
  backend) over `DASH_*` env defaults — mirror of settings/store.py.

  Hot consumers call `effective/1` per read so a change applies without
  restart. Overrides live in an ETS table owned by this GenServer; the python
  "process-local cache, single worker" caveat disappears — one BEAM node, one
  table, refreshed via `reload/0` (called at boot and after writes; a
  periodic refresh keeps a python-side edit from staying invisible during
  the transition phase).

  Secret values are fernet-encrypted in the DB (`is_secret`); one bad row
  never breaks the load (python parity).
  """

  use GenServer

  require Logger

  alias Orbit.Settings.Registry

  @table __MODULE__
  @refresh_ms 60_000

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc """
  Effective value of an editable key: coerced DB override if present, else
  the coerced `DASH_*` env default. Unknown keys raise — the whitelist is
  the contract.
  """
  @spec effective(String.t()) :: integer() | boolean() | String.t()
  def effective(key) do
    {:ok, defn} = Registry.fetch(key)

    with [{^key, raw}] <- :ets.lookup(@table, key),
         {:ok, value} <- Registry.coerce(defn, raw) do
      value
    else
      _ -> env_default(defn)
    end
  end

  @doc "Reload all overrides from the DB (boot, after writes, periodic)."
  @spec reload() :: :ok
  def reload, do: GenServer.call(__MODULE__, :reload)

  @impl true
  def init(_opts) do
    :ets.new(@table, [:named_table, :set, :protected, read_concurrency: true])
    # Boot-time load happens async: the repo pool may still be warming up and
    # settings reads must fall back to env defaults, never crash the tree.
    {:ok, %{}, {:continue, :load}}
  end

  @impl true
  def handle_continue(:load, state) do
    load_overrides()
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, state}
  end

  @impl true
  def handle_call(:reload, _from, state) do
    load_overrides()
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:refresh, state) do
    load_overrides()
    Process.send_after(self(), :refresh, @refresh_ms)
    {:noreply, state}
  end

  defp load_overrides do
    rows =
      Orbit.Repo.query!("SELECT `key`, `value`, `is_secret` FROM app_settings", []).rows

    fresh =
      for [key, value, is_secret] <- rows,
          Map.has_key?(Registry.editable(), key),
          raw = decode_row(key, value, is_secret),
          is_binary(raw),
          do: {key, raw}

    :ets.delete_all_objects(@table)
    :ets.insert(@table, fresh)
  rescue
    # DB not up yet / transient failure: keep serving previous cache + env
    # defaults; next refresh retries.
    e -> Logger.warning("settings.load_failed #{Exception.message(e)}")
  end

  defp decode_row(key, value, is_secret) do
    if is_secret in [1, true] do
      case Orbit.Crypto.decrypt(value) do
        {:ok, plain} ->
          plain

        {:error, _} ->
          Logger.warning("settings.decode_failed key=#{key}")
          nil
      end
    else
      value
    end
  end

  defp env_default(defn) do
    raw = System.get_env(defn.env, defn.default)

    case Registry.coerce(defn, raw) do
      {:ok, value} ->
        value

      {:error, _} ->
        # Env var holds garbage: fall back to the declared default rather
        # than crash a hot path (poller/checks read through here).
        {:ok, value} = Registry.coerce(defn, defn.default)
        value
    end
  end
end
