defmodule Orbit.GeoIP.Lookup do
  @moduledoc """
  Local mmdb country lookups via :locus (DR-G1 — no login IPs leave the
  process). The database file lives on the shared geoip volume and is kept
  fresh by the python stack's weekly updater until the cutover; :locus
  detects filesystem changes and hot-reloads on its own.

  Fail semantics (DR-G5): a missing/unloadable mmdb makes `db_available?/0`
  false — the gate then fails OPEN (a bad DB update must not lock the whole
  company out; the kill switch stays the second rescue anchor).
  """

  require Logger

  @db_id :orbit_geoip

  @doc "Start the async loader (idempotent; safe to call without a db file)."
  def start do
    path = Application.get_env(:orbit, :geoip_db_path, "")

    if path != "" do
      case :locus.start_loader(@db_id, path) do
        :ok -> :ok
        {:error, {:already_started, _}} -> :ok
        {:error, reason} -> Logger.error("geoip.loader_start_failed reason=#{inspect(reason)}")
      end
    end

    :ok
  end

  @doc "True once a database generation is loaded and servable."
  def db_available? do
    match?({:ok, _}, :locus.get_info(@db_id, :metadata))
  catch
    # get_info raises on an unknown database id (loader never started).
    _, _ -> false
  end

  @doc "ISO-3166-1 alpha-2 country code for an IP, or nil."
  def country_for(ip) when is_binary(ip) do
    case :locus.lookup(@db_id, ip) do
      {:ok, entry} -> get_in(entry, ["country", "iso_code"])
      _ -> nil
    end
  catch
    _, _ -> nil
  end
end
