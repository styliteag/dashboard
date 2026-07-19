defmodule Orbit.GeoIP.Updater do
  @moduledoc """
  Weekly GeoLite2-City download (DR-G1). The gate decides on country, but the
  City edition carries both country AND city, so the UI can surface the city
  of a viewer / external IP (the gate logic is unchanged — city is display
  only). The DASH_GEOIP_DB_PATH filename (…Country.mmdb) is historic; the
  City .mmdb is installed in place under it.

  Pulls the official tarball from download.maxmind.com (HTTP basic auth:
  account id + license key), extracts the single `.mmdb` member in memory
  and replaces the active database atomically (tmp file + rename in the
  same directory) — a crashed download can never leave a torn file; the
  lookup reader picks the new mtime up on its next call. Without
  credentials the job is a no-op (manual volume updates keep working).
  """

  require Logger

  @download_url "https://download.maxmind.com/geoip/databases/GeoLite2-City/download"
  # GeoLite2-City is ~35 MB; 100 MB = clearly broken.
  @max_tarball 100 * 1024 * 1024

  @last_key {__MODULE__, :last}

  @doc "Outcome of the most recent run (for the GeoIP config surface)."
  def last_download do
    :persistent_term.get(@last_key, %{at: nil, ok: nil, detail: "never ran"})
  end

  @doc "Download + atomically install the current GeoLite2-City mmdb."
  def refresh do
    account = Application.get_env(:orbit, :maxmind_account_id, "")
    key = Application.get_env(:orbit, :maxmind_license_key, "")

    if account == "" or key == "" do
      finish(nil, "no maxmind credentials configured — job idle")
    else
      with {:ok, tarball} <- download(account, key),
           {:ok, mmdb} <- extract_mmdb(tarball),
           :ok <- install(mmdb, Application.get_env(:orbit, :geoip_db_path, "")) do
        finish(true, "installed #{byte_size(mmdb)} bytes")
      else
        {:error, detail} -> finish(false, detail)
      end
    end
  end

  defp download(account, key) do
    opts =
      [
        url: @download_url,
        params: [suffix: "tar.gz"],
        auth: {:basic, "#{account}:#{key}"},
        receive_timeout: 120_000,
        retry: false
      ] ++ req_test_opts()

    case Req.request(opts) do
      {:ok, %{status: 200, body: body}} when is_binary(body) ->
        if byte_size(body) > @max_tarball,
          do: {:error, "tarball too large: #{byte_size(body)} bytes"},
          else: {:ok, body}

      {:ok, %{status: status}} ->
        {:error, "download failed: HTTP #{status}"}

      {:error, err} ->
        {:error, "download failed: #{Exception.message(err)}"}
    end
  end

  @doc """
  The one `*.mmdb` member of the tarball, extracted in memory (archive
  paths never touch the disk, so member-name traversal is irrelevant).
  """
  def extract_mmdb(tarball) do
    case :erl_tar.extract({:binary, tarball}, [:memory, :compressed]) do
      {:ok, members} ->
        members
        |> Enum.find(fn {name, _bin} -> String.ends_with?(to_string(name), ".mmdb") end)
        |> case do
          {_name, bin} -> {:ok, bin}
          nil -> {:error, "no .mmdb member in tarball"}
        end

      {:error, reason} ->
        {:error, "tar extract failed: #{inspect(reason)}"}
    end
  end

  @doc "Atomic install: tmp file in the target directory, then rename."
  def install(_mmdb, ""), do: {:error, "geoip_db_path not configured"}

  def install(mmdb, path) do
    dir = Path.dirname(path)
    tmp = Path.join(dir, ".geoip-#{System.unique_integer([:positive])}")

    with :ok <- File.mkdir_p(dir),
         :ok <- File.write(tmp, mmdb),
         :ok <- File.rename(tmp, path) do
      :ok
    else
      {:error, posix} ->
        File.rm(tmp)
        {:error, "install failed: #{posix}"}
    end
  end

  defp finish(ok, detail) do
    outcome = %{at: DateTime.utc_now(), ok: ok, detail: detail}
    :persistent_term.put(@last_key, outcome)

    if ok == false,
      do: Logger.error("geoip.db_refresh_failed detail=#{detail}"),
      else: Logger.info("geoip.db_refresh detail=#{detail}")

    outcome
  end

  # Static plug name from config/test.exs; per-process Req.Test stubs only
  # (the opnsense put_env race, never again). nil in dev/prod → real HTTP.
  defp req_test_opts do
    case Application.get_env(:orbit, :geoip_req_plug) do
      nil -> []
      plug -> [plug: plug]
    end
  end
end
