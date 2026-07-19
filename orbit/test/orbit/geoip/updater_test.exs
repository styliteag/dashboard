defmodule Orbit.GeoIP.UpdaterTest do
  @moduledoc """
  GeoLite2-City refresh: credential no-op, tarball download + in-memory mmdb
  extraction, atomic install, failure shapes. Req.Test plug is the static
  name from config/test.exs — stubs are per-process.
  """
  use ExUnit.Case, async: false

  alias Orbit.GeoIP.Updater

  @moduletag :tmp_dir

  # In-memory tar.gz holding the given members ([{~c"name", binary}]).
  defp tarball(members, tmp_dir) do
    path = Path.join(tmp_dir, "t.tar.gz")

    entries =
      for {name, bin} <- members do
        {String.to_charlist(name), bin}
      end

    :ok = :erl_tar.create(String.to_charlist(path), entries, [:compressed])
    File.read!(path)
  end

  defp put_creds(account, key) do
    Application.put_env(:orbit, :maxmind_account_id, account)
    Application.put_env(:orbit, :maxmind_license_key, key)

    on_exit(fn ->
      Application.delete_env(:orbit, :maxmind_account_id)
      Application.delete_env(:orbit, :maxmind_license_key)
    end)
  end

  test "without credentials the job is an idle no-op" do
    assert %{ok: nil, detail: "no maxmind credentials configured — job idle"} =
             Updater.refresh()
  end

  test "downloads, extracts and atomically installs the mmdb", %{tmp_dir: tmp_dir} do
    put_creds("111", "lic")
    target = Path.join(tmp_dir, "sub/GeoLite2-City.mmdb")
    Application.put_env(:orbit, :geoip_db_path, target)
    on_exit(fn -> Application.delete_env(:orbit, :geoip_db_path) end)

    tar = tarball([{"GeoLite2-City_20260718/GeoLite2-City.mmdb", "MMDBDATA"}], tmp_dir)

    Req.Test.stub(Orbit.GeoIP.Updater, fn conn ->
      conn
      |> Plug.Conn.put_resp_content_type("application/gzip")
      |> Plug.Conn.send_resp(200, tar)
    end)

    assert %{ok: true, detail: "installed 8 bytes"} = Updater.refresh()
    assert File.read!(target) == "MMDBDATA"
    assert %{ok: true} = Updater.last_download()
    # No torn tmp files left behind.
    assert Path.wildcard(Path.join(tmp_dir, "sub/.geoip-*")) == []
  end

  test "http error becomes a failed outcome, target untouched", %{tmp_dir: tmp_dir} do
    put_creds("111", "lic")
    target = Path.join(tmp_dir, "GeoLite2-City.mmdb")
    Application.put_env(:orbit, :geoip_db_path, target)
    on_exit(fn -> Application.delete_env(:orbit, :geoip_db_path) end)

    Req.Test.stub(Orbit.GeoIP.Updater, fn conn ->
      Plug.Conn.send_resp(conn, 403, "forbidden")
    end)

    assert %{ok: false, detail: "download failed: HTTP 403"} = Updater.refresh()
    refute File.exists?(target)
  end

  test "a tarball without an mmdb member fails cleanly", %{tmp_dir: tmp_dir} do
    assert {:error, "no .mmdb member in tarball"} =
             tarball([{"README.txt", "hi"}], tmp_dir) |> Updater.extract_mmdb()
  end

  test "garbage bytes fail extraction, not crash" do
    assert {:error, "tar extract failed: " <> _} = Updater.extract_mmdb("not a tarball")
  end
end
