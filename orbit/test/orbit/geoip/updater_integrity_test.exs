defmodule Orbit.GeoIP.UpdaterIntegrityTest do
  @moduledoc """
  The GeoLite2 tarball is checked against MaxMind's published sha256
  (`suffix=tar.gz.sha256`, same endpoint) before anything is installed, and
  extraction inflates with a cap — a mismatching, missing or bomb-sized
  download leaves the installed database untouched.
  """
  use ExUnit.Case, async: false

  alias Orbit.GeoIP.Updater

  @moduletag :tmp_dir

  defp tarball(members, tmp_dir) do
    path = Path.join(tmp_dir, "t.tar.gz")
    entries = for {name, bin} <- members, do: {String.to_charlist(name), bin}
    :ok = :erl_tar.create(String.to_charlist(path), entries, [:compressed])
    File.read!(path)
  end

  setup %{tmp_dir: tmp_dir} do
    Application.put_env(:orbit, :maxmind_account_id, "111")
    Application.put_env(:orbit, :maxmind_license_key, "lic")
    target = Path.join(tmp_dir, "GeoLite2-City.mmdb")
    Application.put_env(:orbit, :geoip_db_path, target)

    on_exit(fn ->
      for k <- [:maxmind_account_id, :maxmind_license_key, :geoip_db_path],
          do: Application.delete_env(:orbit, k)
    end)

    {:ok, target: target}
  end

  defp stub(tar, sha_body) do
    Req.Test.stub(Orbit.GeoIP.Updater, fn conn ->
      conn = Plug.Conn.fetch_query_params(conn)

      if conn.query_params["suffix"] == "tar.gz.sha256",
        do: Plug.Conn.send_resp(conn, 200, sha_body),
        else: Plug.Conn.send_resp(conn, 200, tar)
    end)
  end

  defp sha(bin), do: :crypto.hash(:sha256, bin) |> Base.encode16(case: :lower)

  test "matching sha256 installs", %{tmp_dir: tmp_dir, target: target} do
    tar = tarball([{"GeoLite2-City_1/GeoLite2-City.mmdb", "MMDB"}], tmp_dir)
    stub(tar, "#{sha(tar)}  GeoLite2-City_1.tar.gz\n")
    assert %{ok: true} = Updater.refresh()
    assert File.read!(target) == "MMDB"
  end

  test "a sha256 mismatch installs nothing", %{tmp_dir: tmp_dir, target: target} do
    tar = tarball([{"GeoLite2-City_1/GeoLite2-City.mmdb", "MMDB"}], tmp_dir)
    stub(tar, "#{String.duplicate("0", 64)}  GeoLite2-City_1.tar.gz\n")
    assert %{ok: false, detail: detail} = Updater.refresh()
    assert detail =~ "sha256"
    refute File.exists?(target)
  end

  test "an unparseable checksum installs nothing", %{tmp_dir: tmp_dir, target: target} do
    tar = tarball([{"GeoLite2-City_1/GeoLite2-City.mmdb", "MMDB"}], tmp_dir)
    stub(tar, "<html>maintenance</html>")
    assert %{ok: false} = Updater.refresh()
    refute File.exists?(target)
  end

  test "extraction caps the inflated size" do
    bomb = :zlib.gzip(:binary.copy(<<0>>, 2_000_000))
    assert {:error, "tar extract failed: " <> _} = Updater.extract_mmdb(bomb, 1_000_000)
  end
end
