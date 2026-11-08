defmodule Orbit.GeoIP.LookupTest do
  # touches global application env and the :locus loader registry
  use ExUnit.Case, async: false

  alias Orbit.GeoIP.Lookup

  setup do
    prev_disable = Application.get_env(:orbit, :geoip_disable)
    prev_path = Application.get_env(:orbit, :geoip_db_path)
    Application.put_env(:orbit, :geoip_db_path, "/nonexistent/GeoLite2-Country.mmdb")

    on_exit(fn ->
      _ = :locus.stop_loader(:orbit_geoip)
      restore(:geoip_disable, prev_disable)
      restore(:geoip_db_path, prev_path)
    end)
  end

  defp restore(key, nil), do: Application.delete_env(:orbit, key)
  defp restore(key, value), do: Application.put_env(:orbit, key, value)

  test "the kill switch keeps the loader from starting (no retry noise)" do
    Application.put_env(:orbit, :geoip_disable, true)

    assert Lookup.start() == :ok
    assert {:error, :database_unknown} = :locus.get_info(:orbit_geoip, :metadata)
  end

  test "without the kill switch the loader starts" do
    Application.put_env(:orbit, :geoip_disable, false)

    assert Lookup.start() == :ok
    refute match?({:error, :database_unknown}, :locus.get_info(:orbit_geoip, :metadata))
  end
end
