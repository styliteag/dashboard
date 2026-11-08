defmodule Orbit.GzipTest do
  @moduledoc """
  Bounded gunzip: inflation stops as soon as the output passes the cap, so a
  gzip bomb (a few KB expanding to GB) never materialises in memory. Used
  for agent config backups, the Checkmk blob and the GeoIP tarball.
  """
  use ExUnit.Case, async: true

  alias Orbit.Gzip

  test "round-trips within the cap" do
    assert {:ok, "hello"} = Gzip.gunzip_bounded(:zlib.gzip("hello"), 10)
  end

  test "output above the cap is refused" do
    bomb = :zlib.gzip(:binary.copy(<<0>>, 5_000_000))
    assert byte_size(bomb) < 10_000
    assert {:error, :too_large} = Gzip.gunzip_bounded(bomb, 1_000_000)
  end

  test "garbage is an error, not a crash" do
    assert {:error, :bad_gzip} = Gzip.gunzip_bounded("not gzip", 100)

    assert {:error, :bad_gzip} =
             Gzip.gunzip_bounded(binary_part(:zlib.gzip("hello world"), 0, 8), 100)
  end
end
