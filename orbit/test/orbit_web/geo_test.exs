defmodule OrbitWeb.GeoTest do
  @moduledoc "Display-only GeoIP label formatting (city + country, City edition)."
  use ExUnit.Case, async: true

  alias OrbitWeb.Geo

  describe "format/1" do
    test "city + country → \"City, CC\"" do
      assert Geo.format(%{city: "Munich", country: "DE"}) == "Munich, DE"
    end

    test "country only (Country edition or no city) → the country code" do
      assert Geo.format(%{city: nil, country: "DE"}) == "DE"
    end

    test "nothing known → nil (caller renders a dash)" do
      assert Geo.format(%{country: nil, city: nil}) == nil
      assert Geo.format(%{}) == nil
    end
  end

  describe "label/1" do
    test "nil / non-binary → nil" do
      assert Geo.label(nil) == nil
    end

    test "an IP with no mmdb loaded resolves to nil (fail-soft, display-only)" do
      # locus is not started in the test env, so the lookup catches and geo/1
      # returns %{country: nil, city: nil} → the label is nil.
      assert Geo.label("8.8.8.8") == nil
    end
  end
end
