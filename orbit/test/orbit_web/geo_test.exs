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

  describe "ip_geo/1 — the shared address cell" do
    import Phoenix.LiveViewTest, only: [rendered_to_string: 1]

    defp render(assigns) do
      %{ip: nil, geo: nil, class: ""}
      |> Map.merge(assigns)
      |> Geo.ip_geo()
      |> rendered_to_string()
    end

    test "a pre-resolved location renders beside the address" do
      # The audit Actions table grew this inline; the Timeline and the
      # online-sessions tile — where an unfamiliar address actually matters —
      # showed a bare number. One component so they cannot drift again.
      html = render(%{ip: "203.0.113.5", geo: "Kaiserslautern, DE"})

      assert html =~ "203.0.113.5"
      assert html =~ "Kaiserslautern, DE"
    end

    test "no location renders the address alone, not a placeholder" do
      # Every address in a private deployment is RFC1918; a dash or an
      # "unknown" there would read as a broken lookup on every row.
      html = render(%{ip: "10.20.1.198"})

      assert html =~ "10.20.1.198"
      refute html =~ "unknown"
    end

    test "a missing address is a dash" do
      assert render(%{}) =~ "—"
    end
  end
end
