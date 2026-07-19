defmodule OrbitWeb.Geo do
  @moduledoc """
  Presentation helpers for GeoIP display (city + country). Display-only — the
  access gate decides on country in Orbit.GeoIP; these helpers never influence
  a verdict, they just render "City, DE" wherever an IP is shown.

  City is present only on the GeoLite2-City edition; on the Country edition (or
  a missing DB) the label degrades gracefully to the country, or nil.
  """

  alias Orbit.GeoIP.Lookup

  @doc ~S"""
  "City, DE" | "DE" | nil for an IP string. nil when nothing is known (unknown
  IP, private range, or the DB isn't loaded) so callers can render a dash.
  """
  @spec label(String.t() | nil) :: String.t() | nil
  def label(ip) when is_binary(ip), do: format(Lookup.geo(ip))
  def label(_), do: nil

  @doc "Same as label/1 but for the current request's viewer (proxy-aware IP)."
  @spec viewer_label(Plug.Conn.t()) :: String.t() | nil
  def viewer_label(%Plug.Conn{} = conn), do: label(Orbit.Net.client_ip(conn))

  @doc "Label from an already-resolved `%{country:, city:}` map (no extra lookup)."
  @spec format(%{optional(:country) => String.t() | nil, optional(:city) => String.t() | nil}) ::
          String.t() | nil
  def format(%{city: city, country: country}) when is_binary(city) and is_binary(country),
    do: "#{city}, #{country}"

  def format(%{country: country}) when is_binary(country), do: country
  def format(_), do: nil
end
