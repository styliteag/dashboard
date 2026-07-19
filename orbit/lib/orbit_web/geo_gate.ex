defmodule OrbitWeb.GeoGate do
  @moduledoc """
  LiveView-socket arm of the GeoIP gate. The /live websocket upgrade goes
  through the endpoint `socket` macro and BYPASSES the plug pipeline — a
  stolen session cookie from a blocked location could otherwise open a live
  socket directly (the CSRF token is derivable from the cookie). This
  on_mount hook closes that hole with the same `Orbit.GeoIP.evaluate/1`
  verdict the HTTP plug uses.

  Dead renders (HTTP) are already covered by OrbitWeb.Plugs.GeoIP; the hook
  only needs to act on connected sockets. A denied mount halts to /login,
  where the plug answers the definitive 403.
  """

  import Phoenix.LiveView

  alias Orbit.GeoIP.Store

  require Logger

  def on_mount(:default, _params, _session, socket) do
    if connected?(socket) and blocked?(socket) do
      {:halt, redirect(socket, to: "/login")}
    else
      {:cont, socket}
    end
  end

  defp blocked?(socket) do
    ip = socket_ip(socket)

    case Orbit.GeoIP.evaluate(ip) do
      {:deny, reason, country} ->
        Orbit.GeoIP.Denials.record(ip, country, "/live", reason)

        if Store.should_log?(ip) do
          Logger.warning(
            "geoip.denied ip=#{ip} country=#{country || "-"} path=/live reason=#{reason}"
          )
        end

        true

      {:allow, _, _} ->
        false
    end
  end

  defp socket_ip(socket) do
    xff =
      case get_connect_info(socket, :x_headers) do
        headers when is_list(headers) ->
          Enum.find_value(headers, fn {name, value} -> name == "x-forwarded-for" && value end)

        _ ->
          nil
      end

    peer =
      case get_connect_info(socket, :peer_data) do
        %{address: address} -> address |> :inet.ntoa() |> to_string()
        _ -> nil
      end

    Orbit.Net.pick_client_ip(xff, peer)
  end
end
