defmodule Orbit.Net do
  @moduledoc """
  Client-IP extraction honouring a configured number of trusted proxies —
  port of app/net.py. X-Forwarded-For is client-controllable, so only the
  rightmost `trusted_proxy_hops` entries (each appended by a reverse proxy
  we operate) are trusted; anything the client prepended is ignored.
  """

  @doc "Best-effort client IP for the geo gate, rate limiting and audit."
  def client_ip(%Plug.Conn{} = conn) do
    xff = conn |> Plug.Conn.get_req_header("x-forwarded-for") |> List.first()
    pick_client_ip(xff, conn.remote_ip |> :inet.ntoa() |> to_string())
  end

  @doc "Shared XFF/peer resolution: xff[-hops] when enough entries, else peer."
  def pick_client_ip(xff, peer) do
    hops = Application.get_env(:orbit, :trusted_proxy_hops, 0)

    with true <- hops > 0,
         parts when parts != [] <- split_xff(xff),
         true <- length(parts) >= hops do
      Enum.at(parts, -hops)
    else
      _ -> peer || "unknown"
    end
  end

  defp split_xff(nil), do: []

  defp split_xff(xff) do
    xff |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end
end
