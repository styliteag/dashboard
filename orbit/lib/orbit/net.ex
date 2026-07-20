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

  @doc """
  Is this a globally routable address? Used to tell a box's own public
  address from a private/CGNAT/link-local one when deciding whether it sits
  behind NAT (`Orbit.ExternalIp`).

  Deliberately conservative: anything unparseable is NOT public, so an
  unknown value never produces a "this box is directly reachable" claim.
  """
  def public_ip?(addr) when is_binary(addr) do
    addr
    |> bare_address()
    |> String.to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, tuple} -> public_tuple?(tuple)
      _ -> false
    end
  end

  def public_ip?(_), do: false

  @doc """
  Strip what devices append to an address before comparing or parsing it:
  a CIDR prefix (Securepoint reports `213.232.100.192/32`) and an IPv6 zone
  (`fe80::1%vtnet0`). Without this a perfectly public WAN address parses as
  nothing and the box looks like it has no public IP at all.
  """
  def bare_address(addr) when is_binary(addr) do
    addr
    |> String.split("/", parts: 2)
    |> hd()
    |> String.split("%", parts: 2)
    |> hd()
    |> String.trim()
  end

  def bare_address(_), do: ""

  @doc """
  Is this actually an IP address? Devices mix MACs into the same field
  (OPNsense reports a `<Link#n>` row whose "address" is the MAC), and a
  MAC is colon-separated just like IPv6 — so decide by parsing, never by
  looking for separators.
  """
  def ip_address?(addr) when is_binary(addr) do
    case addr |> bare_address() |> String.to_charlist() |> :inet.parse_address() do
      {:ok, _} -> true
      _ -> false
    end
  end

  def ip_address?(_), do: false

  # RFC1918 private, 127/8 loopback, 169.254/16 link-local, 100.64/10 CGNAT,
  # 0/8 and 224/4+ (multicast/reserved) are all non-public.
  defp public_tuple?({10, _, _, _}), do: false
  defp public_tuple?({127, _, _, _}), do: false
  defp public_tuple?({0, _, _, _}), do: false
  defp public_tuple?({169, 254, _, _}), do: false
  defp public_tuple?({172, b, _, _}) when b >= 16 and b <= 31, do: false
  defp public_tuple?({192, 168, _, _}), do: false
  defp public_tuple?({100, b, _, _}) when b >= 64 and b <= 127, do: false
  defp public_tuple?({a, _, _, _}) when a >= 224, do: false
  defp public_tuple?({a, _, _, _}) when a >= 1 and a <= 223, do: true

  # IPv6: ::1 loopback, fe80::/10 link-local, fc00::/7 unique-local,
  # ff00::/8 multicast, :: unspecified.
  defp public_tuple?({0, 0, 0, 0, 0, 0, 0, 1}), do: false
  defp public_tuple?({0, 0, 0, 0, 0, 0, 0, 0}), do: false
  defp public_tuple?({a, _, _, _, _, _, _, _}) when a >= 0xFE80 and a <= 0xFEBF, do: false
  defp public_tuple?({a, _, _, _, _, _, _, _}) when a >= 0xFC00 and a <= 0xFDFF, do: false
  defp public_tuple?({a, _, _, _, _, _, _, _}) when a >= 0xFF00, do: false
  defp public_tuple?({_, _, _, _, _, _, _, _}), do: true
  defp public_tuple?(_), do: false
end
