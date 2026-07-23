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

  @doc """
  First sensible ping target inside a traffic selector: the network's first
  host address (`"192.168.0.0/20"` → `"192.168.0.1"`), the address itself
  for a one-host selector (bare IP, /32, /128), or `""` when there is no
  meaningful single guess (`0.0.0.0/0`, `::/0`, unparseable input). Used to
  prefill a ping monitor's Destination with the far side's most likely
  gateway — a guess the operator can overtype, so it must never be wrong in
  the "not even in the selector" sense, only in the "gateway is elsewhere"
  sense.
  """
  def first_host(ts) when is_binary(ts) do
    # Selectors arrive cleaned from the agent/Securepoint paths, but strip
    # strongSwan proto/port tails ("…|/0", "…[tcp/80]") defensively anyway.
    [addr | prefix] =
      ts
      |> String.split(["|", "["], parts: 2)
      |> hd()
      |> String.trim()
      |> String.split("/", parts: 2)

    case :inet.parse_address(String.to_charlist(addr)) do
      {:ok, tuple} -> first_host_in(tuple, prefix)
      _ -> ""
    end
  end

  def first_host(_), do: ""

  # Bare address = a one-host selector: the peer itself.
  defp first_host_in(tuple, []), do: ntoa(tuple)

  defp first_host_in(tuple, [prefix]) do
    bits = if tuple_size(tuple) == 4, do: 32, else: 128

    case Integer.parse(prefix) do
      {^bits, ""} -> ntoa(tuple)
      # /0 means "any" — there is no sensible single guess. Garbage and
      # out-of-range prefixes also land here.
      {p, ""} when p > 0 and p < bits -> tuple |> network_first_host(p, bits) |> ntoa()
      _ -> ""
    end
  end

  # Network base (the selector may arrive off-base) + 1 = first host.
  defp network_first_host(tuple, prefix, bits) do
    host_bits = bits - prefix
    base = tuple |> addr_to_int() |> Bitwise.band(Bitwise.bnot(Bitwise.bsl(1, host_bits) - 1))
    int_to_addr(base + 1, bits)
  end

  defp addr_to_int(tuple) do
    width = if tuple_size(tuple) == 4, do: 8, else: 16
    tuple |> Tuple.to_list() |> Enum.reduce(0, fn part, acc -> Bitwise.bsl(acc, width) + part end)
  end

  defp int_to_addr(n, bits) do
    {width, count} = if bits == 32, do: {8, 4}, else: {16, 8}
    mask = Bitwise.bsl(1, width) - 1

    (count - 1)..0//-1
    |> Enum.map(fn i -> n |> Bitwise.bsr(i * width) |> Bitwise.band(mask) end)
    |> List.to_tuple()
  end

  defp ntoa(tuple), do: tuple |> :inet.ntoa() |> to_string()

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
