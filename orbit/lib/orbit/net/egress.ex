defmodule Orbit.Net.Egress do
  @moduledoc """
  Address policy for outbound requests to operator-supplied URLs (notifier
  webhooks, the LLM base URL).

  Blocked: loopback, link-local (incl. cloud metadata 169.254/16),
  unspecified, multicast and reserved (224/3), and the IPv6 forms that embed
  an IPv4 address — IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible `::a.b.c.d`
  and NAT64 `64:ff9b::a.b.c.d` — judged by the embedded address. RFC 1918 and
  ULA stay allowed on purpose: that is where firewalls and self-hosted
  services live.

  `ssrf_block_reason/1` resolves DNS names and checks every address. That is
  a check at request time, not a pin: a name that changes between the check
  and the connect (DNS rebinding) is not caught. Callers also disable
  redirects so a vetted host cannot bounce the request elsewhere.
  """

  import Bitwise

  @doc "True for an address tuple outbound calls must never reach."
  @spec blocked_addr?(:inet.ip_address()) :: boolean()
  def blocked_addr?({127, _, _, _}), do: true
  def blocked_addr?({169, 254, _, _}), do: true
  def blocked_addr?({0, _, _, _}), do: true
  def blocked_addr?({n, _, _, _}) when n >= 224, do: true
  def blocked_addr?({_, _, _, _}), do: false

  # ::ffff:a.b.c.d (mapped) and ::a.b.c.d (compatible, deprecated) — the
  # latter also covers :: and ::1 (embedded 0.0.0.0 / 0.0.0.1).
  def blocked_addr?({0, 0, 0, 0, 0, w, hi, lo}) when w in [0, 0xFFFF], do: embedded(hi, lo)
  # NAT64 well-known prefix 64:ff9b::/96.
  def blocked_addr?({0x64, 0xFF9B, 0, 0, 0, 0, hi, lo}), do: embedded(hi, lo)
  def blocked_addr?({w, _, _, _, _, _, _, _}) when band(w, 0xFFC0) == 0xFE80, do: true
  def blocked_addr?({w, _, _, _, _, _, _, _}) when w >= 0xFF00, do: true
  def blocked_addr?({_, _, _, _, _, _, _, _}), do: false
  def blocked_addr?(_), do: true

  defp embedded(hi, lo), do: blocked_addr?({hi >>> 8, hi &&& 0xFF, lo >>> 8, lo &&& 0xFF})

  @doc """
  Reject a URL whose scheme is not http(s) or whose host is, or resolves to,
  a blocked address. Returns a reason string or nil.
  """
  @spec ssrf_block_reason(String.t()) :: String.t() | nil
  def ssrf_block_reason(url) when is_binary(url) do
    uri = URI.parse(url)

    cond do
      uri.scheme not in ["http", "https"] or uri.host in [nil, ""] ->
        "URL must be http(s) with a host"

      true ->
        case resolve_addrs(uri.host) do
          {:error, _} -> "host does not resolve"
          {:ok, addrs} -> Enum.find_value(addrs, &blocked_reason/1)
        end
    end
  end

  def ssrf_block_reason(_), do: "URL must be http(s) with a host"

  defp blocked_reason(addr) do
    if blocked_addr?(addr), do: "blocked address #{addr |> :inet.ntoa() |> to_string()}"
  end

  defp resolve_addrs(host) do
    chars = host |> String.trim_leading("[") |> String.trim_trailing("]") |> String.to_charlist()

    case :inet.parse_strict_address(chars) do
      {:ok, addr} ->
        {:ok, [addr]}

      {:error, _} ->
        v4 = :inet_res.lookup(chars, :in, :a, timeout: 5_000)
        v6 = :inet_res.lookup(chars, :in, :aaaa, timeout: 5_000)
        if v4 == [] and v6 == [], do: {:error, :nxdomain}, else: {:ok, v4 ++ v6}
    end
  end
end
