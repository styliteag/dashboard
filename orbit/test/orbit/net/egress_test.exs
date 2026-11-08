defmodule Orbit.Net.EgressTest do
  @moduledoc """
  One address policy for every outbound call the dashboard makes on an
  operator-supplied URL (webhooks, LLM base URL): loopback,
  link-local (cloud metadata), unspecified, multicast/reserved — including
  the IPv6 spellings that embed an IPv4 address (::ffff:127.0.0.1,
  ::127.0.0.1, 64:ff9b::127.0.0.1). RFC 1918 / ULA stay allowed: that is
  where firewalls live.
  """
  use ExUnit.Case, async: true

  alias Orbit.Net.Egress

  defp ip(s), do: s |> String.to_charlist() |> :inet.parse_address() |> elem(1)

  test "blocked literal addresses" do
    for a <-
          ~w(127.0.0.1 127.9.9.9 169.254.169.254 0.0.0.0 224.0.0.1 255.255.255.255
             ::1 :: fe80::1 ff02::1 ::ffff:127.0.0.1 ::ffff:169.254.169.254
             ::127.0.0.1 ::ffff:7f00:1 64:ff9b::7f00:1 64:ff9b::169.254.169.254),
        do: assert(Egress.blocked_addr?(ip(a)), a)
  end

  test "private and public addresses pass" do
    for a <- ~w(10.0.0.1 192.168.1.1 172.16.0.1 8.8.8.8 fd00::1 2001:db8::1 ::ffff:10.0.0.1),
        do: refute(Egress.blocked_addr?(ip(a)), a)
  end

  test "ssrf_block_reason/1 judges literal hosts without DNS" do
    assert Egress.ssrf_block_reason("http://[::ffff:127.0.0.1]/x") =~ "blocked address"
    assert Egress.ssrf_block_reason("http://[::127.0.0.1]/x") =~ "blocked address"
    assert Egress.ssrf_block_reason("https://10.0.0.5/hook") == nil
    assert Egress.ssrf_block_reason("gopher://x") =~ "http(s)"
  end

  test "the notifier guard is the same policy" do
    assert Orbit.Notifier.ssrf_block_reason("http://[::ffff:127.0.0.1]/x") =~ "blocked address"
  end
end
