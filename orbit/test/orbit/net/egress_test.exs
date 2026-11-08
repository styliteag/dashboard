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

  # More IPv6 spellings that carry an IPv4 address a gateway may translate:
  # SIIT ::ffff:0:a.b.c.d (RFC 6052/7915), the local-use NAT64 prefix
  # 64:ff9b:1::/48 (RFC 8215) and 6to4 2002:AABB:CCDD::/16 (RFC 3056).
  test "SIIT, local-use NAT64 and 6to4 are judged by the embedded IPv4" do
    for a <-
          ~w(::ffff:0:127.0.0.1 ::ffff:0:169.254.169.254 64:ff9b:1::7f00:1
             64:ff9b:1:abcd::169.254.169.254 2002:7f00:1:: 2002:a9fe:a9fe::1),
        do: assert(Egress.blocked_addr?(ip(a)), a)

    for a <- ~w(::ffff:0:10.0.0.1 64:ff9b:1::a00:1 2002:0808:0808::1),
        do: refute(Egress.blocked_addr?(ip(a)), a)
  end

  test "host_block_reason/1 judges a bare host (SMTP relay) by its addresses" do
    assert Egress.host_block_reason("127.0.0.1") =~ "blocked address"
    assert Egress.host_block_reason("169.254.169.254") =~ "blocked address"
    assert Egress.host_block_reason("[::ffff:127.0.0.1]") =~ "blocked address"
    assert Egress.host_block_reason("10.0.0.5") == nil
    assert Egress.host_block_reason("") =~ "host"
    assert Egress.host_block_reason(nil) =~ "host"
  end

  describe "pin/1 (DNS rebinding)" do
    test "a literal address is kept as is, with its host for SNI/Host" do
      assert {:ok, "https://10.0.0.5:8443/hook?x=1", [hostname: "10.0.0.5"]} =
               Egress.pin("https://10.0.0.5:8443/hook?x=1")

      assert {:ok, "http://[fd00::5]/h", [hostname: "fd00::5"]} = Egress.pin("http://[fd00::5]/h")
    end

    test "blocked or malformed targets are refused" do
      assert {:error, "blocked address" <> _} = Egress.pin("http://[::ffff:127.0.0.1]/x")
      assert {:error, "blocked address" <> _} = Egress.pin("http://169.254.169.254/latest")
      assert {:error, "URL must be http(s) with a host"} = Egress.pin("gopher://x")
      assert {:error, _} = Egress.pin(nil)
    end

    test "a name is replaced by the vetted address, the name kept for SNI/Host" do
      resolve = fn "hook.example" -> {:ok, [{10, 1, 2, 3}, {10, 9, 9, 9}]} end

      assert {:ok, "https://10.1.2.3/h", [hostname: "hook.example"]} =
               Egress.pin("https://hook.example/h", resolve)

      assert {:error, "blocked address 127.0.0.1"} =
               Egress.pin("https://hook.example/h", fn _ ->
                 {:ok, [{10, 1, 2, 3}, {127, 0, 0, 1}]}
               end)

      assert {:error, "host does not resolve"} =
               Egress.pin("https://hook.example/h", fn _ -> {:error, :nxdomain} end)
    end

    # Req resolves an address literal with the inet family unless inet6 is
    # on: a pinned IPv6 target would otherwise fail to connect.
    test "pin_req/1 enables inet6 for an IPv6 target only" do
      assert {:ok, opts} = Egress.pin_req(url: "http://[fd00::5]/h")
      assert opts[:inet6] == true
      assert {:ok, opts} = Egress.pin_req(url: "http://10.0.0.5/h")
      refute Keyword.has_key?(opts, :inet6)
    end

    test "pin_req/1 pins the url and merges :hostname into :connect_options" do
      opts = [url: "https://10.0.0.5/h", connect_options: [timeout: 5], retry: false]

      assert {:ok, pinned} = Egress.pin_req(opts)
      assert pinned[:url] == "https://10.0.0.5/h"
      assert pinned[:connect_options] == [timeout: 5, hostname: "10.0.0.5"]
      assert {:error, "blocked address" <> _} = Egress.pin_req(url: "http://127.0.0.1/")

      stubbed = [url: "http://127.0.0.1/", plug: {Req.Test, __MODULE__}]
      assert {:ok, ^stubbed} = Egress.pin_req(stubbed)
    end

    # The mechanism the callers rely on: Req connects to the address in the
    # URL and sends the :hostname option as Host (and SNI for https).
    test "Req connects to the pinned address and sends the original Host" do
      test_pid = self()

      plug = fn conn, _ ->
        send(test_pid, {:host, conn.host})
        Plug.Conn.send_resp(conn, 200, "ok")
      end

      {:ok, server} = Bandit.start_link(plug: plug, port: 0, ip: :loopback, startup_log: false)
      {:ok, {_ip, port}} = ThousandIsland.listener_info(server)

      assert {:ok, %{status: 200}} =
               Req.get("http://127.0.0.1:#{port}/",
                 connect_options: [hostname: "hook.example"],
                 retry: false
               )

      assert_received {:host, "hook.example"}
    end
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
