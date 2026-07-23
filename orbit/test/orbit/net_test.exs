defmodule Orbit.NetTest do
  @moduledoc "XFF/peer resolution parity with app/net.py pick_client_ip."

  # async: false — mutates the :trusted_proxy_hops application env.
  use ExUnit.Case, async: false

  alias Orbit.Net

  setup do
    previous = Application.get_env(:orbit, :trusted_proxy_hops, 0)
    on_exit(fn -> Application.put_env(:orbit, :trusted_proxy_hops, previous) end)
    :ok
  end

  test "0 hops ignores XFF entirely (header is client-controlled)" do
    Application.put_env(:orbit, :trusted_proxy_hops, 0)
    assert Net.pick_client_ip("6.6.6.6", "192.0.2.1") == "192.0.2.1"
  end

  test "1 hop takes the last XFF entry; client prepends are ignored" do
    Application.put_env(:orbit, :trusted_proxy_hops, 1)
    assert Net.pick_client_ip("spoofed, 203.0.113.7", "192.0.2.1") == "203.0.113.7"
  end

  test "2 hops takes the second-from-right entry" do
    Application.put_env(:orbit, :trusted_proxy_hops, 2)
    assert Net.pick_client_ip("a, 203.0.113.7, 10.0.0.2", "192.0.2.1") == "203.0.113.7"
  end

  test "fewer entries than hops falls back to the peer" do
    Application.put_env(:orbit, :trusted_proxy_hops, 2)
    assert Net.pick_client_ip("203.0.113.7", "192.0.2.1") == "192.0.2.1"
    assert Net.pick_client_ip(nil, "192.0.2.1") == "192.0.2.1"
    assert Net.pick_client_ip(nil, nil) == "unknown"
  end

  # client_ip/1 reads the XFF header off a real conn — the seam the login and
  # enroll rate limiters depend on. Regression: those controllers used to key
  # the LoginLimiter on conn.remote_ip (the nginx container IP in prod, shared
  # by every external client → one bad-code burst locks the whole fleet out).
  # They must resolve through this proxy-aware helper instead.
  describe "client_ip/1 (conn-level)" do
    defp conn_with(xff, peer) do
      conn = %Plug.Conn{remote_ip: peer}
      if xff, do: Plug.Conn.put_req_header(conn, "x-forwarded-for", xff), else: conn
    end

    test "1 hop returns the proxy-appended client, never the peer" do
      Application.put_env(:orbit, :trusted_proxy_hops, 1)
      # nginx appends the real peer as the last XFF entry; the direct TCP peer
      # is the proxy container. The limiter must key on 203.0.113.50.
      assert Net.client_ip(conn_with("client-forged, 203.0.113.50", {10, 0, 0, 9})) ==
               "203.0.113.50"
    end

    test "0 hops falls back to the direct peer (no proxy trusted)" do
      Application.put_env(:orbit, :trusted_proxy_hops, 0)
      assert Net.client_ip(conn_with("6.6.6.6", {192, 0, 2, 1})) == "192.0.2.1"
    end
  end

  # Ping-monitor Destination prefill: the far side's first host address.
  describe "first_host/1" do
    test "network selector yields the first host" do
      assert Net.first_host("192.168.0.0/20") == "192.168.0.1"
      assert Net.first_host("10.3.3.0/24") == "10.3.3.1"
    end

    test "off-base selector is normalized to the network first" do
      assert Net.first_host("10.3.3.7/24") == "10.3.3.1"
    end

    test "one-host selectors return the host itself" do
      assert Net.first_host("10.9.9.9/32") == "10.9.9.9"
      assert Net.first_host("10.1.2.3") == "10.1.2.3"
    end

    test "/31 point-to-point yields the upper of the two hosts" do
      assert Net.first_host("10.0.0.0/31") == "10.0.0.1"
    end

    test "any-selectors and garbage yield no guess" do
      assert Net.first_host("0.0.0.0/0") == ""
      assert Net.first_host("::/0") == ""
      assert Net.first_host("") == ""
      assert Net.first_host(nil) == ""
      assert Net.first_host("foo/24") == ""
      assert Net.first_host("10.0.0.0/33") == ""
    end

    test "strongSwan proto/port tails are stripped (pfSense pipe, classic bracket)" do
      assert Net.first_host("10.3.3.0/24|/0") == "10.3.3.1"
      assert Net.first_host("10.3.3.0/24[tcp/80]") == "10.3.3.1"
    end

    test "IPv6 selectors work the same way" do
      assert Net.first_host("fd00:1::/64") == "fd00:1::1"
      assert Net.first_host("fd00:1::5/128") == "fd00:1::5"
    end
  end
end
