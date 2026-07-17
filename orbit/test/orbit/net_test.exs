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
end
