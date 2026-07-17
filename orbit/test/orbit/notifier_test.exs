defmodule Orbit.NotifierTest do
  @moduledoc """
  Channel dispatch with injected settings + Req.Test transport (no real
  sends). Routing goes through the REAL Orbit.Selection cache default
  (empty = everything unsubscribed), so the not-subscribed skip is the
  genuine base-default-off path. async: false — Req.Test stub table.
  """

  use ExUnit.Case, async: false

  alias Orbit.Notifier

  defp settings(map), do: fn key -> Map.get(map, key, "") end

  @both %{
    "notify_mattermost_url" => "https://mm.example.com/hooks/abc",
    "notify_telegram_token" => "tok123",
    "notify_telegram_chat_id" => "42"
  }

  test "test send reaches every configured channel, bypassing routing" do
    Req.Test.stub(__MODULE__, fn conn -> Req.Test.json(conn, %{"ok" => true}) end)

    results =
      Notifier.send_test(
        settings: settings(@both),
        req_plug: {Req.Test, __MODULE__},
        ssrf_check: fn _url -> nil end
      )

    assert %{"mattermost" => "sent", "telegram" => "sent", "email" => "skipped"} =
             Map.new(results, &{&1.channel, &1.status})
  end

  test "unconfigured channels skip; http >=400 is a failure, not sent" do
    Req.Test.stub(__MODULE__, fn conn -> Plug.Conn.send_resp(conn, 500, "boom") end)

    results =
      Notifier.send_test(
        settings: settings(%{"notify_mattermost_url" => "https://mm.example.com/h"}),
        req_plug: {Req.Test, __MODULE__},
        ssrf_check: fn _url -> nil end
      )

    assert %{"mattermost" => "failed", "telegram" => "skipped"} =
             Map.new(results, &{&1.channel, &1.status})
  end

  test "real alerts respect routing: base default off skips without a send" do
    # No selection rules loaded → every channel reports not subscribed and
    # the Req stub is never consulted.
    Req.Test.stub(__MODULE__, fn _conn -> flunk("a send happened despite routing off") end)

    results =
      Notifier.dispatch("t", "m", "gateway:WAN", 1,
        settings: settings(@both),
        req_plug: {Req.Test, __MODULE__},
        respect_routes: true
      )

    assert Enum.all?(results, &(&1.status == "skipped"))
    assert Enum.all?(results, &(&1.detail in ["not subscribed", "muted"]))
  end

  test "ssrf guard blocks loopback/link-local/metadata, allows rfc1918" do
    assert Notifier.ssrf_block_reason("https://127.0.0.1/hook") =~ "blocked address"
    assert Notifier.ssrf_block_reason("http://169.254.169.254/latest") =~ "blocked address"
    assert Notifier.ssrf_block_reason("ftp://example.com/x") =~ "http(s)"
    assert Notifier.ssrf_block_reason("https://10.0.0.5/hook") == nil
    assert Notifier.ssrf_block_reason("https://192.168.1.10/hook") == nil
  end

  test "a blocked webhook url fails the channel without an http attempt" do
    Req.Test.stub(__MODULE__, fn _conn -> flunk("request left the ssrf guard") end)

    results =
      Notifier.send_test(
        settings: settings(%{"notify_mattermost_url" => "http://127.0.0.1/hook"}),
        req_plug: {Req.Test, __MODULE__}
      )

    assert %{channel: "mattermost", status: "failed", detail: "blocked address 127.0.0.1"} =
             Enum.find(results, &(&1.channel == "mattermost"))
  end
end
