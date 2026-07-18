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

  test "email sends via the injected smtp when host/from/to are set" do
    test_pid = self()

    email_cfg = %{
      "notify_email_smtp_host" => "smtp.example.com",
      "notify_email_from" => "orbit@example.com",
      "notify_email_to" => "ops@example.com, oncall@example.com"
    }

    results =
      Notifier.send_test(
        settings: settings(email_cfg),
        smtp: fn cfg, mail ->
          send(test_pid, {:smtp, cfg, mail})
          :ok
        end
      )

    assert %{channel: "email", status: "sent"} = Enum.find(results, &(&1.channel == "email"))
    assert_received {:smtp, cfg, mail}
    assert cfg.recipients == ["ops@example.com", "oncall@example.com"]
    assert mail =~ "Subject: ✅ Orbit test notification"
    assert mail =~ "From: orbit@example.com"
  end

  test "email skips when host/from/to incomplete and reports smtp failure" do
    # Missing recipients → skipped, no smtp call.
    r1 =
      Notifier.send_test(
        settings: settings(%{"notify_email_smtp_host" => "h", "notify_email_from" => "f"}),
        smtp: fn _c, _m -> flunk("smtp called without recipients") end
      )

    assert %{channel: "email", status: "skipped"} = Enum.find(r1, &(&1.channel == "email"))

    # Fully configured but the relay errors → failed.
    r2 =
      Notifier.send_test(
        settings:
          settings(%{
            "notify_email_smtp_host" => "h",
            "notify_email_from" => "f@x",
            "notify_email_to" => "t@x"
          }),
        smtp: fn _c, _m -> {:error, :nxdomain} end
      )

    assert %{channel: "email", status: "failed"} = Enum.find(r2, &(&1.channel == "email"))
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
