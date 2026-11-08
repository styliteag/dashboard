defmodule Orbit.NotifierInputTest do
  @moduledoc """
  Outbound notification hardening: webhook redirects are not followed (the
  SSRF guard vetted only the first host), and e-mail header fields refuse
  CR/LF (header injection) — both in the group channel form and at send time
  for the global settings.
  """
  use ExUnit.Case, async: false

  alias Orbit.Groups.Channels
  alias Orbit.Notifier

  defp settings(map), do: fn key -> Map.get(map, key, "") end

  test "a webhook answering 302 is a failure, the redirect is not followed" do
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      send(test_pid, {:hit, conn.host})

      conn
      |> Plug.Conn.put_resp_header("location", "http://127.0.0.1/admin")
      |> Plug.Conn.send_resp(302, "")
    end)

    results =
      Notifier.send_test(
        settings: settings(%{"notify_mattermost_url" => "https://mm.example.com/hooks/x"}),
        req_plug: {Req.Test, __MODULE__},
        ssrf_check: fn _ -> nil end
      )

    assert %{status: "failed", detail: "HTTP 302"} =
             Enum.find(results, &(&1.channel == "mattermost"))

    assert_received {:hit, "mm.example.com"}
    refute_received {:hit, _}
  end

  test "e-mail with CR/LF in from or to is refused before the smtp sender" do
    for {key, val} <- [
          {"notify_email_from", "a@b.example\r\nBcc: victim@x.example"},
          {"notify_email_to", "ops@example.com\nBcc: victim@x.example"}
        ] do
      cfg =
        Map.put(
          %{
            "notify_email_smtp_host" => "smtp.example.com",
            "notify_email_from" => "orbit@example.com",
            "notify_email_to" => "ops@example.com"
          },
          key,
          val
        )

      results = Notifier.send_test(settings: settings(cfg), smtp: fn _, _ -> flunk("sent") end)
      assert %{status: "failed"} = Enum.find(results, &(&1.channel == "email"))
    end
  end

  test "an smtp host that is no host name or IP is refused at send time" do
    cfg = %{
      "notify_email_smtp_host" => "smtp.example.com -oX",
      "notify_email_from" => "orbit@example.com",
      "notify_email_to" => "ops@example.com"
    }

    results = Notifier.send_test(settings: settings(cfg), smtp: fn _, _ -> flunk("sent") end)
    assert %{status: "failed"} = Enum.find(results, &(&1.channel == "email"))
  end

  describe "group channel form" do
    @base %{"smtp_host" => "smtp.example.com", "from" => "a@b.example", "to" => "c@d.example"}

    test "CR/LF in from/to and a bad smtp host are refused" do
      assert {:error, _} = Channels.validate("email", %{@base | "from" => "a@b\r\nBcc: x"}, %{})
      assert {:error, _} = Channels.validate("email", %{@base | "to" => "c@d\nBcc: x"}, %{})
      assert {:error, _} = Channels.validate("email", %{@base | "smtp_host" => "a b"}, %{})
      assert {:ok, _} = Channels.validate("email", @base, %{})
    end
  end
end
