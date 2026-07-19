defmodule Orbit.Securepoint.ClientTest do
  @moduledoc """
  spcgi client core against a mocked appliance (Req.Test plug — no real
  box). Login envelope + sessionid, command unwrap, error codes, the
  secret-leak forbidden-command guard, and the session echoed in the
  request payload.
  """
  use ExUnit.Case, async: true

  alias Orbit.Securepoint.Client, as: C

  defp client,
    do: %C{base_url: "https://utm:11115", user: "admin", password: "pw", ssl_verify: false}

  defp with_stub(fun) do
    Req.Test.stub(__MODULE__, fun)
    %{client() | req_plug: {Req.Test, __MODULE__}}
  end

  test "login stores the sessionid from the top-level envelope" do
    c =
      with_stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)
        assert decoded["command"] == ["login"]
        assert decoded["arguments"]["user"] == "admin"
        Req.Test.json(conn, %{"sessionid" => "sid-123", "result" => %{"code" => 0}})
      end)

    assert {:ok, %C{sessionid: "sid-123"}} = C.login(c)
  end

  test "login failure (code >= 400) is an error" do
    c =
      with_stub(fn conn ->
        Req.Test.json(conn, %{"result" => %{"code" => 403, "message" => "nope"}})
      end)

    assert {:error, msg} = C.login(c)
    assert msg =~ "login failed"
  end

  test "command unwraps result.content and echoes the sessionid" do
    test_pid = self()

    c =
      with_stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        if decoded["command"] == ["login"] do
          Req.Test.json(conn, %{"sessionid" => "sid-9", "result" => %{"code" => 0}})
        else
          send(test_pid, {:sid, decoded["sessionid"]})
          Req.Test.json(conn, %{"result" => %{"code" => 0, "content" => [%{"name" => "wan"}]}})
        end
      end)

    assert {:ok, [%{"name" => "wan"}]} = C.command(c, "openvpn", ["status"])
    assert_received {:sid, "sid-9"}
  end

  test "a command error code surfaces as {:error, msg}" do
    c =
      with_stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        if Jason.decode!(body)["command"] == ["login"] do
          Req.Test.json(conn, %{"sessionid" => "s", "result" => %{"code" => 0}})
        else
          Req.Test.json(conn, %{"result" => %{"code" => 500, "message" => "boom"}})
        end
      end)

    assert {:error, msg} = C.command(c, "appmgmt", ["get_information"])
    assert msg =~ "500"
  end

  test "the secret-leaking 'ipsec get' is refused before any request" do
    # No stub installed → any HTTP call would error; the guard must short-circuit.
    c = client()
    assert {:error, msg} = C.command(c, "ipsec", ["get"])
    assert msg =~ "leaks secrets"
  end

  test "fetch_status derives the OPNsense-shaped metric sections, dropping empties" do
    c =
      with_stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        content =
          case {decoded["module"], decoded["command"]} do
            {"auth", ["login"]} ->
              :login

            # The live-stats endpoint — NOT appmgmt get_information, which
            # carries none of these numbers (see fetch_status/1).
            {"system", ["info"]} ->
              [
                %{"attribute" => "hostname", "value" => "utm1"},
                %{"attribute" => "version", "value" => "14.1.6"},
                %{"attribute" => "Idle", "value" => "  98%"},
                %{"attribute" => "Mem Total", "value" => "3887616"},
                %{"attribute" => "Mem Avail", "value" => "2930392"},
                %{"attribute" => "storage", "value" => "61660659712"},
                %{"attribute" => "storage free", "value" => "57942274048"},
                %{"attribute" => "Uptime", "value" => "01:19:44"}
              ]

            {"interface", ["address", "get"]} ->
              [%{"flags" => ["ONLINE"], "device" => "A1", "address" => "10.21.0.1/22"}]

            {"openvpn", ["status"]} ->
              [%{"tunnel" => "vpn1"}]

            _ ->
              []
          end

        if content == :login,
          do: Req.Test.json(conn, %{"sessionid" => "s", "result" => %{"code" => 0}}),
          else: Req.Test.json(conn, %{"result" => %{"code" => 0, "content" => content}})
      end)

    status = C.fetch_status(c)

    # Same section shapes the OPNsense client emits, so one checks/render path
    # serves both vendors.
    assert status["cpu"] == %{"total_pct" => 2.0}
    assert %{"used_pct" => 24.6, "total_mb" => 3796.5} = status["memory"]
    assert [%{"mountpoint" => "/data", "used_pct" => 6.0}] = status["disks"]
    assert status["uptime"] == "01:19:44"
    assert status["system"] == %{"hostname" => "utm1", "os" => "14.1.6"}

    assert [%{"name" => "A1", "status" => "up", "address" => "10.21.0.1/22"}] =
             status["interfaces"]

    assert status["openvpn"] == [%{"tunnel" => "vpn1"}]

    # ipsec returned [] → dropped, no empty section written.
    refute Map.has_key?(status, "ipsec")
  end
end
