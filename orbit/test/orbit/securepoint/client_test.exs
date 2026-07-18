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

  test "fetch_status gathers the raw sections, dropping empties" do
    c =
      with_stub(fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        decoded = Jason.decode!(body)

        content =
          case {decoded["module"], decoded["command"]} do
            {"auth", ["login"]} -> :login
            {"appmgmt", ["get_information"]} -> [%{"hostname" => "utm1"}]
            {"openvpn", ["status"]} -> [%{"tunnel" => "vpn1"}]
            _ -> []
          end

        if content == :login,
          do: Req.Test.json(conn, %{"sessionid" => "s", "result" => %{"code" => 0}}),
          else: Req.Test.json(conn, %{"result" => %{"code" => 0, "content" => content}})
      end)

    status = C.fetch_status(c)
    assert status["system"] == [%{"hostname" => "utm1"}]
    assert status["openvpn"] == [%{"tunnel" => "vpn1"}]
    # ipsec returned [] → dropped.
    refute Map.has_key?(status, "ipsec")
  end
end
