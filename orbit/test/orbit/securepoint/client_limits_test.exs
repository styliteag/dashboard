defmodule Orbit.Securepoint.ClientLimitsTest do
  @moduledoc """
  The spcgi client sends the appliance credentials in the JSON body of
  every login: a 307/308 would make the HTTP client re-send that body to
  wherever the box points, so redirects are never followed. Response bodies
  are capped instead of buffered in full.
  """
  use ExUnit.Case, async: true

  alias Orbit.Securepoint.Client, as: C

  defp with_stub(fun) do
    Req.Test.stub(__MODULE__, fun)

    %C{
      base_url: "https://utm:11115",
      user: "admin",
      password: "pw",
      ssl_verify: false,
      req_plug: {Req.Test, __MODULE__}
    }
  end

  test "a 307 is not followed with the credentials" do
    test_pid = self()

    c =
      with_stub(fn conn ->
        send(test_pid, {:hit, conn.host})

        conn
        |> Plug.Conn.put_resp_header("location", "https://evil.example/steal")
        |> Plug.Conn.send_resp(307, "")
      end)

    assert {:error, _} = C.login(c)
    assert_received {:hit, "utm"}
    refute_received {:hit, "evil.example"}
  end

  test "an oversized body is refused" do
    c =
      with_stub(fn conn ->
        Req.Test.json(conn, %{
          "sessionid" => "s",
          "result" => %{"code" => 0},
          "blob" => String.duplicate("a", 40_000_000)
        })
      end)

    assert {:error, _} = C.login(c)
  end

  test "a normal login still works" do
    c =
      with_stub(fn conn ->
        Req.Test.json(conn, %{"sessionid" => "sid-1", "result" => %{"code" => 0}})
      end)

    assert {:ok, %C{sessionid: "sid-1"}} = C.login(c)
  end
end
