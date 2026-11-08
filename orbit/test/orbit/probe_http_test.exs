defmodule Orbit.Probe.HTTPTest do
  @moduledoc """
  The HTTP probe only needs the status line: the body is never read (a box
  answering with a huge body must not make the probe buffer it), and a
  redirect is an answer, not a hop.
  """
  use ExUnit.Case, async: true

  alias Orbit.Probe.HTTP

  defp probe(fun) do
    Req.Test.stub(__MODULE__, fun)
    HTTP.get("https://box:4444/", req_plug: {Req.Test, __MODULE__})
  end

  test "any status counts as up and the body is not kept" do
    test_pid = self()

    result =
      probe(fn conn ->
        send(test_pid, :hit)
        Plug.Conn.send_resp(conn, 200, String.duplicate("a", 40_000_000))
      end)

    assert_received :hit
    assert %{http_up: true, http_status: 200} = result
    assert HTTP.discard_body({:data, "x"}, {:req, %{body: ""}}) == {:halt, {:req, %{body: ""}}}
  end

  test "a redirect is reported, not followed" do
    result =
      probe(fn conn ->
        conn
        |> Plug.Conn.put_resp_header("location", "https://elsewhere.example/")
        |> Plug.Conn.send_resp(302, "")
      end)

    assert %{http_up: true, http_status: 302} = result
  end
end
