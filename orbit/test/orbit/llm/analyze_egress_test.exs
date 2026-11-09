defmodule Orbit.LLM.AnalyzeEgressTest do
  @moduledoc """
  A custom LLM base URL is an outbound request with an API key in its
  headers: it goes through the same egress guard as the notifier webhooks,
  never follows redirects, and a provider error body is not echoed into the
  UI (it can carry whatever the far side chooses to reflect).
  """
  use ExUnit.Case, async: false

  alias Orbit.LLM.Analyze

  defp settings(map), do: fn key -> Map.get(map, key, "") end

  test "a custom base url on a blocked address is refused without a request" do
    Req.Test.stub(__MODULE__, fn _ -> flunk("request left the guard") end)

    assert {:error, msg} =
             Analyze.analyze_logs("openai", "x",
               settings:
                 settings(%{
                   "llm_openai_api_key" => "k",
                   "llm_openai_base_url" => "http://[::ffff:169.254.169.254]/v1"
                 }),
               req_plug: {Req.Test, __MODULE__}
             )

    assert msg =~ "blocked"
  end

  test "a provider error body is not echoed" do
    Req.Test.stub(__MODULE__, fn conn ->
      conn |> Plug.Conn.put_status(401) |> Req.Test.json(%{"error" => "SECRET-REFLECTION"})
    end)

    assert {:error, msg} =
             Analyze.analyze_logs("openai", "x",
               settings: settings(%{"llm_openai_api_key" => "k"}),
               req_plug: {Req.Test, __MODULE__},
               ssrf_check: fn _ -> nil end
             )

    assert msg =~ "401"
    refute msg =~ "SECRET-REFLECTION"
  end

  test "an oversized provider answer is refused, a normal one still parses" do
    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.json(conn, %{"choices" => [], "pad" => String.duplicate("a", 10_000_000)})
    end)

    opts = [
      settings: settings(%{"llm_openai_api_key" => "k"}),
      req_plug: {Req.Test, __MODULE__},
      ssrf_check: fn _ -> nil end
    ]

    assert {:error, msg} = Analyze.analyze_logs("openai", "x", opts)
    assert msg =~ "too large"

    Req.Test.stub(__MODULE__, fn conn ->
      Req.Test.json(conn, %{"choices" => [%{"message" => %{"content" => " ok "}}]})
    end)

    assert {:ok, %{findings: "ok"}} = Analyze.analyze_logs("openai", "x", opts)
  end

  test "a redirect is not followed" do
    test_pid = self()

    Req.Test.stub(__MODULE__, fn conn ->
      send(test_pid, {:hit, conn.host})

      conn
      |> Plug.Conn.put_resp_header("location", "http://127.0.0.1/steal")
      |> Plug.Conn.send_resp(307, "")
    end)

    assert {:error, _} =
             Analyze.analyze_logs("openai", "x",
               settings: settings(%{"llm_openai_api_key" => "k"}),
               req_plug: {Req.Test, __MODULE__},
               ssrf_check: fn _ -> nil end
             )

    assert_received {:hit, _}
    refute_received {:hit, _}
  end
end
