defmodule Orbit.PollerTest do
  @moduledoc "poll_instance bridge: fetch (mocked) → cache, and the push-refusal guard."
  use ExUnit.Case, async: false

  alias Orbit.Instances.Instance
  alias Orbit.Poller

  defp direct_instance(id) do
    enc = Orbit.Crypto.encrypt("cred")

    %Instance{
      id: id,
      name: "poll-#{id}",
      transport: "direct",
      base_url: "https://box.example:4444/",
      api_key_enc: enc,
      api_secret_enc: enc,
      ssl_verify: false,
      deleted_at: nil
    }
  end

  test "polls a direct instance and ingests the parsed sections into the hub cache" do
    Req.Test.stub(Orbit.Poller.OpnsenseClient, fn conn ->
      body =
        case conn.request_path do
          "/api/diagnostics/system/systemResources" ->
            %{
              "cpu" => %{"used" => 7.0},
              "memory" => %{"total_frmt" => "1000", "used_frmt" => "100"}
            }

          _ ->
            %{}
        end

      Req.Test.json(conn, body)
    end)

    id = 900_001
    assert {:ok, n} = Poller.poll_instance(direct_instance(id))
    assert n >= 2

    # ingest is async (cast); give it a beat, then the cache holds the sections.
    Process.sleep(50)
    status = Orbit.Hub.cache_entry(id)["status"] || %{}
    assert status["cpu"] == %{"total_pct" => 7.0}
    assert status["memory"]["used_pct"] == 10.0
  end

  test "refuses a push instance (it feeds the cache via the agent, not a poll)" do
    push = %{direct_instance(2) | transport: "push"}
    assert Poller.poll_instance(push) == {:error, :push_instance}
  end
end
