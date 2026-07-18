defmodule Orbit.Poller do
  @moduledoc """
  Direct-poll orchestration — the bridge that makes a direct (API-polled)
  instance feed the exact same Checks engine + hub cache as a push instance.

  `poll_instance/1` builds the device client (OPNsense API or Securepoint
  spcgi, by device_type), fetches the live status as raw sections, and
  ingests them into the hub cache (guarded writes, same path the agent push
  takes). One evaluation path, two transports, several vendors.

  The periodic poll scheduler that drives this over every direct instance is
  deliberately NOT wired into Orbit.Scheduler yet: during the transition both
  stacks share the fleet, and a second poller would double-hammer the
  appliances (incident fce8ccc). It arms at cutover; until then this is
  driven on demand (a "poll now" admin action / ops).
  """

  alias Orbit.Instances.Instance
  alias Orbit.Poller.OpnsenseClient
  alias Orbit.Securepoint.Client, as: SecurepointClient

  @doc """
  Poll one direct-transport instance: fetch its live status and ingest it into
  the hub cache. Returns `{:ok, section_count}` or `{:error, reason}`. Push
  instances are refused — they feed the cache via the agent, not a poll.
  """
  @spec poll_instance(Instance.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def poll_instance(%Instance{} = inst) do
    if Instance.agent_mode?(inst) do
      {:error, :push_instance}
    else
      with {:ok, status} <- fetch(inst) do
        Orbit.Hub.ingest_metrics(inst.id, status)
        {:ok, map_size(status)}
      end
    end
  end

  # Vendor dispatch by device_type — OPNsense/pfSense direct API vs the
  # Securepoint spcgi pull. Both return raw sections the checks engine reads.
  defp fetch(%Instance{device_type: "securepoint"} = inst) do
    with {:ok, client} <- SecurepointClient.new(inst) do
      {:ok, SecurepointClient.fetch_status(client)}
    end
  end

  defp fetch(%Instance{} = inst) do
    with {:ok, client} <- OpnsenseClient.new(inst) do
      {:ok, OpnsenseClient.fetch_status(client)}
    end
  end
end
