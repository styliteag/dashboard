defmodule Orbit.Probe.Runner do
  @moduledoc """
  Probe every instance that has a `ping_url`, concurrently — port of the
  deleted probe scheduler job.

  Runs on its own cadence, independent of the poller: the probe must keep
  measuring precisely when polling fails, since "the poll broke" is exactly the
  moment reachability matters. Failures are contained per instance; one
  unreachable box cannot stall the sweep.
  """

  require Logger

  alias Orbit.Instances.Instance
  alias Orbit.Probe
  alias Orbit.Repo

  import Ecto.Query

  @concurrency 16
  @task_timeout 15_000

  @doc "Probe all instances with a ping target. Returns how many ran."
  def run_all do
    targets =
      Repo.all(
        from(i in Instance,
          where: is_nil(i.deleted_at) and not is_nil(i.ping_url) and i.ping_url != "",
          select: {i.id, i.ping_url}
        )
      )

    Orbit.Probe.Registry.retain(Enum.map(targets, &elem(&1, 0)))

    targets
    |> Task.async_stream(&probe_one/1,
      max_concurrency: @concurrency,
      timeout: @task_timeout,
      on_timeout: :kill_task
    )
    |> Enum.count(&match?({:ok, :ok}, &1))
  end

  defp probe_one({id, ping_url}) do
    Orbit.Probe.Registry.put(id, Probe.run(ping_url))
    :ok
  rescue
    e ->
      Logger.warning("probe.failed instance_id=#{id} error=#{Exception.message(e)}")
      :ok
  end
end
