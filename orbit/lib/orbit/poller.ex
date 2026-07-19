defmodule Orbit.Poller do
  @moduledoc """
  Direct-poll orchestration — the bridge that makes a direct (API-polled)
  instance feed the exact same Checks engine + hub cache as a push instance.

  `poll_instance/1` builds the device client (OPNsense API or Securepoint
  spcgi, by device_type), fetches the live status as raw sections, and
  ingests them into the hub cache (guarded writes, same path the agent push
  takes). One evaluation path, two transports, several vendors.

  `poll_all/0` is the scheduler entry point: tick-and-gate over every direct
  instance (Orbit.Poller.Gate), fanned out with a concurrency cap so one hung
  appliance cannot stall the tick.

  NOTE (incident fce8ccc): this must be the ONLY poller pointed at a fleet.
  While a python backend still runs against the same boxes, both stacks poll
  and every direct appliance is hammered twice per interval.
  """

  require Logger

  alias Orbit.Availability
  alias Orbit.Instances.Instance
  alias Orbit.Poller.Gate
  alias Orbit.Poller.OpnsenseClient
  alias Orbit.Securepoint.Client, as: SecurepointClient

  # A single box may not hold a slot forever — the client's own HTTP timeouts
  # should fire first, this is the backstop for a wedged connection.
  @poll_timeout_ms :timer.seconds(60)

  @doc """
  Poll one direct-transport instance: fetch its live status, ingest it into the
  hub cache, persist the metric rows and stamp the availability columns.
  Returns `{:ok, section_count}` or `{:error, reason}`. Push instances are
  refused — they feed the cache via the agent, not a poll.

  The DB half is python's `_poll_instance`: metrics rows, last_success/
  last_error stamps, and the online↔offline edges (history row + alert), all
  through Orbit.Availability so push and poll share the flip semantics.
  """
  @spec poll_instance(Instance.t()) :: {:ok, non_neg_integer()} | {:error, term()}
  def poll_instance(%Instance{} = inst), do: poll_instance(inst, persist: true)

  @doc """
  `persist: false` runs the fetch→cache half only, for callers that just want
  fresh sections (an interactive "poll now") without touching the availability
  columns or writing a metrics point.
  """
  @spec poll_instance(Instance.t(), keyword()) :: {:ok, non_neg_integer()} | {:error, term()}
  def poll_instance(%Instance{} = inst, opts) do
    cond do
      Instance.agent_mode?(inst) ->
        {:error, :push_instance}

      Keyword.get(opts, :persist, true) ->
        persisted_poll(inst)

      true ->
        with {:ok, status} <- fetch(inst) do
          Orbit.Hub.ingest_metrics(inst.id, status)
          {:ok, map_size(status)}
        end
    end
  end

  defp persisted_poll(%Instance{} = inst) do
    now = DateTime.utc_now()

    case fetch(inst) do
      {:ok, status} ->
        Orbit.Hub.ingest_metrics(inst.id, status)
        Orbit.Metrics.write_push(inst.id, now, status)
        Availability.stamp_poll_ok(inst.id, inst.name, now)
        Logger.debug("poll.ok instance=#{inst.name} sections=#{map_size(status)}")
        {:ok, map_size(status)}

      {:error, reason} ->
        Logger.warning("poll.error instance=#{inst.name} error=#{inspect(reason)}")
        Availability.stamp_poll_error(inst.id, inst.name, now, describe(reason))
        {:error, reason}
    end
  rescue
    error ->
      Logger.warning("poll.crashed instance=#{inst.name} error=#{Exception.message(error)}")

      Availability.stamp_poll_error(
        inst.id,
        inst.name,
        DateTime.utc_now(),
        Exception.message(error)
      )

      {:error, :exception}
  end

  @doc """
  Scheduler entry point: poll every direct instance whose own effective
  interval has elapsed. Returns the number of instances actually polled.

  Tick-and-gate (python `_poll_all`): the job fires every `poll_tick_seconds`,
  each box is polled once its own interval — per-instance override or the
  `poll_interval_seconds` default — has passed since its last ATTEMPT, so a
  failing box retries on its own cadence instead of every tick.
  """
  @spec poll_all() :: non_neg_integer()
  def poll_all do
    default_interval = Orbit.Settings.effective("poll_interval_seconds")
    concurrency = max(Orbit.Settings.effective("poll_concurrency"), 1)
    now = DateTime.utc_now()

    due = due_instances(now, default_interval)

    if due != [] do
      Logger.debug("poll.tick due=#{length(due)} concurrency=#{concurrency}")

      due
      |> Task.async_stream(&poll_instance/1,
        max_concurrency: concurrency,
        timeout: @poll_timeout_ms,
        on_timeout: :kill_task,
        ordered: false
      )
      |> Stream.run()
    end

    length(due)
  end

  # Only the columns the gate needs; the full record is loaded per due box so a
  # long tick never works from a stale snapshot of credentials.
  defp due_instances(now, default_interval) do
    %{rows: rows} =
      Orbit.Repo.query!(
        "SELECT id, poll_interval_seconds, last_success_at, last_error_at FROM instances " <>
          "WHERE deleted_at IS NULL AND transport = 'direct'"
      )

    for [id, override, success, error] <- rows,
        Gate.due?(now, success, error, Gate.effective_interval(override, default_interval)),
        inst = Orbit.Repo.get(Instance, id),
        inst != nil,
        do: inst
  end

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)

  # Vendor dispatch by device_type — OPNsense/pfSense direct API vs the
  # Securepoint spcgi pull. Both return raw sections the checks engine reads.
  defp fetch(%Instance{device_type: "securepoint"} = inst) do
    with {:ok, client} <- SecurepointClient.new(inst) do
      client
      |> SecurepointClient.fetch_status()
      |> enrich_ipsec_over_ssh(inst)
      |> non_empty()
    end
  end

  defp fetch(%Instance{} = inst) do
    with {:ok, client} <- OpnsenseClient.new(inst) do
      non_empty(OpnsenseClient.fetch_status(client))
    end
  end

  # SSH enrichment (docs/securepoint-ssh.md): the spcgi `ipsec status` carries no
  # IKE cookies, ESP SPIs or byte counters — swanctl over SSH does, and those are
  # what pair tunnel ends across NAT. Opt-in per instance and FAIL-OPEN on the
  # enrichment itself: any SSH problem (no key pinned yet, box unreachable on 22,
  # swanctl missing) leaves the spcgi section in place rather than failing the
  # whole poll. Fail-CLOSED still governs the connection itself — an unpinned or
  # mismatched host key refuses to connect, it does not fall back to trusting it.
  defp enrich_ipsec_over_ssh(status, %Instance{ssh_enabled: true} = inst) do
    case Orbit.Securepoint.SSH.config_for(inst) do
      {:ok, cfg} ->
        running = ipsec_running?(status)

        case Orbit.Securepoint.SSH.fetch_ipsec_status(cfg, running) do
          {:ok, section} ->
            Map.put(status, "ipsec", section)

          {:error, reason} ->
            Logger.debug("securepoint.ssh_enrich_skipped instance_id=#{inst.id} reason=#{reason}")
            status
        end

      :error ->
        status
    end
  end

  defp enrich_ipsec_over_ssh(status, _inst), do: status

  # The spcgi section is a bare list of connections; a non-empty one means the
  # daemon answered. Keep that verdict — swanctl cannot tell us more.
  defp ipsec_running?(%{"ipsec" => list}) when is_list(list), do: list != []
  defp ipsec_running?(%{"ipsec" => %{"running" => r}}), do: !!r
  defp ipsec_running?(_), do: false

  # DELIBERATE DIVERGENCE from the python original. Both vendor clients swallow
  # per-endpoint failures so one broken endpoint still yields a partial status —
  # but that also means an unreachable box returns an EMPTY section map rather
  # than raising. python's _poll_instance has no guard for that: it stamps
  # last_success_at and writes cpu.total=0, so a dead direct box never goes
  # offline, it just flatlines at 0% (xsense/client.py wraps connection errors
  # in OPNsenseError, which poll_status suppresses). Zero sections = we learned
  # nothing = failed poll, which is what the availability columns must say.
  defp non_empty(status) when map_size(status) == 0, do: {:error, :no_data}
  defp non_empty(status), do: {:ok, status}
end
