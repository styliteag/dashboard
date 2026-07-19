defmodule Orbit.Scheduler do
  @moduledoc """
  Periodic maintenance jobs — the GenServer analogue of poller/scheduler.py's
  APScheduler. One GenServer runs every job sequentially, so `max_instances=1`
  is structural (no job overlaps itself or another). Each job re-arms its own
  timer after running; a raising job is caught and logged, never killing the
  scheduler.

  NOT started in :test (config :orbit, :start_scheduler) — the jobs touch the
  alembic-owned schema the throwaway test DB doesn't have.

  Jobs: enrollment-code cleanup, retention pruning (metrics, ipsec/check
  events — batched oldest-first deletes, gap-lock incident), agent stale
  sweep, weekly GeoIP refresh.
  """

  use GenServer

  require Logger

  @jobs [
    {:enrollment_cleanup, :timer.hours(1), &__MODULE__.cleanup_enrollment_codes/0},
    {:metrics_prune, :timer.hours(1), &Orbit.Maintenance.Prune.prune_metrics/0},
    {:ipsec_events_prune, :timer.hours(24), &Orbit.Maintenance.Prune.prune_ipsec_events/0},
    {:check_events_prune, :timer.hours(24), &Orbit.Maintenance.Prune.prune_check_events/0},
    # Silent push agents flip offline + alert (poller _check_stale_agents port).
    {:agent_stale_sweep, :timer.seconds(60), &Orbit.Availability.sweep/0},
    # Out-of-band reachability (ICMP + HTTP) measured BY the dashboard. Runs on
    # its own cadence, deliberately independent of the poller: the probe matters
    # most exactly when polling fails, and for an agent-less box it is the only
    # liveness signal there is.
    {:reachability_probe, :timer.seconds(60), &Orbit.Probe.Runner.run_all/0},
    # Direct-API fleet (OPNsense/pfSense API, Securepoint spcgi): tick-and-gate.
    # The tick is the RESOLUTION, not the poll rate — each box is polled on its
    # own effective interval (Orbit.Poller.Gate). The job itself only fans out
    # (Task.async_stream, poll_concurrency), so a hung appliance cannot wedge
    # this GenServer and stall the other jobs.
    {:direct_poll, :timer.seconds(10), &Orbit.Poller.poll_all/0},
    # Weekly GeoLite2-City refresh (DR-G1); idle no-op without credentials.
    {:geoip_db_refresh, :timer.hours(24 * 7), &Orbit.GeoIP.Updater.refresh/0}
  ]

  # Stagger first runs a little after boot so startup isn't a DB thundering herd.
  @initial_delay_ms :timer.seconds(30)

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Run a job by id now (out-of-band; used by ops + tests). Returns the job result."
  def run_now(id) do
    {^id, _interval, fun} = Enum.find(@jobs, fn {jid, _, _} -> jid == id end)
    fun.()
  end

  @impl true
  def init(:ok) do
    for {id, _interval, _fun} <- @jobs do
      Process.send_after(self(), {:run, id}, @initial_delay_ms)
    end

    {:ok, %{}}
  end

  @impl true
  def handle_info({:run, id}, state) do
    {^id, interval, fun} = Enum.find(@jobs, fn {jid, _, _} -> jid == id end)

    try do
      fun.()
    rescue
      e -> Logger.warning("scheduler.job_failed id=#{id} #{Exception.message(e)}")
    end

    Process.send_after(self(), {:run, id}, next_interval(id, interval))
    {:noreply, state}
  end

  # The poll tick is operator-tunable at runtime (poll_tick_seconds), so it is
  # re-read on every re-arm instead of frozen into @jobs at compile time. A
  # nonsense setting falls back to the static interval rather than busy-looping.
  defp next_interval(:direct_poll, fallback) do
    case Orbit.Settings.effective("poll_tick_seconds") do
      seconds when is_integer(seconds) and seconds > 0 -> :timer.seconds(seconds)
      _ -> fallback
    end
  rescue
    _ -> fallback
  end

  defp next_interval(_id, interval), do: interval

  @doc """
  Delete used or expired one-time enrollment codes. Small table (codes are
  short-lived and single-use), so a plain DELETE — no batching needed.
  Returns the number of rows removed.
  """
  @spec cleanup_enrollment_codes() :: non_neg_integer()
  def cleanup_enrollment_codes do
    %{num_rows: n} =
      Orbit.Repo.query!(
        "DELETE FROM enrollment_codes WHERE used_at IS NOT NULL OR expires_at < NOW()"
      )

    if n > 0, do: Logger.info("scheduler.enrollment_cleanup removed=#{n}")
    n
  end
end
