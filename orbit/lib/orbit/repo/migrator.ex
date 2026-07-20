defmodule Orbit.Repo.Migrator do
  @moduledoc """
  Boot-time schema owner. Orbit now owns the database schema (the Alembic
  monopoly ended at cutover): this runs any pending Ecto migrations
  synchronously during startup — creating the whole baseline schema on an
  EMPTY database, and applying incremental changes on an existing one — before
  the endpoint accepts a single request. Parity with the old container's
  `alembic upgrade head` at boot (docker/start.sh).

  It is a supervised child placed AFTER `Orbit.Repo` and BEFORE `Orbit.Settings`
  and the endpoint, so nothing queries a table the migration hasn't created yet.
  `start_link/0` runs the migrations and returns `:ignore`, so no process
  lingers in the tree once the DB is at head.

  Gated by `config :orbit, :migrate_on_boot` (false in :test — the suite manages
  its own database).

  ## Waiting for the database

  Compose `depends_on` does not exist in Swarm/Kubernetes, so orbit regularly
  starts before its database is resolvable. Migrating immediately meant the
  first pool checkout was dropped from the queue after 4s, the supervisor could
  not start this child, the whole application exited and the runtime wrote an
  `erl_crash.dump` — for an ordinary, expected startup race that resolves
  itself seconds later. The orchestrator restarted us into the same wall until
  the database happened to be up.

  So we poll first, and only then migrate. The wait is BOUNDED
  (`DASH_DB_WAIT_SECONDS`, default 60): an unreachable database is a real
  failure that must surface, and waiting forever would hide a typo in
  `DATABASE_URL` behind a container that looks like it is starting.
  """

  require Logger

  @probe_pause_ms 2_000
  @report_every_ms 10_000

  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, type: :worker, restart: :transient}
  end

  @doc "Wait for the database, run pending migrations, then bow out."
  def start_link do
    await_database()
    run()
    :ignore
  end

  @doc """
  Block until the database answers, or raise after the configured budget.

  `probe` is injectable so the retry logic is testable without a database; it
  returns `:ok` or anything else for "not yet".
  """
  @spec await_database(keyword()) :: :ok
  def await_database(opts \\ []) do
    probe = Keyword.get(opts, :probe, &probe_database/0)
    budget_ms = Keyword.get(opts, :budget_ms, wait_seconds() * 1_000)
    pause = Keyword.get(opts, :pause_ms, @probe_pause_ms)
    sleep = Keyword.get(opts, :sleep, &Process.sleep/1)

    wait(probe, budget_ms, pause, sleep, 0)
  end

  defp wait(probe, budget_ms, pause, sleep, waited) do
    case probe.() do
      :ok ->
        if waited > 0, do: Logger.info("repo.database_ready waited_ms=#{waited}")
        :ok

      other ->
        if waited >= budget_ms do
          raise "database not reachable after #{div(budget_ms, 1000)}s: #{inspect(other)}. " <>
                  "Check DATABASE_URL and that the database is running; raise " <>
                  "DASH_DB_WAIT_SECONDS if it is simply slow to start."
        end

        # Quiet by default — a few seconds of this is normal — but say something
        # periodically so a genuinely stuck boot is not a silent hang.
        if rem(waited, @report_every_ms) == 0 do
          Logger.info("repo.waiting_for_database waited_ms=#{waited} last=#{inspect(other)}")
        end

        sleep.(pause)
        wait(probe, budget_ms, pause, sleep, waited + pause)
    end
  end

  # A pool checkout EXITS rather than raising when the pool cannot serve it, so
  # this needs `catch` as well as `rescue` — a plain rescue here would let the
  # very failure we are waiting out kill the boot.
  defp probe_database do
    case Orbit.Repo.query("SELECT 1", []) do
      {:ok, _} -> :ok
      {:error, reason} -> reason
    end
  rescue
    error -> Exception.message(error)
  catch
    _kind, reason -> reason
  end

  defp wait_seconds do
    Application.get_env(:orbit, :db_wait_seconds, 60)
  end

  @doc "Apply every pending migration up to head (idempotent)."
  def run do
    path = Application.app_dir(:orbit, ["priv", "repo", "migrations"])

    case Ecto.Migrator.run(Orbit.Repo, path, :up, all: true) do
      [] ->
        Logger.info("repo.migrate up_to_date")

      versions ->
        Logger.info("repo.migrate applied=#{length(versions)} versions=#{inspect(versions)}")
    end

    :ok
  end
end
