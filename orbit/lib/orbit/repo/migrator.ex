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
  """

  require Logger

  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, type: :worker, restart: :transient}
  end

  @doc "Run pending migrations on the already-started Repo, then bow out."
  def start_link do
    run()
    :ignore
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
