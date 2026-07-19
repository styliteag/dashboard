defmodule Orbit.Release do
  @moduledoc """
  Release tasks callable from the built image without Mix (there is no Mix in a
  release). Used for out-of-band schema ops:

      bin/orbit eval "Orbit.Release.migrate()"
      bin/orbit eval "Orbit.Release.rollback(Orbit.Repo, 20250101000000)"

  Boot-time migration goes through `Orbit.Repo.Migrator` instead (the Repo is
  already supervised there); these `with_repo` helpers start a throwaway repo,
  so they are for a stopped app (deploy hooks, manual rollback).
  """

  @app :orbit

  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _fun_return, _apps} =
        Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def rollback(repo, version) do
    load_app()

    {:ok, _fun_return, _apps} =
      Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  defp repos, do: Application.fetch_env!(@app, :ecto_repos)

  defp load_app, do: Application.load(@app)
end
