defmodule OrbitWeb.HealthController do
  use OrbitWeb, :controller

  # M0 liveness probe. Deliberately does
  # not touch the DB: it must stay green while the Repo points at a database
  # this app does not own yet.
  def show(conn, _params) do
    json(conn, %{
      status: "ok",
      engine: "elixir",
      version: to_string(Application.spec(:orbit, :vsn))
    })
  end
end
