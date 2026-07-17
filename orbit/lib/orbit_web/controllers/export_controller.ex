defmodule OrbitWeb.ExportController do
  @moduledoc """
  Machine-export surfaces (checks/routes.py): Checkmk JSON + Prometheus text.
  Same auth + scoping as the python exports — a session user gets their
  groups' instances; api-key callers honor their binding (unbound = global).
  Hub state is unscoped in-memory data, so both filter through the principal's
  instance list (invariant 5).

  Fleet-wide evaluate + render is CPU; the python side runs it off the event
  loop, but on the BEAM each request is its own process, so no extra offloading
  is needed here.
  """

  use OrbitWeb, :controller

  alias Orbit.Checks.{Export, Prometheus}

  def checkmk(conn, _params) do
    principal = conn.assigns.principal
    json(conn, Export.checkmk(principal, DateTime.utc_now()))
  end

  def prometheus(conn, _params) do
    principal = conn.assigns.principal
    text = Export.prometheus(principal, DateTime.utc_now())

    conn
    |> put_resp_content_type(Prometheus.content_type())
    |> send_resp(200, text)
  end
end
