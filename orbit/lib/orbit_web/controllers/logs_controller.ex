defmodule OrbitWeb.LogsController do
  @moduledoc """
  Raw log snapshot download. Raw log content is admin-only (CLAUDE.md invariant
  4 rationale — it may carry sensitive lines the anonymizer only strips on the
  LLM path). Admin gate first, then scope through get_instance (invariant 1):
  an out-of-scope id 404s, never revealing existence.
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.Logs.Store

  def raw(conn, %{"instance_id" => raw_id, "logfile_id" => raw_lid}) do
    user = conn.assigns.current_user

    with true <- user.role == "admin",
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         {lid, ""} <- Integer.parse(raw_lid),
         lf when not is_nil(lf) <- Store.get_logfile(inst.id, lid) do
      conn
      |> put_resp_content_type("text/plain")
      |> put_resp_header("content-disposition", ~s(inline; filename="#{lf.name}"))
      |> send_resp(200, lf.content)
    else
      false -> conn |> put_status(403) |> json(%{detail: "admin only"})
      _ -> conn |> put_status(404) |> json(%{detail: "not found"})
    end
  end
end
