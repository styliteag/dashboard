defmodule OrbitWeb.ConfigBackupController do
  @moduledoc """
  Raw config-version download. Config XML is admin-only (it carries secrets in
  cleartext). Admin gate first, then scope through get_instance (invariant 1);
  an out-of-scope id 404s. The stored blob is Fernet-decrypted by the store.
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.ConfigBackup.Store

  def raw(conn, %{"instance_id" => raw_id, "backup_id" => raw_bid}) do
    user = conn.assigns.current_user

    with true <- user.role == "admin",
         {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user),
         {bid, ""} <- Integer.parse(raw_bid),
         content when is_binary(content) <- Store.get_content(inst.id, bid) do
      conn
      |> put_resp_content_type("text/plain")
      |> put_resp_header("content-disposition", ~s(inline; filename="config-#{bid}.xml"))
      |> send_resp(200, content)
    else
      false -> conn |> put_status(403) |> json(%{detail: "admin only"})
      _ -> conn |> put_status(404) |> json(%{detail: "not found"})
    end
  end
end
