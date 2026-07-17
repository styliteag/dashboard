defmodule OrbitWeb.CommentController do
  @moduledoc """
  Entity comments API. Read is any-session (index); writes ride require_write
  (set) and are audited. Both scope through get_instance (invariant 1): a
  missing or out-of-scope id 404s, never revealing existence. An empty comment
  deletes. Mirror of backend/src/app/comments/routes.py.
  """

  use OrbitWeb, :controller

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Comments

  def index(conn, %{"instance_id" => raw_id}) do
    user = conn.assigns.current_user

    with {id, ""} <- Integer.parse(raw_id),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      json(conn, Enum.map(Comments.list_for_instance(inst.id), &view/1))
    else
      _ -> not_found(conn)
    end
  end

  def set(conn, %{"instance_id" => raw_id} = params) do
    user = conn.assigns.current_user
    kind = params["kind"]
    entity_key = to_string(params["entity_key"] || "")
    text = params["comment"] |> to_string() |> String.trim()

    with {id, ""} <- Integer.parse(raw_id),
         true <- Comments.valid_kind?(kind),
         inst when not is_nil(inst) <- Scope.get_instance(id, user) do
      apply_change(conn, inst.id, kind, entity_key, text, user)
    else
      false -> conn |> put_status(422) |> json(%{detail: "unknown comment kind"})
      _ -> not_found(conn)
    end
  end

  # Empty text deletes; a delete of a never-existing comment is a silent no-op
  # (no audit row), matching the python route.
  defp apply_change(conn, iid, kind, entity_key, "", user) do
    if Comments.remove(iid, kind, entity_key) do
      audit(conn, "comment.delete", iid, kind, entity_key, "", user)
    end

    json(conn, %{ok: true})
  end

  defp apply_change(conn, iid, kind, entity_key, text, user) do
    case Comments.upsert(iid, kind, entity_key, text, user.username) do
      {:ok, _} ->
        audit(conn, "comment.set", iid, kind, entity_key, text, user)
        json(conn, %{ok: true})

      {:error, _} ->
        conn |> put_status(409) |> json(%{detail: "comment was changed concurrently, retry"})
    end
  end

  defp audit(conn, action, iid, kind, entity_key, text, user) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: user.id,
      target_type: "instance",
      target_id: iid,
      source_ip: client_ip(conn),
      # Comment text is operator-authored prose (like Instance.notes) — safe to
      # log verbatim; no secrets pass through here.
      detail: %{kind: kind, entity_key: entity_key, comment: text}
    )
  end

  defp view(c) do
    %{
      instance_id: c.instance_id,
      kind: c.kind,
      entity_key: c.entity_key,
      comment: c.comment,
      updated_by: c.updated_by,
      updated_at: c.updated_at && DateTime.to_iso8601(c.updated_at)
    }
  end

  defp not_found(conn), do: conn |> put_status(404) |> json(%{detail: "not found"})
  defp client_ip(conn), do: conn.remote_ip |> :inet.ntoa() |> to_string()
end
