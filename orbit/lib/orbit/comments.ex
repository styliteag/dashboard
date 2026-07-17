defmodule Orbit.Comments do
  @moduledoc """
  Entity comments: operator notes on check sub-entities, keyed per instance by
  (kind, entity_key). Read is caller-scoped by the route (get_instance); writes
  ride require_write and are audited by the controller. An empty comment
  deletes — mirrors backend/src/app/comments/store.py.
  """

  import Ecto.Query

  alias Orbit.Comments.EntityComment
  alias Orbit.Repo

  @doc "All comments for one instance, ordered by kind then entity_key."
  @spec list_for_instance(integer()) :: [EntityComment.t()]
  def list_for_instance(instance_id) do
    Repo.all(
      from(c in EntityComment,
        where: c.instance_id == ^instance_id,
        order_by: [c.kind, c.entity_key]
      )
    )
  end

  @doc "True if the kind is one of the four annotatable families."
  @spec valid_kind?(term()) :: boolean()
  def valid_kind?(kind), do: kind in EntityComment.kinds()

  @doc """
  Upsert one comment (unique on instance_id+kind+entity_key). Returns
  `{:ok, comment}` or `{:error, changeset}`.
  """
  @spec upsert(integer(), String.t(), String.t(), String.t(), String.t()) ::
          {:ok, EntityComment.t()} | {:error, Ecto.Changeset.t()}
  def upsert(instance_id, kind, entity_key, text, username) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    %EntityComment{}
    |> Ecto.Changeset.change(
      instance_id: instance_id,
      kind: kind,
      entity_key: entity_key,
      comment: text,
      updated_by: username,
      updated_at: now
    )
    # MySQL/MariaDB resolves ON DUPLICATE KEY UPDATE against any unique index
    # (here uq_entity_comment) — it does not accept a conflict_target, unlike
    # Postgres. Passing one raises ArgumentError.
    |> Repo.insert(on_conflict: [set: [comment: text, updated_by: username, updated_at: now]])
  end

  @doc "Delete one comment; returns true when a row was removed."
  @spec remove(integer(), String.t(), String.t()) :: boolean()
  def remove(instance_id, kind, entity_key) do
    {count, _} =
      Repo.delete_all(
        from(c in EntityComment,
          where: c.instance_id == ^instance_id and c.kind == ^kind and c.entity_key == ^entity_key
        )
      )

    count > 0
  end
end
