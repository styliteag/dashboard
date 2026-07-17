defmodule Orbit.Instances do
  @moduledoc """
  Instance queries for the UI. Reads are scoped through Orbit.Auth.Scope —
  a user only ever sees instances of their groups (invariant 1).
  """

  import Ecto.Query

  alias Orbit.Auth.Scope
  alias Orbit.Instances.Instance
  alias Orbit.Repo

  @doc "Active instances the principal may see, group loaded, name-sorted."
  @spec list_visible(Scope.principal()) :: [Instance.t()]
  def list_visible(principal) do
    Instance
    |> where([i], is_nil(i.deleted_at))
    |> Scope.scope(principal)
    |> order_by([i], asc: i.name)
    |> preload(:group)
    |> Repo.all()
  end

  @doc """
  Online when the last success is more recent than the last error — the one
  place the transition is decided (mirror of metrics/store.is_online).
  """
  @spec online?(Instance.t()) :: boolean()
  def online?(%Instance{last_success_at: nil}), do: false

  def online?(%Instance{last_success_at: succ, last_error_at: nil}) when not is_nil(succ),
    do: true

  def online?(%Instance{last_success_at: succ, last_error_at: err}),
    do: DateTime.compare(succ, err) == :gt
end
