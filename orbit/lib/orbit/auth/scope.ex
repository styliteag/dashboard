defmodule Orbit.Auth.Scope do
  @moduledoc """
  Instance-visibility scoping: users only see instances of their groups.

  CHANGE-FROZEN — 1:1 port of backend/src/app/auth/scope.py; semantic changes
  need the user's explicit sign-off there AND here (CLAUDE.md invariant 1).

  Two mechanisms, one policy:
  - `scope/2` — narrows an Instance query to the principal's groups
    (the `scope_clause` equivalent, composable into any Ecto query).
  - `can_access?/2` — membership assertion for an already-loaded instance
    and for in-memory sources (hub state, WS tunnels).
  - `get_instance/2` — by-id fetch; out-of-scope and soft-deleted rows come
    back as `nil` (→ the caller's existing 404 path — no 403 existence
    oracle, and NEVER 403).

  Principals: `nil` marks internal callers (poller, hub hydrate, agent WS)
  and is always unscoped — routes must ALWAYS pass their principal; a
  forgotten argument silently disables scoping (named mistake 2).

  !!! The empty set means OPPOSITE things per principal type — never merge
  the branches: ApiKey with zero bindings = GLOBAL (keys predate groups);
  User with zero memberships = NOTHING. There is NO superadmin bypass:
  superadmin grants rights management, not instance access.
  """

  import Ecto.Query

  alias Orbit.Accounts.{ApiKey, User}
  alias Orbit.Instances.Instance
  alias Orbit.Repo

  @type principal :: User.t() | ApiKey.t() | nil

  @doc """
  Narrow an Instance query to the principal's visible groups.

  `nil` principal = unscoped (internal caller). A user with zero groups gets
  `WHERE false`: zero instances, not all.
  """
  @spec scope(Ecto.Query.t() | module(), principal()) :: Ecto.Query.t() | module()
  def scope(query, nil), do: query

  def scope(query, %ApiKey{} = key) do
    ids = ApiKey.group_id_set(key)

    # INVERTED vs the User branch below: an ApiKey with ZERO bindings is
    # GLOBAL, while a User with zero memberships sees NOTHING. Do not
    # "simplify" these into one branch.
    if MapSet.size(ids) == 0 do
      query
    else
      where(query, [i], i.group_id in ^MapSet.to_list(ids))
    end
  end

  def scope(query, %User{} = user) do
    ids = User.group_id_set(user)

    if MapSet.size(ids) == 0 do
      where(query, [i], false)
    else
      where(query, [i], i.group_id in ^MapSet.to_list(ids))
    end
  end

  @doc "Membership assertion for an already-loaded instance."
  @spec can_access?(principal(), Instance.t()) :: boolean()
  def can_access?(nil, %Instance{}), do: true

  def can_access?(%ApiKey{} = key, %Instance{group_id: group_id}) do
    ids = ApiKey.group_id_set(key)
    # empty = global, see scope/2
    MapSet.size(ids) == 0 or MapSet.member?(ids, group_id)
  end

  def can_access?(%User{} = user, %Instance{group_id: group_id}) do
    MapSet.member?(User.group_id_set(user), group_id)
  end

  @doc """
  Load an active instance; out-of-scope rows come back as `nil` (→ the
  caller's existing 404 path — no 403 existence oracle).

  There is deliberately no 2-arity default: every caller writes the principal
  explicitly, `nil` only for internal contexts.
  """
  @spec get_instance(integer(), principal()) :: Instance.t() | nil
  def get_instance(instance_id, principal) do
    with %Instance{deleted_at: nil} = inst <- Repo.get(Instance, instance_id),
         true <- can_access?(principal, inst) do
      inst
    else
      _ -> nil
    end
  end
end
