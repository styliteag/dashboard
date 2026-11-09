defmodule Orbit.AgentBinding do
  @moduledoc """
  Owner of the agent-binding transitions of an instance — the credential an
  agent socket authenticates with (`transport` + `agent_token`, and the
  instance being alive).

      unbound (direct, no token) ──enable──▶ bound (push, token T1)
      bound (T1)                 ──enable──▶ bound (T2)      token rotation
      bound                      ──disable─▶ unbound         also "uninstall"
      any                        ──delete──▶ deleted

  The agent WS authenticates ONCE, at the upgrade
  (OrbitWeb.AgentWsController via `instance_for_token/1`). So every
  transition that invalidates a binding also evicts the live socket
  (`Orbit.Hub.evict/2`), and the socket re-checks `current?/2` right after
  it registers on hello — closing the window between upgrade and hello.

  Regression: the callers used `Hub.unregister/1` from the LiveView process;
  unregister is pid-identity-checked, answered `:stale` and did nothing, so
  a disabled/uninstalled/deleted/rotated agent kept pushing (stamping
  last_success_at, clearing maintenance) and kept receiving commands and
  tunnels until it happened to reconnect.

  Enrollment redeem (`Orbit.Enrollment.redeem/1`) also writes the binding,
  but only binds an unbound instance or keeps the existing token — it never
  revokes one, so it needs no eviction.

  `Orbit.Instances.soft_delete/1` stays a raw write (it does not touch the
  socket) for callers that must still talk to the agent before closing it
  (PRO mctl host delete sends `agent.uninstall` first). Everything else goes
  through `delete/2` here.
  """

  import Ecto.Query

  require Logger

  alias Orbit.Hub
  alias Orbit.Instances.Instance
  alias Orbit.Repo

  @doc """
  Bind (or re-bind) an instance to an agent: push transport with a FRESH
  token. On an already bound instance this is the token rotation — the old
  token's socket is evicted. Returns `{:ok, inst, token}`.
  """
  @spec enable(Instance.t(), GenServer.server()) ::
          {:ok, Instance.t(), String.t()} | {:error, Ecto.Changeset.t()}
  def enable(%Instance{} = inst, hub \\ Hub) do
    token = 48 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)

    inst
    |> Ecto.Changeset.change(transport: "push", agent_token: token)
    |> Repo.update()
    |> case do
      {:ok, updated} ->
        evict(hub, updated.id)
        {:ok, updated, token}

      other ->
        other
    end
  end

  @doc "Unbind: revoke the token, fall back to direct transport, evict the socket."
  @spec disable(Instance.t(), GenServer.server()) ::
          {:ok, Instance.t()} | {:error, Ecto.Changeset.t()}
  def disable(%Instance{} = inst, hub \\ Hub) do
    inst
    |> Ecto.Changeset.change(transport: "direct", agent_token: nil)
    |> Repo.update()
    |> evict_on_ok(hub)
  end

  @doc "Soft-delete the instance and evict its socket."
  @spec delete(Instance.t(), GenServer.server()) ::
          {:ok, Instance.t()} | {:error, Ecto.Changeset.t()}
  def delete(%Instance{} = inst, hub \\ Hub) do
    inst |> Orbit.Instances.soft_delete() |> evict_on_ok(hub)
  end

  @doc "The live push-mode instance a bearer token authenticates, or nil (ws.py:101-109)."
  @spec instance_for_token(String.t() | nil) :: Instance.t() | nil
  def instance_for_token(token) when is_binary(token) and token != "" do
    Repo.one(
      from(i in Instance,
        where: i.agent_token == ^token and i.transport == "push" and is_nil(i.deleted_at)
      )
    )
  end

  def instance_for_token(_token), do: nil

  @doc "Is `token` still the live binding of `instance_id`?"
  @spec current?(integer(), String.t() | nil) :: boolean()
  def current?(instance_id, token) do
    match?(%Instance{id: ^instance_id}, instance_for_token(token))
  end

  defp evict_on_ok({:ok, %Instance{id: id}} = ok, hub) do
    evict(hub, id)
    ok
  end

  defp evict_on_ok(other, _hub), do: other

  defp evict(hub, instance_id) do
    Hub.evict(hub, instance_id)
  catch
    # A hub that is not running has no socket to close; the DB write already
    # revoked the credential for every future upgrade. A busy hub (call
    # timeout) may leave the socket up — say so loudly.
    :exit, reason ->
      Logger.warning(
        "agent_binding.evict_failed instance_id=#{instance_id} reason=#{inspect(reason)}"
      )

      :not_connected
  end
end
