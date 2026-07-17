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

  # -- mutations (instances/service.py port) ---------------------------------

  @editable_fields ~w(name base_url location notes ping_url ssl_verify gui_login_enabled
    shell_enabled ssh_enabled ssh_port ssh_user maintenance firmware_locked)a

  @doc """
  Update an instance from string-keyed form params — service.update_instance
  parity: empty/omitted secrets keep the stored value (a rotation needs a
  non-empty new one); a rotated ssh key un-pins the host key; empty interval
  strings clear the per-instance override back to the global default; a
  changed slug must be free (SlugConflictError equivalent: {:error, :slug_taken}).
  A changed push interval is live-applied to a connected agent.
  """
  def update_instance(%Instance{} = inst, params) do
    with {:ok, changes} <- build_changes(inst, params) do
      inst
      |> Ecto.Changeset.change(changes)
      |> Repo.update()
      |> case do
        {:ok, updated} ->
          if Map.has_key?(changes, :push_interval_seconds) and Instance.agent_mode?(updated) do
            interval =
              updated.push_interval_seconds || Orbit.Settings.effective("push_interval_seconds")

            Orbit.Hub.send_config(updated.id, %{"push_interval" => interval})
          end

          {:ok, updated}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  @doc "Soft delete — the slug is freed for reuse (generated-column contract)."
  def soft_delete(%Instance{} = inst) do
    inst
    |> Ecto.Changeset.change(%{deleted_at: DateTime.utc_now()})
    |> Repo.update()
  end

  @doc """
  The allowlist audit detail for an update (routes._safe_audit_detail port):
  only safe fields verbatim, rotated secrets by NAME only — never a value.
  """
  def safe_audit_detail(params) do
    safe =
      for f <- @editable_fields ++ [:slug, :poll_interval_seconds, :push_interval_seconds],
          key = to_string(f),
          Map.has_key?(params, key),
          into: %{},
          do: {key, params[key]}

    rotated = for s <- ~w(api_key api_secret ssh_key), (params[s] || "") != "", do: s
    if rotated == [], do: safe, else: Map.put(safe, "secrets_rotated", rotated)
  end

  defp build_changes(inst, params) do
    base =
      for f <- @editable_fields,
          key = to_string(f),
          Map.has_key?(params, key),
          into: %{},
          do: {f, coerce(f, params[key])}

    base
    |> merge_intervals(params)
    |> merge_secrets(params)
    |> merge_slug(inst, params)
  end

  @bool_fields ~w(ssl_verify gui_login_enabled shell_enabled ssh_enabled
    maintenance firmware_locked)a

  # Checkboxes arrive "true"/"false" (or absent); ints as strings.
  defp coerce(f, value) when f in @bool_fields, do: value in [true, "true", "on"]
  defp coerce(:ssh_port, value), do: parse_int(value) || 22
  defp coerce(f, value) when f in [:location, :notes, :ping_url], do: presence(value)
  defp coerce(_f, value), do: value

  defp merge_intervals(changes, params) do
    Enum.reduce([:poll_interval_seconds, :push_interval_seconds], changes, fn f, acc ->
      key = to_string(f)

      if Map.has_key?(params, key) do
        # Empty string clears the override back to the global default.
        Map.put(acc, f, parse_int(params[key]))
      else
        acc
      end
    end)
  end

  # Empty = keep existing (invariant 3); a new value is fernet-encrypted.
  defp merge_secrets(changes, params) do
    changes
    |> put_secret(:api_key_enc, params["api_key"])
    |> put_secret(:api_secret_enc, params["api_secret"])
    |> put_ssh_key(params["ssh_key"])
  end

  defp put_secret(changes, _field, value) when value in [nil, ""], do: changes
  defp put_secret(changes, field, value), do: Map.put(changes, field, Orbit.Crypto.encrypt(value))

  defp put_ssh_key(changes, value) when value in [nil, ""], do: changes

  defp put_ssh_key(changes, value) do
    changes
    |> Map.put(:ssh_key_enc, Orbit.Crypto.encrypt(value))
    # Re-pin against the new key/identity (TOFU happens python-side for now).
    |> Map.put(:ssh_host_key, nil)
  end

  defp merge_slug(changes, inst, params) do
    case params["slug"] do
      value when value in [nil, ""] ->
        {:ok, changes}

      slug when slug == inst.slug ->
        {:ok, changes}

      slug ->
        cond do
          not Orbit.Instances.Slug.valid?(slug) -> {:error, :slug_invalid}
          slug_taken?(slug, inst.id) -> {:error, :slug_taken}
          true -> {:ok, Map.put(changes, :slug, slug)}
        end
    end
  end

  # Only ACTIVE instances reserve a slug (soft-deleted rows free it).
  defp slug_taken?(slug, exclude_id) do
    Instance
    |> where([i], i.slug == ^slug and is_nil(i.deleted_at) and i.id != ^exclude_id)
    |> limit(1)
    |> Repo.exists?()
  end

  defp parse_int(value) do
    case Integer.parse(to_string(value || "")) do
      {n, ""} when n > 0 -> n
      _ -> nil
    end
  end

  defp presence(value) do
    case String.trim(to_string(value || "")) do
      "" -> nil
      text -> text
    end
  end
end
