defmodule Orbit.Instances do
  @moduledoc """
  Instance queries for the UI. Reads are scoped through Orbit.Auth.Scope —
  a user only ever sees instances of their groups (invariant 1).
  """

  import Ecto.Query

  require Logger

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
  Tag vocabulary in use across the principal's visible instances, sorted —
  the tag picker's suggestion list.

  Scoped like every other instance read (invariant 1) and for a concrete
  reason: tags carry customer names, so an unscoped list would leak them into
  the dropdown of a user who cannot see the boxes wearing them.
  """
  @spec known_tags(Scope.principal()) :: [String.t()]
  def known_tags(principal) do
    Instance
    |> where([i], is_nil(i.deleted_at))
    |> Scope.scope(principal)
    |> select([i], i.tags)
    |> Repo.all()
    |> Enum.flat_map(&(&1 || []))
    |> Enum.uniq()
    |> Enum.sort()
  end

  @doc """
  Online when the last success is more recent than the last error — the
  last-outcome verdict (mirror of metrics/store.is_online), decided in
  `Orbit.Availability.online?/2`.
  """
  @spec online?(Instance.t()) :: boolean()
  def online?(%Instance{last_success_at: succ, last_error_at: err}),
    do: Orbit.Availability.online?(succ, err)

  @doc """
  Three-way status bucket for the list KPI tiles and row badges
  (statusBucket parity, InstancesPage.tsx) — the string form of
  `Orbit.Availability.classify/3`. Tiles are counted from the same function
  the badges render from, so the two can never drift.
  """
  @spec status_bucket(Instance.t(), boolean(), DateTime.t()) :: String.t()
  def status_bucket(%Instance{} = inst, agent_connected, now \\ DateTime.utc_now()) do
    inst |> Orbit.Availability.classify(agent_connected, now) |> Atom.to_string()
  end

  @doc """
  Move an instance to another group (instances/routes.py move_group — a
  RIGHTS operation, not instance config; the groups page's superadmin
  assignment table is the only caller). Returns {:ok, inst} | {:error, _}.
  """
  def move_group(%Instance{} = inst, group_id) when is_integer(group_id) do
    inst
    |> Ecto.Changeset.change(group_id: group_id)
    |> Repo.update()
  end

  # -- mutations (instances/service.py port) ---------------------------------

  @editable_fields ~w(name base_url location notes ping_url tags ssl_verify gui_login_enabled
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
    with :ok <- Orbit.Instances.Input.validate(params),
         {:ok, changes} <- build_changes(inst, params) do
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

  @doc """
  Store a host key captured by probing the box (trust on first use).

  Deliberately NOT an editable form field: a pinned host key is only meaningful
  if it came from the box itself. Letting it be typed would turn the whole
  fail-closed check into something an operator can defeat by pasting whatever
  the attacker presented.
  """
  def pin_ssh_host_key(%Instance{} = inst, line) when is_binary(line) do
    if String.trim(line) == "" do
      {:error, :empty}
    else
      inst
      |> Ecto.Changeset.change(%{ssh_host_key: String.trim(line)})
      |> Repo.update()
    end
  end

  @doc """
  Correct a wrong `device_type` from what the agent reports about itself.

  A box enrolled with the wrong type (the create form defaults to opnsense;
  a pfSense enrolled by hand stays mislabeled forever) gets the wrong
  firmware branch, the wrong GUI deep links and the wrong tabs — silently
  and permanently, because nothing else ever revisits the field. The agent's
  `detect_platform()` is authoritative: it reads the box's own markers.

  Only ever heals between the agent-detectable types. A Securepoint or any
  other pull-only type is never touched (no agent runs there), and an
  unknown/blank platform is ignored rather than written.
  """
  @agent_detectable ~w(opnsense pfsense linux)

  def heal_device_type(instance_id, platform) when platform in @agent_detectable do
    case Repo.get(Instance, instance_id) do
      %Instance{device_type: ^platform} ->
        :ok

      %Instance{device_type: old} = inst when old in @agent_detectable ->
        inst
        |> Ecto.Changeset.change(device_type: platform)
        |> Repo.update()

        Orbit.Audit.write(
          action: "instance.device_type_healed",
          result: "ok",
          target_type: "instance",
          target_id: instance_id,
          detail: %{"kind" => "#{old}->#{platform}"}
        )

        Logger.info(
          "instance.device_type_healed instance_id=#{instance_id} from=#{old} to=#{platform}"
        )

        :ok

      _ ->
        :ok
    end
  end

  def heal_device_type(_instance_id, _platform), do: :ok

  @device_types ~w(opnsense pfsense proxmox truenas securepoint linux)
  # Push-only device types have no direct API — base_url must stay empty (DR-9).
  @push_only_types ~w(linux)

  def device_types, do: @device_types
  def push_only_type?(device_type), do: device_type in @push_only_types

  @doc """
  Create an instance (service.create_instance port): agent-mode gets
  encrypted placeholder credentials (NOT NULL columns), transport defaults
  from the mode, a name-derived slug auto-suffixes -2/-3… while an explicit
  one must be free.
  """

  def create_instance(params, group_id) do
    transport =
      if params["transport"] in ["push", "direct"], do: params["transport"], else: "push"

    device_type = if params["device_type"] in @device_types, do: params["device_type"], else: nil
    name = String.trim(to_string(params["name"] || ""))

    cond do
      (bad = Orbit.Instances.Input.validate(params)) != :ok ->
        bad

      name == "" ->
        {:error, :name_required}

      device_type == nil ->
        {:error, :bad_device_type}

      push_only_type?(device_type) and presence(params["base_url"]) != nil ->
        {:error, :push_only_no_base_url}

      true ->
        insert_instance(params, group_id, name, transport, device_type)
    end
  end

  defp insert_instance(params, group_id, name, transport, device_type) do
    api_key = presence(params["api_key"]) || "agent-mode-no-key"
    api_secret = presence(params["api_secret"]) || "agent-mode-no-secret"

    with {:ok, slug} <- resolve_create_slug(params["slug"], name) do
      %Instance{}
      |> Ecto.Changeset.change(%{
        name: name,
        group_id: group_id,
        slug: slug,
        base_url: presence(params["base_url"]) || "",
        api_key_enc: Orbit.Crypto.encrypt(api_key),
        api_secret_enc: Orbit.Crypto.encrypt(api_secret),
        transport: transport,
        device_type: device_type,
        ssl_verify: params["ssl_verify"] in [true, "true", "on"],
        ca_bundle: presence(params["ca_bundle"]),
        # Autologin armed on new instances (operator decision 2026-07-20): the
        # point of the GUI proxy is landing IN the firewall's web UI, not on
        # its login form, and every box that gets one wants it. Absent means
        # on; an explicit false still wins, so a create form that later grows
        # the checkbox keeps working without touching this.
        gui_login_enabled: params["gui_login_enabled"] not in [false, "false", "off"],
        # Terminal armed on new instances (2.7.8/3.0.5 behaviour, restored by
        # operator decision 2026-07-20). This is a per-instance opt-in only —
        # the root shell still needs the global DASH_SHELL_ENABLED gate, an
        # admin session and the write role, and every open is audited. A box
        # that must never expose a shell has to be edited after creation.
        shell_enabled: true,
        ssh_enabled: false,
        maintenance: false,
        firmware_locked: false,
        location: presence(params["location"]),
        # Carried at creation, not edit-only: the retired React modal offered
        # these four on the add form, and a create-then-edit round trip is easy
        # to forget — a box then sits untagged and unprobed. Same coercion as
        # the edit path (comma string -> array, blank interval -> global default).
        tags: coerce(:tags, params["tags"]),
        ping_url: presence(params["ping_url"]),
        notes: presence(params["notes"]),
        push_interval_seconds: parse_int(params["push_interval_seconds"]),
        # No agent_token at creation — the enrollment redeem mints it (§16 C2).
        created_at: DateTime.utc_now(),
        updated_at: DateTime.utc_now()
      })
      |> Repo.insert()
      |> case do
        {:ok, inst} ->
          {:ok, inst}

        {:error, _changeset} ->
          {:error, :conflict}
      end
    end
  rescue
    # name_active_key/slug uniques are DB-side generated-column constraints —
    # ecto raises instead of returning a changeset error (409 parity).
    Ecto.ConstraintError -> {:error, :conflict}
  end

  # Explicit slug must be free (a clash is an error); name-derived auto-suffixes.
  defp resolve_create_slug(explicit, name) do
    case presence(explicit) do
      nil ->
        {:ok, auto_suffix_slug(Orbit.Instances.Slug.slugify(name))}

      slug ->
        cond do
          not Orbit.Instances.Slug.valid?(slug) -> {:error, :slug_invalid}
          slug_taken?(slug, 0) -> {:error, :slug_taken}
          true -> {:ok, slug}
        end
    end
  end

  defp auto_suffix_slug(base), do: auto_suffix_slug(base, base, 2)

  defp auto_suffix_slug(base, candidate, n) do
    if slug_taken?(candidate, 0) do
      suffix = "-#{n}"
      max = Orbit.Instances.Slug.max_len() - String.length(suffix)
      trimmed = base |> String.slice(0, max) |> String.trim_trailing("-")
      auto_suffix_slug(base, trimmed <> suffix, n + 1)
    else
      candidate
    end
  end

  @doc """
  Target group for a new instance (routes._resolve_create_group port): one
  of the creator's groups (superadmins may target any); implied when the
  user has exactly one.
  """
  def resolve_create_group(user, group_id_param) do
    memberships = Orbit.Accounts.User.group_id_set(user)
    requested = parse_int(group_id_param)

    cond do
      requested == nil and MapSet.size(memberships) == 1 ->
        {:ok, memberships |> MapSet.to_list() |> hd()}

      requested == nil ->
        {:error, :group_required}

      user.is_superadmin ->
        if Repo.get(Orbit.Accounts.Group, requested),
          do: {:ok, requested},
          else: {:error, :unknown_group}

      MapSet.member?(memberships, requested) ->
        {:ok, requested}

      true ->
        {:error, :not_a_member}
    end
  end

  @doc """
  Soft delete — the slug is freed for reuse (generated-column contract).

  Raw write: it does NOT close a connected agent socket. UI/API callers use
  Orbit.AgentBinding.delete/2, which evicts it; call this directly only when
  you must still talk to the agent first and close the socket yourself.
  """
  def soft_delete(%Instance{} = inst) do
    inst
    |> Ecto.Changeset.change(%{deleted_at: DateTime.utc_now()})
    |> Repo.update()
    |> case do
      {:ok, deleted} ->
        {:ok, deleted}

      other ->
        other
    end
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

    # ca_bundle rides the by-name list, never the verbatim one — a PEM in the
    # audit detail is exactly what the allowlist exists to prevent.
    rotated = for s <- ~w(api_key api_secret ssh_key ca_bundle), (params[s] || "") != "", do: s
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
    |> drop_secrets_on_new_origin(inst, params)
    |> merge_secrets(params)
    |> merge_slug(inst, params)
  end

  # A base_url pointing at another origin (scheme, host or port) must not
  # inherit the stored API credentials — the next poll or "Test connection"
  # would hand them to that host. Whatever is not re-entered in the same save
  # is replaced by the agent-mode placeholder (the columns are NOT NULL).
  # Re-entered values are applied afterwards by merge_secrets/2.
  defp drop_secrets_on_new_origin(changes, inst, params) do
    if Map.has_key?(params, "base_url") and
         Orbit.Instances.Input.new_origin?(params["base_url"], inst.base_url) do
      changes
      |> Map.put(:api_key_enc, Orbit.Crypto.encrypt("agent-mode-no-key"))
      |> Map.put(:api_secret_enc, Orbit.Crypto.encrypt("agent-mode-no-secret"))
    else
      changes
    end
  end

  @bool_fields ~w(ssl_verify gui_login_enabled shell_enabled ssh_enabled
    maintenance firmware_locked)a

  # Checkboxes arrive "true"/"false" (or absent); ints as strings.
  defp coerce(f, value) when f in @bool_fields, do: value in [true, "true", "on"]
  defp coerce(:ssh_port, value), do: parse_int(value) || 22
  defp coerce(f, value) when f in [:location, :notes, :ping_url], do: presence(value)

  # Tags arrive as one comma-separated string from the form and are stored as
  # an array. Trimmed, blanks dropped, de-duplicated — the fleet page filters
  # on exact matches, so " LAB" and "LAB" must not become two chips.
  defp coerce(:tags, value) when is_binary(value) do
    value
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
    |> Enum.uniq()
  end

  defp coerce(:tags, value) when is_list(value), do: value
  defp coerce(:tags, _value), do: []

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
    |> put_ca_bundle(params["ca_bundle"])
  end

  # Public certificate material, so no fernet — but deliberately NOT in
  # @editable_fields: that list is what safe_audit_detail copies VERBATIM into
  # the audit row, and a PEM blob has no business there (invariant 3, and the
  # retired stack's own rule: ca_bundle is recorded by name only).
  #
  # Unlike the secrets above it, an empty value CLEARS rather than keeps: the
  # edit form can show a CA bundle (it is not a secret), so submitting it empty
  # is a deliberate removal, not the "I did not retype my password" case.
  defp put_ca_bundle(changes, nil), do: changes
  defp put_ca_bundle(changes, ""), do: Map.put(changes, :ca_bundle, nil)
  defp put_ca_bundle(changes, value), do: Map.put(changes, :ca_bundle, value)

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
