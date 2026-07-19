defmodule OrbitWeb.Components.CommentEditor do
  @moduledoc """
  Inline editable operator comment for list rows (EntityCommentBadge parity)
  — a pencil that opens a small popover with a textarea; save writes, an
  empty save clears. Two backends behind one UI:

    * `kind: "notes"` → the instance's own `notes` column (the Instances
      list; matches the old InstanceNotesBadge).
    * `kind` in `#{inspect(Orbit.Comments.EntityComment.kinds())}` →
      an `entity_comments` row keyed (instance_id, kind, entity_key)
      (VPN tunnels = "ipsec", connectivity monitors = "connectivity", …).

  Every mutation re-resolves the instance through the caller's scope
  (invariant 1 — the ids come from the DOM) and is write-gated + audited.
  The host LiveView wires the two events to `save/2` and `clear/2` and
  refreshes its comment lookup.
  """

  use Phoenix.Component

  alias Orbit.Auth.Scope

  attr :text, :string, default: nil, doc: "current comment, nil/\"\" = none"
  attr :writable, :boolean, required: true
  attr :instance_id, :integer, required: true
  attr :kind, :string, required: true
  attr :entity_key, :string, default: ""

  def comment_editor(assigns) do
    ~H"""
    <span
      :if={not @writable and present?(@text)}
      title={@text}
      class="ml-1 cursor-help align-text-bottom text-warning/80"
    >
      <.pencil filled={true} />
    </span>
    <details
      :if={@writable}
      id={dom_id(@instance_id, @kind, @entity_key)}
      phx-hook="CommentPop"
      class="ml-1 inline-block align-text-bottom [&_summary]:list-none [&_summary::-webkit-details-marker]:hidden"
    >
      <summary
        class={[
          "inline-flex cursor-pointer items-center rounded p-0.5 hover:bg-base-300",
          if(present?(@text), do: "text-warning/80", else: "text-base-content/40")
        ]}
        title={@text || "Add comment"}
      >
        <.pencil filled={present?(@text)} />
      </summary>
      <%!-- position:fixed (set by the CommentPop hook) so the panel escapes
           the list table's overflow-x-auto clip; starts hidden until placed. --%>
      <div
        data-cmt-panel
        class="fixed z-50 hidden w-64 rounded-lg border border-base-300 bg-base-200 p-2 shadow-xl"
      >
        <form phx-submit="comment_save">
          <input type="hidden" name="instance_id" value={@instance_id} />
          <input type="hidden" name="kind" value={@kind} />
          <input type="hidden" name="entity_key" value={@entity_key} />
          <textarea
            name="comment"
            rows="3"
            placeholder="Comment…"
            class="w-full rounded border border-base-content/20 bg-base-300 px-2 py-1 text-xs text-base-content focus:border-primary focus:outline-none"
          >{@text}</textarea>
          <div class="mt-1 flex items-center justify-end gap-1">
            <button
              :if={present?(@text)}
              type="button"
              phx-click="comment_clear"
              phx-value-instance_id={@instance_id}
              phx-value-kind={@kind}
              phx-value-entity_key={@entity_key}
              class="rounded border border-error/40 px-2 py-0.5 text-xs text-error hover:bg-error/15"
            >
              Clear
            </button>
            <button
              type="submit"
              class="rounded bg-primary px-2 py-0.5 text-xs text-white hover:bg-primary/80"
            >
              Save
            </button>
          </div>
        </form>
      </div>
    </details>
    """
  end

  defp pencil(assigns) do
    ~H"""
    <svg
      viewBox="0 0 24 24"
      fill={if @filled, do: "currentColor", else: "none"}
      stroke="currentColor"
      stroke-width="1.8"
      class="h-3.5 w-3.5"
    >
      <path
        stroke-linecap="round"
        stroke-linejoin="round"
        d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z"
      />
    </svg>
    """
  end

  defp present?(t), do: is_binary(t) and String.trim(t) != ""

  # id-safe key: entity_key may hold slashes/dots/colons.
  defp dom_id(instance_id, kind, entity_key) do
    "cmt-#{instance_id}-#{kind}-#{Base.encode16(entity_key, case: :lower)}"
  end

  # ---- shared handlers (called from the host LiveView) ---------------------

  @doc """
  Look up comments for a set of instances at once →
  `%{{instance_id, kind, entity_key} => %{comment, updated_by}}`. Instance
  notes ride the same map under `{id, "notes", ""}`.
  """
  def lookup(instances) when is_list(instances) do
    ids = Enum.map(instances, & &1.id)

    entity =
      case ids do
        [] ->
          %{}

        _ ->
          placeholders = Enum.map_join(ids, ", ", fn _ -> "?" end)

          Orbit.Repo.query!(
            "SELECT instance_id, kind, entity_key, comment, updated_by FROM entity_comments " <>
              "WHERE instance_id IN (#{placeholders})",
            ids
          ).rows
          |> Map.new(fn [iid, kind, ek, comment, by] ->
            {{iid, kind, ek}, %{comment: comment, updated_by: by}}
          end)
      end

    Enum.reduce(instances, entity, fn inst, acc ->
      if present?(inst.notes),
        do: Map.put(acc, {inst.id, "notes", ""}, %{comment: inst.notes, updated_by: nil}),
        else: acc
    end)
  rescue
    _ -> %{}
  end

  @doc "Comment text for one entity from a `lookup/1` map (nil when none)."
  def text(map, instance_id, kind, entity_key) do
    case Map.get(map, {instance_id, kind, entity_key}) do
      %{comment: c} -> c
      _ -> nil
    end
  end

  @doc "Handle a comment_save event; returns the (unchanged) socket."
  def save(socket, %{"instance_id" => raw, "kind" => kind} = params) do
    text = String.trim(params["comment"] || "")
    write(socket, raw, kind, params["entity_key"] || "", text)
  end

  @doc "Handle a comment_clear event."
  def clear(socket, %{"instance_id" => raw, "kind" => kind} = params) do
    write(socket, raw, kind, params["entity_key"] || "", "")
  end

  defp write(socket, raw_id, kind, entity_key, text) do
    user = socket.assigns.current_user

    with true <- user.role in ~w(admin user),
         {id, ""} <- Integer.parse(to_string(raw_id)),
         %Orbit.Instances.Instance{} = inst <- Scope.get_instance(id, user) do
      do_write(inst, user, kind, entity_key, text)
    end

    socket
  end

  # Instance notes column.
  defp do_write(inst, user, "notes", _ek, text) do
    Orbit.Instances.update_instance(inst, %{"notes" => text})
    audit(user, inst.id, if(text == "", do: "comment.delete", else: "comment.set"), "notes", "")
  end

  # EntityComment row.
  defp do_write(inst, user, kind, entity_key, "") do
    if Orbit.Comments.valid_kind?(kind) and Orbit.Comments.remove(inst.id, kind, entity_key),
      do: audit(user, inst.id, "comment.delete", kind, entity_key)
  end

  defp do_write(inst, user, kind, entity_key, text) do
    if Orbit.Comments.valid_kind?(kind) do
      Orbit.Comments.upsert(inst.id, kind, entity_key, text, user.username)
      audit(user, inst.id, "comment.set", kind, entity_key)
    end
  end

  defp audit(user, instance_id, action, kind, entity_key) do
    Orbit.Audit.write(
      action: action,
      result: "ok",
      user_id: user.id,
      target_type: "instance",
      target_id: instance_id,
      detail: %{"kind" => kind, "entity_key" => entity_key}
    )
  end
end
