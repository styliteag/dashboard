defmodule OrbitWeb.ApiKeysLive do
  @moduledoc """
  Machine api-key management UI over Orbit.ApiKeys (apikeys/routes.py
  parity, admin-or-superadmin gate like the python routes). The minted
  token renders exactly once after create; reveal answers the same
  \"not revealable\" for every refusal reason (no oracle). Revoke is soft
  and drops the recoverable copy; purge requires a prior revoke. Every
  action audits.
  """

  use OrbitWeb, :live_view

  alias Orbit.ApiKeys
  alias Orbit.Audit

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(error: nil, minted: nil, revealed: nil, show_create: false)
     |> reload()}
  end

  defp reload(socket), do: assign(socket, keys: ApiKeys.list(), groups: all_groups())

  defp all_groups, do: Orbit.Repo.all(Orbit.Accounts.Group) |> Enum.sort_by(& &1.name)

  @impl true
  def handle_event("toggle_create", _p, socket) do
    {:noreply, assign(socket, show_create: not socket.assigns.show_create, error: nil)}
  end

  def handle_event("create_key", %{"key" => params}, socket) do
    params = Map.put(params, "group_ids", for({"group_" <> gid, "true"} <- params, do: gid))

    case ApiKeys.create(params, socket.assigns.current_user) do
      {:ok, minted} ->
        audit(socket, "apikey.create", minted.id, %{
          "name" => params["name"],
          "revealable" => params["revealable"] == "true",
          "group_ids" => minted.group_ids
        })

        {:noreply, socket |> assign(minted: minted, show_create: false, error: nil) |> reload()}

      {:error, reason} ->
        {:noreply, assign(socket, error: error_text(reason))}
    end
  end

  def handle_event("revoke", %{"id" => raw}, socket) do
    id = String.to_integer(raw)
    ApiKeys.revoke(id)
    audit(socket, "apikey.revoke", id, nil)
    {:noreply, socket |> assign(error: nil, revealed: nil) |> reload()}
  end

  def handle_event("purge", %{"id" => raw}, socket) do
    id = String.to_integer(raw)

    case ApiKeys.purge(id) do
      :ok ->
        audit(socket, "apikey.delete", id, nil)
        {:noreply, socket |> assign(error: nil) |> reload()}

      {:error, :not_revoked} ->
        {:noreply,
         assign(socket, error: "revoke the key first — purge removes only revoked keys")}
    end
  end

  def handle_event("reveal", %{"id" => raw}, socket) do
    id = String.to_integer(raw)

    case ApiKeys.reveal(id, socket.assigns.current_user) do
      nil ->
        {:noreply, assign(socket, error: "not revealable", revealed: nil)}

      token ->
        audit(socket, "apikey.reveal", id, nil)
        {:noreply, assign(socket, revealed: {id, token}, error: nil)}
    end
  end

  def handle_event("hide_secrets", _p, socket) do
    {:noreply, assign(socket, minted: nil, revealed: nil)}
  end

  defp audit(socket, action, target_id, detail) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      target_type: "apikey",
      target_id: target_id,
      detail: detail
    )
  end

  defp error_text(:name_required), do: "name is required"

  defp error_text(:binding_required),
    do: "a group-scoped admin must bind the key to at least one of his groups"

  defp error_text(:not_a_member), do: "not a member of the target group(s)"
  defp error_text(:unknown_group), do: "unknown group"

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:settings} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:password} class="h-5 w-5 text-base-content/60" /> API keys
            <span class="ml-2 text-sm text-base-content/60">({length(@keys)})</span>
          </h1>
          <button
            phx-click="toggle_create"
            class="rounded bg-primary px-2 py-1 text-xs text-primary-content hover:bg-primary/80"
          >
            {if @show_create, do: "Cancel", else: "New key"}
          </button>
        </div>

        <p class="mb-4 max-w-3xl text-xs text-base-content/60">
          Read-only machine keys (Checkmk/Prometheus scrapes). A key without group bindings is
          GLOBAL — minting one is superadmin-only; group admins must bind to their own groups.
        </p>

        <div
          :if={@error}
          class="mb-4 max-w-3xl rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <div
          :if={@minted}
          class="mb-4 max-w-3xl rounded border border-primary/40 bg-primary/10 p-3 text-sm"
        >
          <div class="mb-1 text-primary">
            Key created — copy it NOW, it is shown only once:
          </div>
          <code class="break-all font-mono text-xs text-primary">{@minted.token}</code>
          <button
            phx-click="hide_secrets"
            class="ml-3 text-xs text-base-content/70 hover:text-base-content"
          >
            dismiss
          </button>
        </div>

        <div
          :if={@revealed}
          class="mb-4 max-w-3xl rounded border border-warning/40 bg-warning/10 p-3 text-sm"
        >
          <div class="mb-1 text-warning">Revealed key #{elem(@revealed, 0)}:</div>
          <code class="break-all font-mono text-xs text-warning">{elem(@revealed, 1)}</code>
          <button
            phx-click="hide_secrets"
            class="ml-3 text-xs text-base-content/70 hover:text-base-content"
          >
            dismiss
          </button>
        </div>

        <form
          :if={@show_create}
          phx-submit="create_key"
          class="mb-6 max-w-3xl rounded-lg border border-base-300 bg-base-200 p-4 text-sm"
        >
          <div class="grid gap-3 md:grid-cols-2">
            <label class="block">
              <span class="mb-1 block text-xs text-base-content/60">Name</span>
              <input name="key[name]" required class={input_cls()} />
            </label>
            <label class="block">
              <span class="mb-1 block text-xs text-base-content/60">Purpose (optional)</span>
              <input name="key[purpose]" class={input_cls()} />
            </label>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-4 text-base-content/80">
            <label class="flex items-center gap-2">
              <input type="hidden" name="key[revealable]" value="false" />
              <input
                type="checkbox"
                name="key[revealable]"
                value="true"
                class="accent-primary"
              /> revealable (stores an encrypted copy until revoke)
            </label>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-4 text-base-content/80">
            <span class="text-xs text-base-content/60">Bind to groups:</span>
            <label :for={g <- @groups} class="flex items-center gap-1.5">
              <input
                type="checkbox"
                name={"key[group_#{g.id}]"}
                value="true"
                class="accent-primary"
              />
              {g.name}
            </label>
          </div>
          <button
            type="submit"
            class="mt-3 rounded bg-primary px-3 py-1 text-xs text-primary-content hover:bg-primary/80"
          >
            Mint key
          </button>
        </form>

        <table class="w-full max-w-4xl text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-2 pr-4 font-medium">Key</th>
              <th class="py-2 pr-4 font-medium">Groups</th>
              <th class="py-2 pr-4 font-medium">Last used</th>
              <th class="py-2 pr-4 font-medium">Status</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={k <- @keys} class="border-b border-base-300/50">
              <td class="py-2 pr-4">
                <span class="font-mono text-xs text-base-content/80">{k.prefix}…</span>
                <span class="ml-2 text-base-content">{k.name}</span>
                <span :if={k.purpose} class="ml-2 text-xs text-base-content/60">({k.purpose})</span>
              </td>
              <td class="py-2 pr-4 text-base-content/70">
                {if k.groups == [],
                  do: "GLOBAL",
                  else: k.groups |> Enum.map(& &1.name) |> Enum.join(", ")}
              </td>
              <td class="py-2 pr-4 text-base-content/70">{ts(k.last_used_at)}</td>
              <td class="py-2 pr-4">
                <span
                  :if={k.revoked_at}
                  class="rounded bg-error/20 px-1.5 py-0.5 text-xs text-error"
                >
                  revoked
                </span>
                <span :if={is_nil(k.revoked_at)} class="text-primary">active</span>
              </td>
              <td class="py-2 text-right">
                <button
                  :if={is_nil(k.revoked_at) and k.revealable}
                  phx-click="reveal"
                  phx-value-id={k.id}
                  class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
                >
                  reveal
                </button>
                <button
                  :if={is_nil(k.revoked_at)}
                  phx-click="revoke"
                  phx-value-id={k.id}
                  data-confirm={"Revoke key #{k.name}? Scrapes using it stop working."}
                  class="ml-1 rounded border border-warning/40 px-2 py-0.5 text-xs text-warning hover:bg-warning/10"
                >
                  revoke
                </button>
                <button
                  :if={k.revoked_at}
                  phx-click="purge"
                  phx-value-id={k.id}
                  data-confirm={"Purge key #{k.name} permanently?"}
                  class="ml-1 rounded border border-error/40 px-2 py-0.5 text-xs text-error hover:bg-error/15"
                >
                  purge
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp ts(nil), do: "never"
  defp ts(dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")

  defp input_cls do
    "w-full rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end
end
