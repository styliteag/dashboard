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
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <.top_nav active={:settings} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="text-lg font-medium text-slate-200">
            API keys <span class="ml-2 text-sm text-slate-500">({length(@keys)})</span>
          </h1>
          <button
            phx-click="toggle_create"
            class="rounded bg-emerald-700 px-2 py-1 text-xs text-white hover:bg-emerald-600"
          >
            {if @show_create, do: "Cancel", else: "New key"}
          </button>
        </div>

        <p class="mb-4 max-w-3xl text-xs text-slate-500">
          Read-only machine keys (Checkmk/Prometheus scrapes). A key without group bindings is
          GLOBAL — minting one is superadmin-only; group admins must bind to their own groups.
        </p>

        <div
          :if={@error}
          class="mb-4 max-w-3xl rounded border border-red-800 bg-red-950/50 p-2 text-sm text-red-300"
        >
          {@error}
        </div>

        <div
          :if={@minted}
          class="mb-4 max-w-3xl rounded border border-emerald-800 bg-emerald-950/40 p-3 text-sm"
        >
          <div class="mb-1 text-emerald-300">
            Key created — copy it NOW, it is shown only once:
          </div>
          <code class="break-all font-mono text-xs text-emerald-200">{@minted.token}</code>
          <button phx-click="hide_secrets" class="ml-3 text-xs text-slate-400 hover:text-slate-200">
            dismiss
          </button>
        </div>

        <div
          :if={@revealed}
          class="mb-4 max-w-3xl rounded border border-amber-800 bg-amber-950/40 p-3 text-sm"
        >
          <div class="mb-1 text-amber-300">Revealed key #{elem(@revealed, 0)}:</div>
          <code class="break-all font-mono text-xs text-amber-200">{elem(@revealed, 1)}</code>
          <button phx-click="hide_secrets" class="ml-3 text-xs text-slate-400 hover:text-slate-200">
            dismiss
          </button>
        </div>

        <form
          :if={@show_create}
          phx-submit="create_key"
          class="mb-6 max-w-3xl rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm"
        >
          <div class="grid gap-3 md:grid-cols-2">
            <label class="block">
              <span class="mb-1 block text-xs text-slate-500">Name</span>
              <input name="key[name]" required class={input_cls()} />
            </label>
            <label class="block">
              <span class="mb-1 block text-xs text-slate-500">Purpose (optional)</span>
              <input name="key[purpose]" class={input_cls()} />
            </label>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-4 text-slate-300">
            <label class="flex items-center gap-2">
              <input type="hidden" name="key[revealable]" value="false" />
              <input
                type="checkbox"
                name="key[revealable]"
                value="true"
                class="accent-emerald-600"
              /> revealable (stores an encrypted copy until revoke)
            </label>
          </div>
          <div class="mt-3 flex flex-wrap items-center gap-4 text-slate-300">
            <span class="text-xs text-slate-500">Bind to groups:</span>
            <label :for={g <- @groups} class="flex items-center gap-1.5">
              <input
                type="checkbox"
                name={"key[group_#{g.id}]"}
                value="true"
                class="accent-emerald-600"
              />
              {g.name}
            </label>
          </div>
          <button
            type="submit"
            class="mt-3 rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600"
          >
            Mint key
          </button>
        </form>

        <table class="w-full max-w-4xl text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Key</th>
              <th class="py-2 pr-4 font-medium">Groups</th>
              <th class="py-2 pr-4 font-medium">Last used</th>
              <th class="py-2 pr-4 font-medium">Status</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={k <- @keys} class="border-b border-slate-800/50">
              <td class="py-2 pr-4">
                <span class="font-mono text-xs text-slate-300">{k.prefix}…</span>
                <span class="ml-2 text-slate-200">{k.name}</span>
                <span :if={k.purpose} class="ml-2 text-xs text-slate-500">({k.purpose})</span>
              </td>
              <td class="py-2 pr-4 text-slate-400">
                {if k.groups == [],
                  do: "GLOBAL",
                  else: k.groups |> Enum.map(& &1.name) |> Enum.join(", ")}
              </td>
              <td class="py-2 pr-4 text-slate-400">{ts(k.last_used_at)}</td>
              <td class="py-2 pr-4">
                <span
                  :if={k.revoked_at}
                  class="rounded bg-red-900/60 px-1.5 py-0.5 text-xs text-red-300"
                >
                  revoked
                </span>
                <span :if={is_nil(k.revoked_at)} class="text-emerald-400">active</span>
              </td>
              <td class="py-2 text-right">
                <button
                  :if={is_nil(k.revoked_at) and k.revealable}
                  phx-click="reveal"
                  phx-value-id={k.id}
                  class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-400 hover:bg-slate-800"
                >
                  reveal
                </button>
                <button
                  :if={is_nil(k.revoked_at)}
                  phx-click="revoke"
                  phx-value-id={k.id}
                  data-confirm={"Revoke key #{k.name}? Scrapes using it stop working."}
                  class="ml-1 rounded border border-amber-800 px-2 py-0.5 text-xs text-amber-400 hover:bg-amber-950"
                >
                  revoke
                </button>
                <button
                  :if={k.revoked_at}
                  phx-click="purge"
                  phx-value-id={k.id}
                  data-confirm={"Purge key #{k.name} permanently?"}
                  class="ml-1 rounded border border-red-900 px-2 py-0.5 text-xs text-red-400 hover:bg-red-950"
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
    "w-full rounded border border-slate-700 bg-slate-950 p-1.5 text-sm text-slate-200"
  end
end
