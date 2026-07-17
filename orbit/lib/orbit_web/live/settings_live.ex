defmodule OrbitWeb.SettingsLive do
  @moduledoc """
  Editable settings (admin-only, config surface). Shows every whitelisted key
  with its effective value + env default; a form per key writes a DB override
  via Orbit.Settings.set_override (validated by the registry), or clears it
  back to the default. First mutating LiveView — the form pattern the rest of
  the admin surfaces reuse.

  Admin gate is the on_mount hook (require_admin); the write itself is
  re-validated in the context, so a crafted request can't set a bad value.
  """

  use OrbitWeb, :live_view

  alias Orbit.Settings
  alias Orbit.Settings.Registry

  @impl true
  def mount(_params, _session, socket) do
    {:ok, assign(socket, rows: load_rows(), flash_key: nil)}
  end

  @impl true
  def handle_event("save", %{"key" => key, "value" => value}, socket) do
    case Settings.set_override(key, value) do
      {:ok, _} ->
        {:noreply, socket |> assign(rows: load_rows()) |> put_flash(:info, "#{key} saved")}

      {:error, msg} ->
        {:noreply, put_flash(socket, :error, msg)}
    end
  end

  def handle_event("clear", %{"key" => key}, socket) do
    Settings.clear_override(key)
    {:noreply, socket |> assign(rows: load_rows()) |> put_flash(:info, "#{key} reset to default")}
  end

  defp load_rows do
    Registry.editable()
    |> Map.values()
    |> Enum.sort_by(& &1.key)
    |> Enum.map(fn defn ->
      %{
        key: defn.key,
        type: defn.type,
        default: System.get_env(defn.env, defn.default),
        effective: to_string(Settings.effective(defn.key))
      }
    end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-slate-950 text-slate-100">
      <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
        <div class="flex items-center gap-3">
          <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
          <nav class="flex gap-3 text-sm text-slate-400">
            <a href={~p"/instances"} class="hover:text-slate-200">Instances</a>
            <a href={~p"/settings"} class="text-slate-200">Settings</a>
          </nav>
        </div>
        <span class="text-sm text-slate-400">{@current_user.username}</span>
      </header>

      <section class="p-6">
        <h1 class="mb-4 text-lg font-medium text-slate-200">Settings</h1>

        <p
          :if={@flash[:info]}
          class="mb-3 rounded-md border border-emerald-800 bg-emerald-950 px-3 py-2 text-sm text-emerald-300"
        >
          {@flash[:info]}
        </p>
        <p
          :if={@flash[:error]}
          class="mb-3 rounded-md border border-red-800 bg-red-950 px-3 py-2 text-sm text-red-300"
        >
          {@flash[:error]}
        </p>

        <table class="w-full text-left text-sm">
          <thead class="text-slate-500">
            <tr class="border-b border-slate-800">
              <th class="py-2 pr-4 font-medium">Key</th>
              <th class="py-2 pr-4 font-medium">Effective</th>
              <th class="py-2 pr-4 font-medium">Default</th>
              <th class="py-2 pr-4 font-medium">Set</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rows} class="border-b border-slate-800/50">
              <td class="py-2 pr-4 text-slate-200">{r.key}</td>
              <td class="py-2 pr-4 text-emerald-300">{r.effective}</td>
              <td class="py-2 pr-4 text-slate-500">{r.default}</td>
              <td class="py-2 pr-4">
                <form phx-submit="save" class="flex items-center gap-2">
                  <input type="hidden" name="key" value={r.key} />
                  <input
                    type="text"
                    name="value"
                    value={r.effective}
                    class="w-24 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100 focus:border-emerald-500 focus:outline-none"
                  />
                  <button
                    type="submit"
                    class="rounded bg-emerald-700 px-2 py-1 text-xs text-white hover:bg-emerald-600"
                  >
                    Save
                  </button>
                  <button
                    type="button"
                    phx-click="clear"
                    phx-value-key={r.key}
                    class="rounded border border-slate-700 px-2 py-1 text-xs text-slate-400 hover:bg-slate-800"
                  >
                    Reset
                  </button>
                </form>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end
end
