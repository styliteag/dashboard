defmodule OrbitWeb.SelectionLive do
  @moduledoc """
  Service-selection rules editor — the write surface over selection_rules
  (selection/routes.py port, admin-gated like the python routes). Flat
  rule table + add form instead of the react tree: same reach — every
  (consumer, category-or-full-key, global-or-instance, include/exclude)
  rule can be created and removed. Base default stays OFF; the checkmk
  consumer never offers availability (host up/down is checkmk's own).

  Per-instance rules scope-check the instance through get_instance
  (invariant 1); every write audits selection.rule.set/clear and reloads
  the routing cache so the notifier sees it immediately.
  """

  use OrbitWeb, :live_view

  alias Orbit.Audit
  alias Orbit.Auth.Scope
  alias Orbit.Selection

  @impl true
  def mount(_params, _session, socket) do
    {:ok, socket |> assign(error: nil) |> reload()}
  end

  defp reload(socket) do
    assign(socket,
      rules: Selection.list_rules(),
      instances: Orbit.Instances.list_visible(socket.assigns.current_user)
    )
  end

  @impl true
  def handle_event("add_rule", %{"rule" => params}, socket) do
    consumer = params["consumer"]
    selector = String.trim(params["selector_key"] || "")
    selector = if selector == "", do: params["selector"], else: selector
    mode = params["mode"]
    instance_id = parse_instance(params["instance_id"])

    cond do
      not Selection.valid_consumer?(consumer) ->
        {:noreply, assign(socket, error: "unknown consumer")}

      not Selection.valid_mode?(mode) ->
        {:noreply, assign(socket, error: "unknown mode")}

      not Selection.valid_selector?(consumer, selector) ->
        {:noreply, assign(socket, error: "selector must be a known category or family:key")}

      instance_id != nil and
          Scope.get_instance(instance_id, socket.assigns.current_user) == nil ->
        {:noreply, assign(socket, error: "unknown instance")}

      true ->
        Selection.set_rule(consumer, selector, mode, instance_id)

        audit(socket, "selection.rule.set", %{
          "name" => consumer,
          "mode" => mode,
          "kind" => selector
        })

        {:noreply, socket |> assign(error: nil) |> reload()}
    end
  end

  def handle_event("delete_rule", %{"consumer" => c, "selector" => s} = p, socket) do
    instance_id = parse_instance(p["instance_id"])
    Selection.delete_rule(c, s, instance_id)
    audit(socket, "selection.rule.clear", %{"name" => c, "kind" => s})
    {:noreply, socket |> assign(error: nil) |> reload()}
  end

  defp parse_instance(raw) do
    case Integer.parse(to_string(raw || "")) do
      {n, ""} -> n
      _ -> nil
    end
  end

  defp audit(socket, action, detail) do
    Audit.write(
      action: action,
      result: "ok",
      user_id: socket.assigns.current_user.id,
      detail: detail
    )
  end

  @impl true
  def render(assigns) do
    ~H"""
    <main class="min-h-screen bg-base-100 text-base-content">
      <.top_nav active={:settings} current_user={@current_user} />

      <section class="p-6">
        <div class="mb-4 flex items-center gap-3">
          <h1 class="flex items-center gap-2 text-lg font-medium text-base-content">
            <Icons.icon name={:list_checks} class="h-5 w-5 text-base-content/60" /> Selection rules
            <span class="ml-2 text-sm text-base-content/60">({length(@rules)})</span>
          </h1>
          <a href={~p"/settings"} class="text-xs text-base-content/60 hover:text-base-content/80">settings</a>
        </div>

        <p class="mb-4 max-w-3xl text-xs text-base-content/60">
          Routing for the checkmk export and the notification channels. Base default is OFF —
          a consumer only receives a check when an include rule matches; instance rules beat
          global ones, full keys (gateway:WAN) beat categories.
        </p>

        <div
          :if={@error}
          class="mb-4 max-w-3xl rounded border border-error/40 bg-error/10 p-2 text-sm text-error"
        >
          {@error}
        </div>

        <form
          phx-submit="add_rule"
          class="mb-6 flex max-w-4xl flex-wrap items-end gap-2 rounded-lg border border-base-300 bg-base-200 p-3 text-sm"
        >
          <label class="block">
            <span class="mb-1 block text-xs text-base-content/60">Consumer</span>
            <select name="rule[consumer]" class={input_cls()}>
              <option :for={c <- Selection.consumers()} value={c}>{c}</option>
            </select>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-base-content/60">Category</span>
            <select name="rule[selector]" class={input_cls()}>
              <option :for={c <- Selection.categories_for("mattermost")} value={c}>{c}</option>
            </select>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-base-content/60">…or full key (overrides)</span>
            <input name="rule[selector_key]" placeholder="gateway:WAN" class={input_cls()} />
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-base-content/60">Instance (blank = global)</span>
            <select name="rule[instance_id]" class={input_cls()}>
              <option value="">— global —</option>
              <option :for={i <- @instances} value={i.id}>{i.name}</option>
            </select>
          </label>
          <label class="block">
            <span class="mb-1 block text-xs text-base-content/60">Mode</span>
            <select name="rule[mode]" class={input_cls()}>
              <option value="include">include</option>
              <option value="exclude">exclude</option>
            </select>
          </label>
          <button
            type="submit"
            class="rounded bg-primary px-3 py-1.5 text-xs text-white hover:bg-primary/80"
          >
            Set rule
          </button>
        </form>

        <table class="w-full max-w-4xl text-left text-sm">
          <thead class="text-base-content/60">
            <tr class="border-b border-base-300">
              <th class="py-2 pr-4 font-medium">Consumer</th>
              <th class="py-2 pr-4 font-medium">Selector</th>
              <th class="py-2 pr-4 font-medium">Scope</th>
              <th class="py-2 pr-4 font-medium">Mode</th>
              <th class="py-2 font-medium"></th>
            </tr>
          </thead>
          <tbody>
            <tr :for={r <- @rules} class="border-b border-base-300/50">
              <td class="py-2 pr-4 text-base-content/80">{r.consumer}</td>
              <td class="py-2 pr-4 font-mono text-xs text-base-content/80">{r.selector}</td>
              <td class="py-2 pr-4 text-base-content/70">
                {r.instance_name || (r.instance_id && "##{r.instance_id}") || "global"}
              </td>
              <td class="py-2 pr-4">
                <span class={
                  if(r.mode == "include",
                    do: "text-primary",
                    else: "text-error"
                  )
                }>
                  {r.mode}
                </span>
              </td>
              <td class="py-2 text-right">
                <button
                  phx-click="delete_rule"
                  phx-value-consumer={r.consumer}
                  phx-value-selector={r.selector}
                  phx-value-instance_id={r.instance_id}
                  class="rounded border border-base-content/20 px-2 py-0.5 text-xs text-base-content/70 hover:bg-base-300"
                >
                  remove
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
    """
  end

  defp input_cls do
    "rounded border border-base-content/20 bg-base-100 p-1.5 text-sm text-base-content"
  end
end
