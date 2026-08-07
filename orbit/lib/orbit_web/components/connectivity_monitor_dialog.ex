defmodule OrbitWeb.Components.ConnectivityMonitorDialog do
  @moduledoc """
  Editor for a standalone connectivity monitor — the same shape as the Phase-2
  ping dialog, so both monitor kinds are configured the same way.

  Replaces an inline "add" form plus two row buttons that could only create,
  toggle and delete: a destination could not be corrected without deleting the
  monitor, which also threw away its history and its `connectivity:<id>` check
  key.

  The host LiveView owns the state and the events (`conn_change`, `conn_save`,
  `conn_cancel`, `conn_delete`, `conn_test`); this only draws them. `editor` is
  nil when the dialog is closed.
  """

  use Phoenix.Component

  import OrbitWeb.CoreComponents, only: [btn: 1]

  attr :editor, :map, default: nil, doc: "nil = closed"
  attr :busy, :boolean, default: false, doc: "a Test is running"
  attr :result, :any, default: nil, doc: "{:ok | :error, message} of the last Test"

  def connectivity_monitor_dialog(assigns) do
    ~H"""
    <div
      :if={@editor}
      class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
    >
      <div class="w-full max-w-md rounded-lg border border-base-content/20 bg-base-200 p-5">
        <h3 class="text-sm font-medium text-base-content">
          {if @editor.monitor_id, do: "Edit connectivity monitor", else: "Add connectivity monitor"}
        </h3>
        <p class="mt-1 text-xs text-base-content/70">
          {@editor.instance_name} · pinged from the box on every cycle
        </p>

        <form phx-change="conn_change" phx-submit="conn_save" class="mt-4 space-y-3 text-sm">
          <label class="block text-xs text-base-content/70">
            Name *
            <input
              name="monitor[name]"
              value={@editor.name}
              required
              class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
            />
          </label>
          <label class="block text-xs text-base-content/70">
            Source IP (must be box-owned; blank = default route)
            <input
              name="monitor[source]"
              value={@editor.source}
              class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-sm text-base-content"
            />
          </label>
          <label class="block text-xs text-base-content/70">
            Destination *
            <input
              name="monitor[destination]"
              value={@editor.destination}
              required
              placeholder="host or IP to ping"
              class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-sm text-base-content"
            />
          </label>
          <div class="flex items-end gap-4">
            <label class="block text-xs text-base-content/70">
              Pings per cycle
              <input
                name="monitor[ping_count]"
                value={@editor.ping_count}
                class="mt-1 w-20 rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
              />
            </label>
            <label class="flex items-center gap-1.5 pb-1.5 text-xs text-base-content/70">
              <input
                type="checkbox"
                name="monitor[enabled]"
                value="true"
                checked={@editor.enabled}
                class="accent-primary"
              /> Enabled
            </label>
          </div>

          <div
            :if={@result}
            class={[
              "rounded px-3 py-2 text-xs",
              case @result do
                {:ok, _} -> "bg-primary/15 text-primary"
                _ -> "bg-error/15 text-error"
              end
            ]}
          >
            Test: {elem(@result, 1)}
          </div>

          <div class="flex items-center justify-between pt-2">
            <div class="flex gap-2">
              <.btn type="button" phx-click="conn_cancel">
                Cancel
              </.btn>
              <.btn
                :if={@editor.monitor_id}
                variant={:danger}
                type="button"
                phx-click="conn_delete"
                phx-value-id={@editor.monitor_id}
                data-confirm="Delete this connectivity monitor?"
              >
                Delete
              </.btn>
            </div>
            <div class="flex gap-2">
              <.btn type="button" phx-click="conn_test" disabled={@busy}>
                {if @busy, do: "Testing…", else: "Test"}
              </.btn>
              <.btn variant={:primary} type="submit">
                Save
              </.btn>
            </div>
          </div>
        </form>
      </div>
    </div>
    """
  end
end
