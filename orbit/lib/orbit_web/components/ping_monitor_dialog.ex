defmodule OrbitWeb.Components.PingMonitorDialog do
  @moduledoc """
  The Phase-2 ping-monitor editor — one markup, used by the fleet VPN page and
  by an instance's own VPN tab.

  Extracted rather than copied: the detail page carried a condensed inline form
  per Phase-2 row instead, which was a second spelling of the same feature and
  offered no way to edit, disable or delete a monitor at all.

  The host LiveView owns the state and the events (`p2mon_change`, `p2mon_save`,
  `p2mon_cancel`, `p2mon_delete`, `p2mon_test`); this only draws them. `editor`
  is nil when the dialog is closed.

  Test runs a one-off ping on the CURRENT form values — via the agent where
  there is one, over SSH on a Securepoint (Orbit.Monitors.ping_test/4).
  """

  use Phoenix.Component

  attr :editor, :map, default: nil, doc: "nil = closed"
  attr :busy, :boolean, default: false, doc: "a Test is running"
  attr :result, :any, default: nil, doc: "{:ok | :error, message} of the last Test"

  def ping_monitor_dialog(assigns) do
    ~H"""
    <div
      :if={@editor}
      class="fixed inset-0 z-50 flex items-center justify-center bg-base-100/80 p-4"
    >
      <div class="w-full max-w-md rounded-lg border border-base-content/20 bg-base-200 p-5">
        <h3 class="text-sm font-medium text-base-content">
          {if @editor.monitor_id, do: "Edit ping monitor", else: "Add ping monitor"}
        </h3>
        <p class="mt-1 text-xs text-base-content/60">
          {@editor.instance_name} · {@editor.child_name}
          <span :if={@editor.local_ts != ""}>
            · {@editor.local_ts} ⇄ {@editor.remote_ts}
          </span>
        </p>

        <form phx-change="p2mon_change" phx-submit="p2mon_save" class="mt-4 space-y-3 text-sm">
          <label class="block text-xs text-base-content/60">
            Source IP (must be box-owned; blank = default route)
            <input
              name="mon[source]"
              value={@editor.source}
              class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-sm text-base-content"
            />
          </label>
          <label class="block text-xs text-base-content/60">
            Destination *
            <input
              name="mon[destination]"
              value={@editor.destination}
              required
              placeholder="host on the far side of the tunnel"
              class="mt-1 w-full rounded border border-base-content/20 bg-base-300 px-2 py-1.5 font-mono text-sm text-base-content"
            />
          </label>
          <div class="flex items-end gap-4">
            <label class="block text-xs text-base-content/60">
              Pings per cycle
              <input
                name="mon[ping_count]"
                value={@editor.ping_count}
                class="mt-1 w-20 rounded border border-base-content/20 bg-base-300 px-2 py-1.5 text-sm text-base-content"
              />
            </label>
            <label class="flex items-center gap-1.5 pb-1.5 text-xs text-base-content/70">
              <input
                type="checkbox"
                name="mon[enabled]"
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
              <button
                type="button"
                phx-click="p2mon_cancel"
                class="rounded border border-base-content/20 px-3 py-1.5 text-xs text-base-content/80 hover:bg-base-300"
              >
                Cancel
              </button>
              <button
                :if={@editor.monitor_id}
                type="button"
                phx-click="p2mon_delete"
                phx-value-id={@editor.monitor_id}
                phx-value-iid={@editor.instance_id}
                data-confirm="Remove this Phase-2 ping monitor?"
                class="rounded border border-error/40 px-3 py-1.5 text-xs text-error hover:bg-error/15"
              >
                Delete
              </button>
            </div>
            <div class="flex gap-2">
              <button
                type="button"
                phx-click="p2mon_test"
                disabled={@busy}
                class="rounded border border-info/40 px-3 py-1.5 text-xs text-info hover:bg-info/15 disabled:opacity-50"
              >
                {if @busy, do: "Testing…", else: "Test"}
              </button>
              <button
                type="submit"
                class="rounded bg-primary px-3 py-1.5 text-xs text-primary-content hover:bg-primary/80"
              >
                Save
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
    """
  end
end
