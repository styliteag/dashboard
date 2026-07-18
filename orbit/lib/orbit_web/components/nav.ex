defmodule OrbitWeb.Components.Nav do
  @moduledoc """
  Shared top navigation for every authenticated LiveView. Centralises the link
  set and active-page highlight so no page is unreachable and the bar is
  identical everywhere (each LiveView used to hardcode its own partial nav —
  the Hub page had none at all). Admin-only links (Settings, Audit) are hidden
  for non-admins per the frontend role-hiding rule; the backend still enforces.
  """

  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: OrbitWeb.Endpoint,
    router: OrbitWeb.Router,
    statics: OrbitWeb.static_paths()

  attr :active, :atom, default: nil, doc: "the current page key, e.g. :alerts"
  attr :current_user, :map, required: true

  def top_nav(assigns) do
    ~H"""
    <header class="flex items-center justify-between border-b border-slate-800 bg-slate-900 px-6 py-3">
      <div class="flex items-center gap-4">
        <a href={~p"/"} class="font-semibold text-slate-100">STYLiTE Orbit</a>
        <nav class="flex flex-wrap gap-3 text-sm text-slate-400">
          <.nav_link active={@active} key={:instances} href={~p"/instances"} label="Instances" />
          <.nav_link active={@active} key={:hub} href={~p"/hub"} label="Hub" />
          <.nav_link active={@active} key={:alerts} href={~p"/alerts"} label="Alerts" />
          <.nav_link
            active={@active}
            key={:connectivity}
            href={~p"/connectivity"}
            label="Connectivity"
          />
          <.nav_link active={@active} key={:vpn} href={~p"/vpn"} label="VPN" />
          <.nav_link active={@active} key={:certificates} href={~p"/certificates"} label="Certs" />
          <.nav_link active={@active} key={:firmware} href={~p"/firmware"} label="Firmware" />
          <.nav_link active={@active} key={:logs} href={~p"/logs"} label="Logs" />
          <.nav_link
            :if={admin?(@current_user)}
            active={@active}
            key={:settings}
            href={~p"/settings"}
            label="Settings"
          />
          <.nav_link
            :if={admin?(@current_user) or superadmin?(@current_user)}
            active={@active}
            key={:audit}
            href={~p"/audit"}
            label="Audit"
          />
          <.nav_link
            :if={superadmin?(@current_user)}
            active={@active}
            key={:users}
            href={~p"/users"}
            label="Users"
          />
          <.nav_link
            :if={superadmin?(@current_user)}
            active={@active}
            key={:groups}
            href={~p"/groups"}
            label="Groups"
          />
          <.nav_link
            :if={superadmin?(@current_user)}
            active={@active}
            key={:access_control}
            href={~p"/access-control"}
            label="Access"
          />
        </nav>
      </div>
      <div class="flex items-center gap-3 text-sm">
        <.nav_link active={@active} key={:security} href={~p"/security"} label="Security" />
        <a href={~p"/password"} class="text-slate-400 hover:text-slate-200" title="Change password">
          {@current_user.username}
        </a>
        <form action={~p"/logout"} method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <button
            type="submit"
            class="rounded-md border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:bg-slate-800"
          >
            Sign out
          </button>
        </form>
        <%!-- Version tag (VersionFooter parity, compacted into the nav —
             every page shares this header, no separate footer needed). --%>
        <span class="text-xs text-slate-600" title="Orbit version">v{app_version()}</span>
      </div>
    </header>
    """
  end

  defp app_version, do: Application.spec(:orbit, :vsn) |> to_string()

  attr :active, :atom, required: true
  attr :key, :atom, required: true
  attr :href, :string, required: true
  attr :label, :string, required: true

  defp nav_link(assigns) do
    ~H"""
    <a href={@href} class={["hover:text-slate-200", @active == @key && "text-slate-200"]}>
      {@label}
    </a>
    """
  end

  defp admin?(%{role: "admin"}), do: true
  defp admin?(_), do: false

  defp superadmin?(%{is_superadmin: true}), do: true
  defp superadmin?(_), do: false
end
