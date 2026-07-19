defmodule OrbitWeb.Components.Nav do
  @moduledoc """
  Shared top navigation for every authenticated LiveView. Centralises the link
  set and active-page highlight so no page is unreachable and the bar is
  identical everywhere (each LiveView used to hardcode its own partial nav —
  the Hub page had none at all). Links are hidden along three axes, per the
  frontend role-hiding rule — the routes and the scoping still enforce:

  - role: Settings/Hub admin-only, Audit admin-or-superadmin,
    Users/Groups/Access superadmin-only;
  - group membership: the instance-data links vanish for an account that
    would see zero instances (see `instance_data?/1`);
  - never security: everything here is cosmetics on top of the real gates.
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
    <header class="flex items-center justify-between border-b border-base-300 bg-base-200 px-6 py-3">
      <div class="flex items-center gap-4">
        <a href={~p"/"} class="flex items-center gap-2 font-semibold text-base-content">
          <.nav_icon name={:brand} class="h-5 w-5 text-primary" /> STYLiTE Orbit
        </a>
        <nav class="flex flex-wrap gap-3 text-sm text-base-content/70">
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:instances}
            href={~p"/instances"}
            label="Instances"
          />
          <.nav_link
            :if={admin?(@current_user)}
            active={@active}
            key={:hub}
            href={~p"/hub"}
            label="Hub"
          />
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:alerts}
            href={~p"/alerts"}
            label="Alerts"
          />
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:connectivity}
            href={~p"/connectivity"}
            label="Connectivity"
          />
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:vpn}
            href={~p"/vpn"}
            label="VPN"
          />
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:certificates}
            href={~p"/certificates"}
            label="Certs"
          />
          <.nav_link
            :if={instance_data?(@current_user)}
            active={@active}
            key={:firmware}
            href={~p"/firmware"}
            label="Firmware"
          />
          <%!-- Logs needs BOTH gates: admin-only content (invariant 4), and
                the list is per visible instance, so a group-less admin still
                gets an empty page. --%>
          <.nav_link
            :if={admin?(@current_user) and instance_data?(@current_user)}
            active={@active}
            key={:logs}
            href={~p"/logs"}
            label="Logs"
          />
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
        <a
          href={~p"/password"}
          class="flex items-center gap-1.5 text-base-content/70 hover:text-base-content"
          title="Change password"
        >
          <.nav_icon name={:password} class="h-3.5 w-3.5" />
          {@current_user.username}
        </a>
        <.theme_switcher />
        <form action={~p"/logout"} method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <button
            type="submit"
            class="flex items-center gap-1.5 rounded-md border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            <.nav_icon name={:signout} class="h-3.5 w-3.5" /> Sign out
          </button>
        </form>
        <%!-- Version tag (VersionFooter parity, compacted into the nav —
             every page shares this header, no separate footer needed). --%>
        <span class="text-xs text-base-content/40" title="Orbit version">v{app_version()}</span>
      </div>
    </header>
    """
  end

  defp app_version, do: Application.spec(:orbit, :vsn) |> to_string()

  @doc """
  Design/mode switcher (OrbitWeb.Design): plain POST forms, server-side
  cookies. The active choice is marked CLIENT-side from the html element's
  data-theme (see markThemeChoices in app.js) — LiveViews don't carry the
  design conn assigns, and the DOM attribute is the single truth anyway.
  """
  def theme_switcher(assigns) do
    ~H"""
    <details class="relative text-xs">
      <summary
        class="cursor-pointer rounded-md border border-base-content/20 px-2 py-1 text-base-content/70 hover:bg-base-300 hover:text-base-content"
        title="Theme"
      >
        Theme
      </summary>
      <div class="absolute right-0 top-8 z-50 w-44 rounded-lg border border-base-300 bg-base-200 p-2 shadow-xl">
        <p class="mb-1 px-1 text-[10px] uppercase tracking-wide text-base-content/50">Design</p>
        <form :for={d <- OrbitWeb.Design.all()} action="/design" method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <input type="hidden" name="design" value={d} />
          <button data-theme-design={d} class="w-full rounded px-2 py-1 text-left hover:bg-base-300">
            {OrbitWeb.Design.name(d)}
          </button>
        </form>
        <p class="mb-1 mt-2 px-1 text-[10px] uppercase tracking-wide text-base-content/50">Mode</p>
        <div class="flex gap-1">
          <form
            :for={m <- OrbitWeb.Design.modes()}
            action="/design/mode"
            method="post"
            class="flex-1"
          >
            <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
            <input type="hidden" name="mode" value={m} />
            <button data-theme-mode={m} class="w-full rounded px-2 py-1 hover:bg-base-300">
              {OrbitWeb.Design.mode_name(m)}
            </button>
          </form>
          <form action="/design/mode" method="post" class="flex-1">
            <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
            <input type="hidden" name="mode" value="" />
            <button
              class="w-full rounded px-2 py-1 hover:bg-base-300"
              title="Use the design's native mode"
            >
              Auto
            </button>
          </form>
        </div>
      </div>
    </details>
    """
  end

  attr :active, :atom, required: true
  attr :key, :atom, required: true
  attr :href, :string, required: true
  attr :label, :string, required: true

  defp nav_link(assigns) do
    ~H"""
    <a
      href={@href}
      class={[
        "flex items-center gap-1.5 rounded-md px-2 py-1",
        if(@active == @key,
          do: "bg-base-300 font-medium text-primary",
          else: "text-base-content/70 hover:bg-base-300/60 hover:text-base-content"
        )
      ]}
    >
      <.nav_icon name={@key} />
      {@label}
    </a>
    """
  end

  @doc "Nav icon — thin wrapper over the shared Icons catalog (page keys)."
  attr :name, :atom, required: true
  attr :class, :string, default: "h-4 w-4"

  def nav_icon(assigns), do: OrbitWeb.Components.Icons.icon(assigns)

  defp admin?(%{role: "admin"}), do: true
  defp admin?(_), do: false

  # "Would this account see any instance content?" Instance visibility comes
  # solely from group membership (Orbit.Auth.Scope: zero groups compiles to
  # WHERE false), so a group-less account gets "(0)" on every instance page —
  # Instances, Alerts, Connectivity, VPN, Certs, Firmware, Logs. That is the
  # normal state of a pure superadmin (rights management, no instance access)
  # and of any user before group assignment; linking them to seven empty
  # pages reads as breakage.
  #
  # Deliberately NOT keyed on is_superadmin: a superadmin may also hold
  # groups, and then sees instances like anyone else.
  #
  # Fails OPEN (unloaded assoc → show the links): this is nav cosmetics, the
  # scoping in Scope/the LiveViews is what actually withholds data.
  defp instance_data?(%{groups: groups}) when is_list(groups), do: groups != []
  defp instance_data?(_), do: true

  defp superadmin?(%{is_superadmin: true}), do: true
  defp superadmin?(_), do: false
end
