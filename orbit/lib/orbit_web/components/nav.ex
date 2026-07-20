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
    <%!-- flex-wrap on the header itself plus min-w-0 on both groups: without
         them the right-hand group (user, theme, sign out) pushed the page
         604px wide at a 390px viewport and every page scrolled sideways. --%>
    <header class="flex flex-wrap items-center justify-between gap-y-2 border-b border-base-300 bg-base-200 px-6 py-3">
      <div class="flex min-w-0 flex-wrap items-center gap-4">
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
      <.account_menu current_user={@current_user} active={@active} />
    </header>
    """
  end

  @doc """
  Account menu: everything that is about the *operator* rather than the
  fleet — profile, security, theme, sign out — behind one trigger on the
  right. Four loose controls competed with the page nav for attention and
  were what pushed the header past a phone-width viewport.

  Same `<details>` mechanics as the theme switcher (server-rendered, no
  LiveView state, closes on outside click via the data-popover handler in
  app.js), so it works on the login page too, where no LiveView is mounted.
  """
  attr :current_user, :map, required: true
  attr :active, :atom, default: nil

  def account_menu(assigns) do
    ~H"""
    <details data-popover class="relative text-sm">
      <summary class="flex cursor-pointer list-none items-center gap-2 rounded-md border border-base-content/20 px-2 py-1 text-base-content/80 hover:bg-base-300 hover:text-base-content">
        <span class="grid h-6 w-6 place-items-center rounded-full bg-primary/20 text-xs font-semibold uppercase text-primary">
          {String.first(@current_user.username)}
        </span>
        <span class="max-w-[10rem] truncate">{@current_user.username}</span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="h-3 w-3">
          <path stroke-linecap="round" stroke-linejoin="round" d="m6 9 6 6 6-6" />
        </svg>
      </summary>

      <div class="absolute right-0 top-10 z-50 w-60 overflow-hidden rounded-lg border border-base-300 bg-base-200 shadow-xl">
        <div class="border-b border-base-300 px-3 py-2">
          <p class="truncate text-sm font-medium text-base-content">{@current_user.username}</p>
          <p class="text-xs text-base-content/50">{role_label(@current_user)}</p>
        </div>

        <nav class="py-1">
          <a href={~p"/security"} class={menu_item(@active == :security)}>
            <.nav_icon name={:security} class="h-4 w-4 opacity-70" /> Security &amp; 2FA
          </a>
          <a href={~p"/password"} class={menu_item(false)}>
            <.nav_icon name={:password} class="h-4 w-4 opacity-70" /> Change password
          </a>
        </nav>

        <div class="border-t border-base-300 px-3 py-2">
          <p class="mb-1.5 text-[10px] uppercase tracking-wide text-base-content/50">Appearance</p>
          <.theme_controls />
        </div>

        <div class="border-t border-base-300 p-2">
          <form action={~p"/logout"} method="post">
            <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
            <button
              type="submit"
              class="flex w-full items-center gap-2 rounded px-2 py-1.5 text-sm text-error hover:bg-error/10"
            >
              <.nav_icon name={:signout} class="h-4 w-4" /> Sign out
            </button>
          </form>
        </div>

        <div class="border-t border-base-300 px-3 py-1.5 text-[11px] text-base-content/40">
          STYLiTE Orbit v{app_version()}
        </div>
      </div>
    </details>
    """
  end

  defp menu_item(active?) do
    [
      "flex items-center gap-2 px-3 py-1.5 text-sm",
      if(active?,
        do: "bg-base-300 text-primary",
        else: "text-base-content/80 hover:bg-base-300 hover:text-base-content"
      )
    ]
  end

  defp role_label(%{is_superadmin: true}), do: "Superadmin · rights management"
  defp role_label(%{role: "admin"}), do: "Administrator"
  defp role_label(%{role: "user"}), do: "Operator"
  defp role_label(_), do: "Read-only"

  defp app_version, do: Application.spec(:orbit, :vsn) |> to_string()

  @doc """
  The design/mode buttons themselves, without a trigger — embedded in the
  account menu in-app and in the standalone switcher on the login page.
  """
  def theme_controls(assigns) do
    ~H"""
    <div class="text-xs">
      <div class="grid grid-cols-3 gap-1">
        <form :for={d <- OrbitWeb.Design.all()} action="/design" method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <input type="hidden" name="design" value={d} />
          <button
            data-theme-design={d}
            class="w-full rounded border border-base-content/15 px-2 py-1 hover:bg-base-300 data-[active]:border-primary"
          >
            {OrbitWeb.Design.name(d)}
          </button>
        </form>
      </div>
      <div class="mt-1.5 grid grid-cols-3 gap-1">
        <form :for={m <- OrbitWeb.Design.modes()} action="/design/mode" method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <input type="hidden" name="mode" value={m} />
          <button
            data-theme-mode={m}
            class="w-full rounded border border-base-content/15 px-2 py-1 hover:bg-base-300"
          >
            {OrbitWeb.Design.mode_name(m)}
          </button>
        </form>
        <form action="/design/mode" method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <input type="hidden" name="mode" value="" />
          <button
            class="w-full rounded border border-base-content/15 px-2 py-1 hover:bg-base-300"
            title="Use the design's native mode"
          >
            Auto
          </button>
        </form>
      </div>
    </div>
    """
  end

  @doc """
  Design/mode switcher (OrbitWeb.Design): plain POST forms, server-side
  cookies. The active choice is marked CLIENT-side from the html element's
  data-theme (see markThemeChoices in app.js) — LiveViews don't carry the
  design conn assigns, and the DOM attribute is the single truth anyway.
  """
  def theme_switcher(assigns) do
    ~H"""
    <details data-popover class="relative text-xs">
      <summary
        class="cursor-pointer list-none rounded-md border border-base-content/20 px-2 py-1 text-base-content/70 hover:bg-base-300 hover:text-base-content"
        title="Theme"
      >
        Theme
      </summary>
      <div class="absolute right-0 top-8 z-50 w-52 rounded-lg border border-base-300 bg-base-200 p-3 shadow-xl">
        <.theme_controls />
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
