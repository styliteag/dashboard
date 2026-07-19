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
    <header class="flex items-center justify-between border-b border-base-300 bg-base-200 px-6 py-3">
      <div class="flex items-center gap-4">
        <a href={~p"/"} class="flex items-center gap-2 font-semibold text-base-content">
          <.nav_icon name={:brand} class="h-5 w-5 text-primary" /> STYLiTE Orbit
        </a>
        <nav class="flex flex-wrap gap-3 text-sm text-base-content/70">
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

  @doc """
  Inline lucide icon (Layout.tsx nav-icon parity — no icon dependency in
  orbit, the paths are vendored). Keyed by nav page key; unknown keys render
  nothing so a new nav link without an icon never crashes the header.
  """
  attr :name, :atom, required: true
  attr :class, :string, default: "h-4 w-4"

  def nav_icon(assigns) do
    ~H"""
    <svg
      :if={icon_paths(@name)}
      class={@class}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="2"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
    >
      {Phoenix.HTML.raw(icon_paths(@name))}
    </svg>
    """
  end

  # Vendored lucide path data (24x24 stroke icons). Mapping mostly mirrors
  # the old Layout.tsx, with two deliberate upgrades: VPN uses a lock (the
  # old shield collided with the brand mark and Security's shield-check),
  # and Audit uses history (a trail through time) instead of file-text.
  defp icon_paths(:instances),
    do:
      ~s(<rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>)

  defp icon_paths(:hub), do: ~s(<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>)

  defp icon_paths(:alerts),
    do:
      ~s(<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/>)

  defp icon_paths(:connectivity),
    do:
      ~s(<circle cx="12" cy="12" r="2"/><path d="M4.93 19.07a10 10 0 0 1 0-14.14"/><path d="M7.76 16.24a6 6 0 0 1 0-8.49"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/>)

  defp icon_paths(:vpn),
    do:
      ~s(<rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>)

  defp icon_paths(:certificates),
    do:
      ~s(<path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><path d="m9 12 2 2 4-4"/>)

  defp icon_paths(:firmware),
    do:
      ~s(<path d="m7.5 4.27 9 5.15"/><path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>)

  defp icon_paths(:logs),
    do:
      ~s(<path d="M15 12h-5"/><path d="M15 8h-5"/><path d="M19 17V5a2 2 0 0 0-2-2H4"/><path d="M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3"/>)

  defp icon_paths(:settings),
    do:
      ~s(<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>)

  defp icon_paths(:audit),
    do:
      ~s(<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>)

  defp icon_paths(:users),
    do:
      ~s(<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>)

  defp icon_paths(:groups),
    do:
      ~s(<path d="M20 10a1 1 0 0 0 1-1V6a1 1 0 0 0-1-1h-2.5a1 1 0 0 1-.8-.4l-.9-1.2A1 1 0 0 0 15 3h-2a1 1 0 0 0-1 1v5a1 1 0 0 0 1 1Z"/><path d="M20 21a1 1 0 0 0 1-1v-3a1 1 0 0 0-1-1h-2.5a1 1 0 0 1-.8-.4l-.9-1.2a1 1 0 0 0-.8-.4h-2a1 1 0 0 0-1 1v5a1 1 0 0 0 1 1Z"/><path d="M3 5a2 2 0 0 0 2 2h3"/><path d="M3 3v13a2 2 0 0 0 2 2h3"/>)

  defp icon_paths(:access_control),
    do:
      ~s(<path d="M21.54 15H17a2 2 0 0 0-2 2v4.54"/><path d="M7 3.34V5a3 3 0 0 0 3 3a2 2 0 0 1 2 2c0 1.1.9 2 2 2a2 2 0 0 0 2-2c0-1.1.9-2 2-2h3.17"/><path d="M11 21.95V18a2 2 0 0 0-2-2a2 2 0 0 1-2-2v-1a2 2 0 0 0-2-2H2.05"/><circle cx="12" cy="12" r="10"/>)

  defp icon_paths(:security),
    do: ~s(<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>)

  defp icon_paths(:brand), do: ~s(<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>)

  defp icon_paths(:password),
    do:
      ~s(<path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/>)

  defp icon_paths(:signout),
    do:
      ~s(<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>)

  defp icon_paths(_), do: nil

  defp admin?(%{role: "admin"}), do: true
  defp admin?(_), do: false

  defp superadmin?(%{is_superadmin: true}), do: true
  defp superadmin?(_), do: false
end
