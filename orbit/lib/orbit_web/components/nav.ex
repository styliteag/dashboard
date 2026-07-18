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
        <a href={~p"/"} class="font-semibold text-base-content">STYLiTE Orbit</a>
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
          class="text-base-content/70 hover:text-base-content"
          title="Change password"
        >
          {@current_user.username}
        </a>
        <.theme_switcher />
        <form action={~p"/logout"} method="post">
          <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
          <button
            type="submit"
            class="rounded-md border border-base-content/20 px-2 py-0.5 text-xs text-base-content/80 hover:bg-base-300"
          >
            Sign out
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
        "rounded-md px-2 py-1",
        if(@active == @key,
          do: "bg-base-300 font-medium text-primary",
          else: "text-base-content/70 hover:bg-base-300/60 hover:text-base-content"
        )
      ]}
    >
      {@label}
    </a>
    """
  end

  defp admin?(%{role: "admin"}), do: true
  defp admin?(_), do: false

  defp superadmin?(%{is_superadmin: true}), do: true
  defp superadmin?(_), do: false
end
