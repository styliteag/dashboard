defmodule OrbitWeb.Router do
  use OrbitWeb, :router

  import OrbitWeb.UserAuth,
    only: [
      fetch_current_user: 2,
      require_authenticated_user: 2,
      require_authenticated_api: 2,
      require_write_api: 2,
      read_principal: 2,
      redirect_if_authenticated: 2
    ]

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {OrbitWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_current_user
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/", OrbitWeb do
    pipe_through [:browser, :redirect_if_authenticated]

    get "/login", SessionController, :new
    post "/login", SessionController, :create
    get "/login/totp", SessionController, :totp_form
    post "/login/totp", SessionController, :totp_verify
  end

  scope "/", OrbitWeb do
    pipe_through [:browser, :require_authenticated_user]

    get "/", PageController, :home
    post "/logout", SessionController, :delete

    live_session :authenticated, on_mount: OrbitWeb.UserAuth do
      live "/instances", InstancesLive
      live "/instances/:id", InstanceDetailLive
      live "/instances/:id/terminal", TerminalLive
      live "/alerts", AlertsLive
      live "/connectivity", ConnectivityLive
      live "/certificates", CertificatesLive
      live "/firmware", FirmwareLive
      live "/vpn", VpnLive
      live "/hub", HubStatusLive
    end

    live_session :admin, on_mount: {OrbitWeb.UserAuth, :require_admin} do
      live "/settings", SettingsLive
      live "/audit", AuditLive
    end

    live_session :superadmin, on_mount: {OrbitWeb.UserAuth, :require_superadmin} do
      live "/users", UsersLive
      live "/groups", GroupsLive
    end
  end

  # Bare pipeline for the agent websocket: bearer-token auth happens in the
  # controller (§27.1); no accepts/session/csrf must run before the upgrade.
  pipeline :agent_ws do
    plug :put_secure_browser_headers
  end

  # Machine-facing surface lives under /api (nginx only proxies/upgrades there).
  scope "/api", OrbitWeb do
    pipe_through :api

    get "/health-ex", HealthController, :show
  end

  scope "/api", OrbitWeb do
    pipe_through :agent_ws

    get "/ws/agent", AgentWSController, :connect
  end

  # Client-facing WS (shell/capture/gui-tunnel): needs the session cookie for
  # WSAuth, but no accepts/csrf. Auth + close codes live in the controller.
  pipeline :client_ws do
    plug :fetch_session
  end

  scope "/api", OrbitWeb do
    pipe_through :client_ws

    get "/ws/shell/:instance_id", ShellWSController, :connect
    get "/ws/capture/:instance_id", CaptureWSController, :connect
  end

  # Session-cookie JSON api (python parity: cookie auth, no csrf on /api).
  # orbit_ api-key auth joins this pipeline in a later slice.
  pipeline :session_api do
    plug :accepts, ["json"]
    plug :fetch_session
    plug :fetch_current_user
    plug :require_authenticated_api
  end

  scope "/api", OrbitWeb do
    pipe_through :session_api

    get "/agents/connected", AgentApiController, :connected
    post "/instances/:instance_id/agent/ping", AgentApiController, :ping
    get "/instances/:instance_id/comments", CommentController, :index
  end

  # Write-gated api mutations (require_write parity).
  pipeline :write_api do
    plug :accepts, ["json"]
    plug :fetch_session
    plug :fetch_current_user
    plug :require_write_api
  end

  scope "/api", OrbitWeb do
    pipe_through :write_api

    post "/instances/:instance_id/agent/enroll-code", EnrollController, :create_code
    post "/instances/:instance_id/agent/update", AgentApiController, :update
    put "/instances/:instance_id/comments", CommentController, :set
  end

  # Public enrollment: unauthenticated, rate-limited in the controller.
  scope "/api", OrbitWeb do
    pipe_through :api

    post "/agent/enroll", EnrollController, :enroll
  end

  # Machine exports: read_principal (session OR orbit_ read-only api key).
  # No :accepts plug — prometheus serves text/plain to */* scrapers.
  pipeline :read_api do
    plug :fetch_session
    plug :fetch_current_user
    plug :read_principal
  end

  scope "/api", OrbitWeb do
    pipe_through :read_api

    get "/export/checkmk", ExportController, :checkmk
    get "/export/prometheus", ExportController, :prometheus
  end

  # Enable LiveDashboard in development
  if Application.compile_env(:orbit, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: OrbitWeb.Telemetry
    end
  end
end
