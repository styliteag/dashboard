defmodule OrbitWeb.Router do
  use OrbitWeb, :router

  import OrbitWeb.UserAuth,
    only: [fetch_current_user: 2, require_authenticated_user: 2, redirect_if_authenticated: 2]

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
  end

  # Machine-facing surface lives under /api (nginx only proxies/upgrades there).
  scope "/api", OrbitWeb do
    pipe_through :api

    get "/health-ex", HealthController, :show
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
