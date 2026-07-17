defmodule Orbit.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      OrbitWeb.Telemetry,
      Orbit.Repo,
      {DNSCluster, query: Application.get_env(:orbit, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Orbit.PubSub},
      {Orbit.Auth.LoginLimiter, []},
      {Orbit.Settings, []},
      {Orbit.Hub, []},
      {Orbit.Shell.Slots, []},
      # Start to serve requests, typically the last entry
      OrbitWeb.Endpoint
    ]

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Orbit.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    OrbitWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
