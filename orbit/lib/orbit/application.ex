defmodule Orbit.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    base = [
      OrbitWeb.Telemetry,
      Orbit.Repo,
      {DNSCluster, query: Application.get_env(:orbit, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Orbit.PubSub},
      {Orbit.Auth.LoginLimiter, []},
      {Orbit.Settings, []},
      {Orbit.Hub, []},
      {Orbit.Shell.Slots, []}
    ]

    # GeoIP gate processes (config store + dyndns resolver) start BEFORE the
    # endpoint — the gate must have its rules before the first request; the
    # endpoint stays last so it only serves once everything is up. Scheduler
    # (maintenance jobs) appends behind a flag; geoip likewise not in :test
    # (both touch alembic-owned tables the throwaway test DB doesn't have).
    children = maybe_scheduler(base ++ geoip_children() ++ [OrbitWeb.Endpoint])

    # See https://elixir.hexdocs.pm/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Orbit.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp maybe_scheduler(children) do
    if Application.get_env(:orbit, :start_scheduler, true) do
      children ++ [{Orbit.Scheduler, []}]
    else
      children
    end
  end

  defp geoip_children do
    if Application.get_env(:orbit, :start_geoip, true) do
      Orbit.GeoIP.Lookup.start()
      [{Orbit.GeoIP.Store, []}, {Orbit.GeoIP.Dyndns, []}, {Orbit.GeoIP.Crowdsec, []}]
    else
      []
    end
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    OrbitWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
