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

    # GeoIP gate + access accounting start BEFORE the endpoint — both must
    # be up before the first request; the endpoint stays last so it only
    # serves once everything is up. Scheduler (maintenance jobs) appends
    # behind a flag; geoip/access likewise not in :test (all touch
    # alembic-owned tables the throwaway test DB doesn't have).
    children =
      maybe_scheduler(
        base ++ geoip_children() ++ access_children() ++ gui_children() ++ [OrbitWeb.Endpoint]
      )

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

  defp access_children do
    if Application.get_env(:orbit, :start_access, true) do
      # Selection rules cache feeds the notifier routing; the transition
      # tracker diffs check states per push (same not-in-test reasoning:
      # both touch alembic-owned tables).
      [{Orbit.Access.Store, []}, {Orbit.Selection, []}, {Orbit.Checks.Transitions, []}]
    else
      []
    end
  end

  defp geoip_children do
    if Application.get_env(:orbit, :start_geoip, true) do
      Orbit.GeoIP.Lookup.start()

      [
        {Orbit.GeoIP.Store, []},
        {Orbit.GeoIP.Dyndns, []},
        {Orbit.GeoIP.Crowdsec, []},
        {Orbit.GeoIP.Denials, []}
      ]
    else
      []
    end
  end

  # GUI-proxy support: the session-cookie stash + the per-instance TCP
  # forwarder manager (idle reaper armed). In-memory + cheap, so on in every
  # env; forwarders bind on demand from gui/open. :start_gui=false in tests
  # keeps the reaper timer out of the async suite.
  defp gui_children do
    if Application.get_env(:orbit, :start_gui, true) do
      [
        {Orbit.GUI.SessionStash, []},
        {Orbit.GUI.TunnelManager, [reap_ms: :timer.minutes(1)]}
      ]
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
