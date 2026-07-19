defmodule Orbit.Application do
  # See https://elixir.hexdocs.pm/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    base =
      [
        OrbitWeb.Telemetry,
        Orbit.Repo
      ] ++
        migrator_child() ++
        [
          {DNSCluster, query: Application.get_env(:orbit, :dns_cluster_query) || :ignore},
          {Phoenix.PubSub, name: Orbit.PubSub},
          {Orbit.Auth.LoginLimiter, []},
          {Orbit.Settings, []},
          {Orbit.Hub, []},
          {Orbit.Shell.Slots, []},
          {Orbit.Capture.Snapshots, []}
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

    with {:ok, pid} <- Supervisor.start_link(children, opts) do
      # Settings-driven log level/format — after the Settings table exists.
      Orbit.Logging.apply()
      {:ok, pid}
    end
  end

  # Run pending migrations at boot (empty DB → full baseline schema; existing
  # DB → incremental changes) BEFORE Settings/Hub/endpoint touch any table.
  # Off in :test — the suite manages its own database.
  defp migrator_child do
    if Application.get_env(:orbit, :migrate_on_boot, true) do
      [Orbit.Repo.Migrator]
    else
      []
    end
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
        {Orbit.GUI.TunnelManager, [reap_ms: :timer.minutes(1)]},
        gui_finch()
      ]
    else
      []
    end
  end

  # Dedicated Finch for the GUI reverse proxy. HTTP/2 is mandatory (OPNsense
  # lighttpd corrupts large *uncompressed* static bodies over HTTP/1.1 — see
  # OrbitWeb.GuiProxy.forward/3), and `count` opens several h2 connections so a
  # page load's burst of concurrent asset requests spreads across connections
  # instead of exhausting one connection's MAX_CONCURRENT_STREAMS (lighttpd's
  # default is small → :too_many_concurrent_requests). Each connection is one
  # loopback TCP conn into the per-instance forwarder tunnel; verify_none since
  # the firewall's cert is validated end-to-end by the browser, not here.
  defp gui_finch do
    {Finch,
     name: Orbit.GUI.Finch,
     pools: %{
       default: [
         protocols: [:http2],
         count: 10,
         conn_opts: [transport_opts: [verify: :verify_none]]
       ]
     }}
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    OrbitWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
