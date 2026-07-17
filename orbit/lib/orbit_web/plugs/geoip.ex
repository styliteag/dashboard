defmodule OrbitWeb.Plugs.GeoIP do
  @moduledoc """
  HTTP enforcement of the GeoIP access restriction (DR-G2) — the plug runs
  in the endpoint ahead of the router, so every dynamic route (LiveView dead
  renders, session routes, /api, client-WS upgrades) passes through it.

  Divergence from the python middleware, on purpose: python exempts all
  non-/api paths because they only serve the static react bundle; in orbit
  the UI itself is server-rendered session surface, so everything is
  checked. Static assets are served by Plug.Static BEFORE this plug.

  Exemptions mirror the ADR: agent WS + enroll (firewalls connect from
  customer sites worldwide), /api/health (uptime probes), `orbit_` bearer
  keys (machine reads, read-only by construction). The /live websocket
  bypasses the plug pipeline entirely (endpoint `socket` macro) — that hole
  is closed by OrbitWeb.GeoGate in every live_session.

  Denials: 403 with a fixed message (no country named), one log line per IP
  per 10s (a scanner must not flood the log). Login-path denials are the one
  audit-worthy case (rare + high signal; auditing every blocked request
  would let a scanner write-flood the audit table).
  """

  @behaviour Plug

  import Plug.Conn

  require Logger

  alias Orbit.GeoIP.Store

  @exempt_prefixes [
    "/api/ws/agent",
    "/api/agent/enroll",
    "/api/health"
  ]

  @deny_text "access restricted from your location"

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    cond do
      exempt_path?(conn.request_path) -> conn
      api_key?(conn) -> conn
      true -> enforce(conn)
    end
  end

  defp exempt_path?(path), do: Enum.any?(@exempt_prefixes, &String.starts_with?(path, &1))

  defp api_key?(conn) do
    case get_req_header(conn, "authorization") do
      [auth | _] -> auth |> String.downcase() |> String.starts_with?("bearer orbit_")
      [] -> false
    end
  end

  defp enforce(conn) do
    ip = Orbit.Net.client_ip(conn)

    # Test seam: the verdict fn is swappable so the deny path (403 shape,
    # halt, login audit) is testable without a loaded mmdb.
    evaluator = Application.get_env(:orbit, :geoip_evaluator, &Orbit.GeoIP.evaluate/1)

    case evaluator.(ip) do
      {:allow, "db_unavailable", _} ->
        # Fail-open on infrastructure failure (DR-G5) — loud, throttled.
        if Store.should_log?(ip), do: Logger.error("geoip.db_unavailable_fail_open ip=#{ip}")
        conn

      {:allow, _reason, _} ->
        conn

      {:deny, reason, country} ->
        deny(conn, ip, reason, country)
    end
  end

  defp deny(conn, ip, reason, country) do
    if Store.should_log?(ip) do
      Logger.warning(
        "geoip.denied ip=#{ip} country=#{country || "-"} path=#{conn.request_path} reason=#{reason}"
      )
    end

    if conn.request_path == "/login" and conn.method == "POST" do
      audit_login_denial(ip, country, reason)
    end

    if String.starts_with?(conn.request_path, "/api/") do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(403, Jason.encode!(%{detail: @deny_text}))
      |> halt()
    else
      conn
      |> put_resp_content_type("text/plain")
      |> send_resp(403, @deny_text)
      |> halt()
    end
  end

  defp audit_login_denial(ip, country, reason) do
    Orbit.Audit.write(
      action: "auth.login",
      result: "denied",
      detail: %{"reason" => "geo_blocked", "country" => country || "", "why" => reason},
      source_ip: ip
    )
  rescue
    # An audit hiccup must not 500 the deny.
    error -> Logger.warning("geoip.audit_failed error=#{Exception.message(error)}")
  end
end
