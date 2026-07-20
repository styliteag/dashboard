import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/orbit start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :orbit, OrbitWeb.Endpoint, server: true
end

config :orbit, OrbitWeb.Endpoint, http: [port: String.to_integer(System.get_env("PORT", "4000"))]

# Fernet key for the shared *_enc columns — same env var as the python
# backend (DASH_ prefix). Optional at boot: modules that decrypt fetch it via
# Orbit.Crypto.master_key!/0 which raises a clear error when unset.
config :orbit, :dash_master_key, System.get_env("DASH_MASTER_KEY")

# GeoIP access restriction (docs/geoip-access-restriction.md) — same env
# vars as the python backend. DASH_GEOIP_DISABLE is the env-only kill
# switch (DR-G2); the mmdb lives on the shared geoip volume and is kept
# fresh by the python updater until cutover.
config :orbit, :geoip_disable, System.get_env("DASH_GEOIP_DISABLE") in ~w(1 true yes on)

config :orbit,
       :geoip_db_path,
       System.get_env("DASH_GEOIP_DB_PATH", "/data/geoip/GeoLite2-Country.mmdb")

config :orbit,
       :trusted_proxy_hops,
       String.to_integer(System.get_env("DASH_TRUSTED_PROXY_HOPS", "0"))

# Weekly GeoLite2 refresh (DR-G1). Empty credentials = job idles; manual
# volume updates keep working. Never inherited in :test — the dev container
# carries real creds via .env, and the updater tests must control them.
if config_env() != :test do
  config :orbit, :maxmind_account_id, System.get_env("DASH_MAXMIND_ACCOUNT_ID", "")
  config :orbit, :maxmind_license_key, System.get_env("DASH_MAXMIND_LICENSE_KEY", "")
end

config :orbit, :mfa_issuer, System.get_env("DASH_MFA_ISSUER", "Orbit Dashboard")

# WebAuthn / passkeys (webauthn_svc.py + mfa_routes.py port). `rp_id` is the
# port-independent host, so it is shared-safe with the still-running python
# stack. The origin, though, must match the browser's address bar EXACTLY — and
# orbit (dev :8000) is a different origin than the python/React UI (:5173) that
# owns the shared DASH_WEBAUTHN_ORIGIN. ORBIT_WEBAUTHN_ORIGIN overrides so the
# two stacks don't fight; a comma-separated value accepts several origins (wax
# checks list membership). In prod, orbit is one origin — DASH_WEBAUTHN_ORIGIN
# (https://dash.example.com) is correct and the fallback picks it up.
config :orbit, :webauthn_rp_id, System.get_env("DASH_WEBAUTHN_RP_ID", "localhost")
config :orbit, :webauthn_rp_name, System.get_env("DASH_WEBAUTHN_RP_NAME", "Orbit Dashboard")

config :orbit,
       :webauthn_origins,
       (System.get_env("ORBIT_WEBAUTHN_ORIGIN") ||
          System.get_env("DASH_WEBAUTHN_ORIGIN", "http://localhost:8000"))
       |> String.split(",", trim: true)
       |> Enum.map(&String.trim/1)
       |> Enum.reject(&(&1 == ""))

# GUI proxy (§18): orbit host-matches the per-instance origin itself
# (OrbitWeb.GuiProxy) and reverse-proxies over an internal TCP forwarder —
# no sidecar. Off unless explicitly enabled.
config :orbit, :gui_proxy_enabled, System.get_env("DASH_GUI_PROXY_ENABLED") in ~w(1 true yes on)
# Per-instance GUI origin template; {slug}/{id} substituted. Empty → the
# dev host convention http://<slug>.localhost:<gui_dev_port>, host-matched
# and reverse-proxied by OrbitWeb.GuiProxy on the app port.
config :orbit, :gui_base_template, System.get_env("DASH_GUI_BASE_TEMPLATE", "")
config :orbit, :gui_dev_port, String.to_integer(System.get_env("DASH_GUI_DEV_PORT", "8000"))

config :orbit,
       :gui_idle_minutes,
       String.to_integer(System.get_env("DASH_GUI_IDLE_MINUTES", "15"))

# Root-terminal session recording (asciicast v2). Off unless a directory is
# set. PTY OUTPUT only — never keystrokes; see Orbit.Shell.Recorder.
config :orbit, :shell_record_dir, System.get_env("DASH_SHELL_RECORD_DIR", "")

# Bootstrap-seed force flags (auth/bootstrap.py _resolve_mode): "0"/"false"
# keeps the seed enabled and skips auto-retirement on rights changes.
config :orbit, :admin_disabled_raw, System.get_env("DASH_ADMIN_DISABLED", "auto")
config :orbit, :superadmin_disabled_raw, System.get_env("DASH_SUPERADMIN_DISABLED", "auto")

# Seed passwords for those two accounts (auth/bootstrap.py). Unset = the seed is
# never created; an empty database then has no way in at all.
config :orbit, :admin_password, System.get_env("DASH_ADMIN_PASSWORD")
config :orbit, :superadmin_password, System.get_env("DASH_SUPERADMIN_PASSWORD")

# CrowdSec blocklist (DR-G8): the key turns it on, DISABLE turns it off
# without losing the key; independent of the country restriction.
config :orbit, :crowdsec_api_key, System.get_env("DASH_CROWDSEC_API_KEY")
config :orbit, :crowdsec_disable, System.get_env("DASH_CROWDSEC_DISABLE") in ~w(1 true yes on)

config :orbit,
       :crowdsec_lapi_url,
       System.get_env("DASH_CROWDSEC_LAPI_URL", "http://crowdsec:8080")

if config_env() == :dev do
  # Reload browser tabs when matching files change.
  config :orbit, OrbitWeb.Endpoint,
    live_reload: [
      web_console_logger: true,
      patterns: [
        # Static assets, except user uploads
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$"E,
        # Router, Controllers, LiveViews and LiveComponents
        ~r"lib/orbit_web/router\.ex$"E,
        ~r"lib/orbit_web/(controllers|live|components)/.*\.(ex|heex)$"E
      ]
    ]
end

if config_env() == :prod do
  # The python stack's DASH_DATABASE_URL is the shared source of truth
  # (plan §6 M0): strip the sqlalchemy driver suffix ("mysql+aiomysql://")
  # so the same env var feeds both stacks. Plain DATABASE_URL still wins
  # for orbit-only deployments.
  database_url =
    System.get_env("DATABASE_URL") ||
      case System.get_env("DASH_DATABASE_URL") do
        nil ->
          raise """
          environment variable DATABASE_URL (or DASH_DATABASE_URL) is missing.
          For example: ecto://USER:PASS@HOST/DATABASE
          """

        dash_url ->
          String.replace(dash_url, ~r/^[a-z0-9]+\+[a-z0-9]+:\/\//, "mysql://")
      end

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :orbit, Orbit.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  # Length is checked HERE, not left to the first request. Plug's cookie store
  # requires >= 64 bytes and raises per-request when it is shorter, which fails
  # in the worst possible shape: the release boots, migrates, reports healthy
  # (/api/health-ex holds no session, so it answers 200 all day) and then 500s
  # every actual page. An operator sees a green container serving a broken
  # dashboard. Refusing to boot is the honest failure. Reported from prod
  # 2026-07-20 on a swarm deploy that shipped a placeholder value.
  #
  # Deliberately inline rather than a testable helper module: config/runtime.exs
  # is evaluated before the application starts, so it must not grow a dependency
  # on app modules being loadable at that point.
  if byte_size(secret_key_base) < 64 do
    raise """
    environment variable SECRET_KEY_BASE is too short: #{byte_size(secret_key_base)} bytes, need at least 64.

    Plug's cookie session store rejects anything shorter, so every page would
    fail with "cookie store expects conn.secret_key_base to be at least 64 bytes"
    while the health check still reported the container as up.

    Generate a valid one with:  openssl rand -base64 48
    """
  end

  host = System.get_env("PHX_HOST") || "example.com"

  config :orbit, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :orbit, OrbitWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://bandit.hexdocs.pm/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :orbit, OrbitWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://plug.hexdocs.pm/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :orbit, OrbitWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.
end
