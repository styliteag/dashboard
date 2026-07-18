import Config

# Configure your database
#
# The MIX_TEST_PARTITION environment variable can be used
# to provide built-in test partitioning in CI environment.
# Run `mix help test` for more information.
# Throwaway orbit_test DB on the compose-dev MariaDB — Ecto-owned, separate
# from the Alembic-owned `dash` schema. Root creds: only root may CREATE it.
config :orbit, Orbit.Repo,
  username: "root",
  password: System.get_env("DB_ROOT_PASSWORD", "rootdev"),
  hostname: System.get_env("ORBIT_DB_HOST", "db"),
  database: "orbit_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: System.schedulers_online() * 2

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :orbit, OrbitWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "SKJlLhtx0GLqEO7nR+0h6EfIoSOCIcuwxwNXhsbGxRyTv2/6wBloxVA0l8lDcHyj",
  server: false

# Throwaway fernet key for crypto-dependent tests (NOT a real master key).
config :orbit, :dash_master_key, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

# Maintenance jobs touch the alembic-owned schema the throwaway test DB lacks.
config :orbit, :start_scheduler, false

# GeoIP store reads the alembic-owned geoip_config table — not in test; the
# gate then runs on the DISABLED default (rules are unit-tested directly).
config :orbit, :start_geoip, false

# Access store writes alembic-owned tables — not in test; record casts and
# session opens degrade to no-ops (buffer transitions are unit-tested).
config :orbit, :start_access, false

# GUI-proxy support processes (stash + forwarder manager) — off in test;
# started explicitly by the tests that exercise them.
config :orbit, :start_gui, false

# One shared Req.Test plug name for the OPNsense client. Tests stub it
# per-process (Req.Test ownership, $callers-propagated) — never via
# Application.put_env in a setup block: that global write raced across
# async test modules and made fetch_status sections vanish mid-test.
config :orbit, :opnsense_req_plug, {Req.Test, Orbit.Poller.OpnsenseClient}

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Enable helpful, but potentially expensive runtime checks
config :phoenix_live_view,
  enable_expensive_runtime_checks: true

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
