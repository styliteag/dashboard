# Extension points

Orbit open ships with every extension point empty. A downstream build (for
example the commercial edition) plugs its own modules in through
`config :orbit, ...` entries instead of editing open files, so merging open
into it stays conflict-free. Open behaviour with no entry set is the plain
open product; the tests prove that for every hook.

Rules for a new hook:

- Read one config key with an empty default (`[]` or `nil`); no downstream
  module names in open code.
- Default behaviour must stay byte-identical when the key is unset.
- Add a test with a stub module (`test/support/extension_hook_stubs.ex`).
  Runtime hooks are switched on per test with `OrbitWeb.TestHooks.put_hook/2`
  in an `async: false` module. Compile-time hooks get a stub entry in
  `config/test.exs` and an extension-tolerant test (it must also pass when a
  downstream build registers its own entries instead).
- Document the hook here and in the CHANGELOG.

"Compile-time" keys are read with `Application.compile_env` (changing them
needs a recompile); "runtime" keys with `Application.get_env` on each use.

## Core

| Key | When read | Entry shape | Effect |
| --- | --- | --- | --- |
| `:extra_children` | runtime (app start) | child specs | Supervised after the migrator and the bootstrap seed (their tables exist), before PubSub and the endpoint. |
| `:notification_suppressors` | runtime | modules with `suppress?(instance_id, check_key) :: boolean` | Any `true` drops the alert in `Orbit.Notifier.send_notification/5`, after the `alert ...` event-stream log line; a `alert suppressed ...` line is logged instead of dispatching. |
| `:vendor_metrics` | compile-time | `{module, fun}`; `fun(push) :: [{name, value}]` | Extra series persisted with each push (generic `metrics` rows, no schema change). |
| `:vendor_checks` | compile-time | `{module, fun}`; `fun(entry) :: [ServiceCheck]` | Extra check families on every check surface (Checks, Alerts, Checkmk export, Prometheus). |
| `:checkmk_output_receivers` | runtime | modules with `checkmk_output(instance_id, output, meta)`; `output` = the decompressed Checkmk-agent text, `meta` = `%{interval: seconds \| nil}` | Called by `Orbit.Hub` for every push that carries a fresh run of a Linux node's Checkmk script (never for a push between runs), after the cache ingest. Runs in the hub process: a receiver must hand off at once (cast/send); one that raises is logged (`checkmk.receiver_failed`, module and error only) and skipped. `interval` is the agent's reported run interval (10..3600 s; nil from an agent that runs it on every push). `Orbit.Checks.Export.checkmk_for/2` gives the box's Checkmk export entry, if a receiver ships the dashboard's checks along. |

## Web: routing and auth

| Key | When read | Entry shape | Effect |
| --- | --- | --- | --- |
| `:extra_forwards` | compile-time | `{path, plug, opts}` | `forward path, plug, opts` at the router's top level. No pipeline runs first: the plug owns auth completely (a machine API, an external login flow). |
| `:extra_superadmin_live` | compile-time | `{path, live_module}` (module relative to `OrbitWeb`) | Extra LiveView pages inside the `:superadmin` live session (superadmin gate, GeoGate). |
| `:session_validators` | runtime | modules with `valid_session?(user, session) :: boolean` (string-keyed session map) | Every validator must accept, on each HTTP request (`fetch_current_user`), LiveView mount and client-WebSocket upgrade (`OrbitWeb.WSAuth`), on top of the built-in checks (user exists and enabled, password version, MFA). A rejected session behaves as logged out. `OrbitWeb.UserAuth.user_from_session/1` is the one shared check. |
| `:geoip_key_auth_prefixes` | runtime | path prefixes (strings starting with `/`, not `/` alone; other entries are ignored) | Extra paths (the prefix itself or anything below `prefix/`) where an `Authorization: Bearer orbit_…` header exempts the request from the GeoIP gate, on top of the built-in `/api/export/checkmk` and `/api/export/prometheus`. Only for forwards whose auth is the bearer key alone (a wrong key must be a 401, never a session fallback). |
| `:logout_redirects` | runtime | modules with `logout_redirect(conn) :: url \| nil` | Asked in order before the session is dropped (so they can read it); the first URL wins and is used as an external redirect. All `nil`: `/login`. |

## Web: pages

| Key | When read | Entry shape | Effect |
| --- | --- | --- | --- |
| `:designs` | compile-time | `%{id, name, default_mode}` | Design registry (`OrbitWeb.Design`); replaces the default list. |
| `:edition` | runtime | string | Edition label in the nav and version footer. |
| `:apikeys_extra_links` | runtime | `{label, path, :all \| :superadmin}` | Links next to "New key" on `/apikeys`; `:superadmin` entries only for superadmins. |
| `:instance_badges` | runtime | `{module, fun}`; `fun(instance) :: nil \| %{label, title}` | Extra badges in the instance detail header (after the agent badge). |
| `:vendor_sections` | compile-time | `%{section, component: {module, fun}}` | Overview cards for instances whose cache carries the `x_*` section. |
| `:vendor_tabs` | compile-time | `%{key, label, device_types, agent, component, visible}` | Extra tabs on the instance detail page. The component gets `entry` (cache entry), `instance`, `chart_range`, `table_sort`, `writable` (the viewer may change things; a tab's own event handler must check it again) and `current_user` (for the audit row of such a change). |
