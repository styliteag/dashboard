# State machines

Two flows are security boundaries and are owned by one module each. Change
them only there, and keep the table-driven tests in step.

## Login flow: `Orbit.Auth.LoginFlow`

Pure module (`orbit/lib/orbit/auth/login_flow.ex`), states
`anonymous | pending_verify | pending_enroll | full`.

- The password step chooses the pending state (`{:password, :done | :verify
  | :enroll}`); it is stored in the session as `login_state` next to
  `mfa_user_id`.
- Every second-factor action names its event (`:show_challenge`,
  `:factor_verified`, `:begin_enroll`, `:factor_enrolled`) and gets the user
  only through `OrbitWeb.UserAuth.pending_mfa_user(conn, event)`, which asks
  `LoginFlow.allowed?/2`. Each event belongs to exactly one pending state.
- Enrollment is double-gated: `pending_enroll` in the session AND
  `Orbit.Accounts.enrollable?/1` (no TOTP, no passkey) against the DB; the
  enrollment UPDATEs repeat that condition in their WHERE clause.
- Tests: `test/orbit/auth/login_flow_test.exs` (transition table),
  `test/orbit_web/controllers/session_enroll_test.exs` (both pending kinds).

## Agent binding: `Orbit.AgentBinding`

`orbit/lib/orbit/agent_binding.ex` owns `enable` (also token rotation),
`disable` (also the uninstall path) and `delete`. The agent WebSocket
authenticates only at the upgrade, so every transition evicts the live
socket with `Orbit.Hub.evict/2` (close 4003), and the socket re-checks
`AgentBinding.current?/2` on hello (before registering, so a stale token
cannot replace the current socket, and again after, so a revocation in
between is not missed). Frames before hello are dropped: an unregistered
socket is out of `evict/2`'s reach.

- Never call `Hub.unregister/1` for a binding change: it is pid-identity
  checked and is a no-op from any process but the socket itself.
- `Orbit.Instances.soft_delete/1` is a raw write that leaves the socket
  open; use it only when you must still talk to the agent first and then
  evict it yourself.
- Tests: `test/orbit/agent_binding_test.exs`, `test/orbit/hub_test.exs`
  (`evict/2`), `test/orbit_web/agent_socket_test.exs`.
