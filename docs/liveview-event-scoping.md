# LiveView event scoping — audit 2026-07-19

## The rule

**Every `phx-value-*` is user input.** It is rendered into the DOM, so its value
is whatever the visitor's browser sends back — devtools make changing it
trivial. "The row carries the id" and "the browser sent the id" describe the
same bytes.

Only two things are trustworthy in a `handle_event`:

1. `socket.assigns` set server-side *after* a check (e.g. `assigns.instance` on a
   per-instance page, resolved once at `mount` through `Scope.get_instance/2`),
   and
2. the session's `current_user`.

So a **fleet** page — one that lists many instances — must re-resolve the
instance in *every* handler, because there is no per-page instance to lean on.

    Scope.get_instance(id, socket.assigns.current_user)   # nil = not yours

`nil` covers both "does not exist" and "out of your scope"; the caller must not
distinguish them (no existence oracle). Mutations additionally need the write
role, and rights-management pages are gated at the router
(`require_superadmin` / `require_admin_or_superadmin`) rather than by instance
scope, since they are not instance-scoped resources.

## What was audited

Every `handle_event/3` in `orbit/lib/orbit_web/live/*.ex` that performs a
mutation (`Hub.send_command`, `Repo.*`, `Monitors.*`, `Instances.*`, `Bulk.run`,
`GUI.open_flow`, `Firmware.*`, `Accounts.*`, `ping_test`, `pin_ssh_host_key`),
checked for a scope or role guard in the same clause.

### Result: no unguarded mutation

Verified rather than assumed, on the dev database:

- **Scope really refuses.** A freshly created user with zero groups got `nil`
  from `Scope.get_instance/2` for every instance (inverted empty-set semantics:
  a user with no groups sees *nothing*). Removed again afterwards.
- **The SQL is a second layer.** A monitor belonging to instance 1, addressed as
  instance 5, survived both an update and a delete untouched — every statement
  carries `WHERE id = ? AND instance_id = ?`. Pinned by
  `test/orbit/monitors_scoping_test.exs`.

### Where the guards live

| Site | Guard |
|---|---|
| `ListKit.gui_open_row/3` | write role + `Scope.get_instance` + `GUI.openable` — used by alerts, certificates, firmware, hub, instances, vpn |
| `CommentEditor.write/5` | write role + `Scope.get_instance` |
| `Bulk.run/4` | starts from `list_visible(user)` and *filters* the selection — an out-of-scope id is simply absent, rather than fetched |
| `instances_live` delete | write role + `Scope.get_instance` |
| `vpn_live` history/reconnect/p2mon | write role (where mutating) + `Scope.get_instance` |
| `connectivity_live` monitor dialog | write role + `Scope.get_instance` per entry point |
| `security_live` passkey delete | `Accounts.delete_credential/2` refuses a credential whose `user_id` is not the caller's |
| `/users`, `/groups`, `/access-control` | `require_superadmin` at the router |
| `/audit`, `/apikeys` | `require_admin_or_superadmin` at the router |

`instances_live` `toggle_select` and `vpn_live` `toggle_expand` take ids without
a check on purpose: they only build a client-side selection. The guard belongs
at the point of action, and `Bulk.run/4` has it.

## The one gap found

The monitor **Test** buttons (fleet VPN, instance VPN, instance connectivity)
checked scope but not the write role. A test sends real ICMP from the operator's
appliance — it stores nothing, but it is a mutation of the outside world, and a
view-only session should not cause traffic to leave a customer box. Reaching the
button already required the write role, but that is an indirect guarantee and a
crafted event has to be refused on its own. Fixed in `4b82981`.

## Not covered here

This audit is static: it reads the guard in each clause. It does not prove the
guards themselves are correct — `Orbit.Auth.Scope` is change-frozen and has its
own tests (`test/orbit/auth/scope_test.exs`), which is what that rests on.
