defmodule OrbitWeb.Components.NavTest do
  @moduledoc """
  Top-nav link visibility (DB-free component render).

  Regression: the group-less seed superadmin was offered Instances, Alerts,
  Connectivity, VPN, Certs and Firmware — pages that render "(0)" for an
  account with no group memberships (Scope: zero groups = zero instances) —
  plus Hub, whose counters are fleet-wide and unscoped, and Logs, which shows
  log-line content. The latter two are admin-only now (router :admin
  live_session, python parity).
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias Orbit.Accounts.{Group, User}
  alias OrbitWeb.Components.Nav

  # The instance-data pages: every one of them lists instances the caller may
  # see, so all of them are empty without group membership. /logs belongs to
  # the family too but carries an extra admin gate — see its own test.
  @instance_paths ~w(/instances /alerts /connectivity /vpn /certificates /firmware)

  defp user(attrs) do
    struct!(
      %User{
        id: 1,
        username: "u",
        role: "user",
        is_superadmin: false,
        disabled: false,
        groups: []
      },
      attrs
    )
  end

  defp nav(user), do: render_component(&Nav.top_nav/1, active: nil, current_user: user)

  test "a user with groups gets the instance-data links" do
    html = nav(user(groups: [%Group{id: 3, name: "LAB"}]))

    for path <- @instance_paths, do: assert(html =~ ~s|href="#{path}"|)
  end

  test "a group-less superadmin gets none of the instance-data links" do
    html = nav(user(role: "view_only", is_superadmin: true, groups: []))

    for path <- @instance_paths, do: refute(html =~ ~s|href="#{path}"|)
    refute html =~ ~s|href="/logs"|

    # …but the rights-management surface stays reachable.
    assert html =~ ~s|href="/users"|
    assert html =~ ~s|href="/groups"|
    assert html =~ ~s|href="/access-control"|
    assert html =~ ~s|href="/audit"|
    assert html =~ ~s|href="/security"|
  end

  test "a superadmin WITH groups keeps the instance-data links (not keyed on the flag)" do
    html = nav(user(role: "view_only", is_superadmin: true, groups: [%Group{id: 1, name: "A"}]))

    assert html =~ ~s|href="/instances"|
    assert html =~ ~s|href="/vpn"|
    assert html =~ ~s|href="/users"|
    # …but Logs is admin content, and superadmin's role is view_only.
    refute html =~ ~s|href="/logs"|
  end

  test "Logs needs admin AND groups — log lines are admin-only content" do
    groups = [%Group{id: 1, name: "A"}]

    assert nav(user(role: "admin", groups: groups)) =~ ~s|href="/logs"|
    # a plain member of the same group must not read the log lines
    refute nav(user(role: "user", groups: groups)) =~ ~s|href="/logs"|
    refute nav(user(role: "view_only", groups: groups)) =~ ~s|href="/logs"|
    # an admin without groups would only get an empty list
    refute nav(user(role: "admin", groups: [])) =~ ~s|href="/logs"|
  end

  test "Hub is admin-only — a group-less user and a superadmin never see it" do
    refute nav(user(groups: [])) =~ ~s|href="/hub"|
    refute nav(user(role: "view_only", is_superadmin: true)) =~ ~s|href="/hub"|
    refute nav(user(groups: [%Group{id: 1, name: "A"}])) =~ ~s|href="/hub"|
    assert nav(user(role: "admin", groups: [%Group{id: 1, name: "A"}])) =~ ~s|href="/hub"|
  end

  test "Settings stays admin-only, Audit is admin-or-superadmin" do
    plain = nav(user(groups: [%Group{id: 1, name: "A"}]))
    refute plain =~ ~s|href="/settings"|
    refute plain =~ ~s|href="/audit"|

    assert nav(user(role: "admin")) =~ ~s|href="/settings"|
    assert nav(user(role: "admin")) =~ ~s|href="/audit"|
  end
end
