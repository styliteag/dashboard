defmodule OrbitWeb.ExtensionHooksUITest do
  @moduledoc """
  Router and page extension points (docs/extension-points.md):
  `:extra_forwards`, `:extra_superadmin_live` (compile-time, stubs registered
  in config/test.exs), `:apikeys_extra_links` and `:instance_badges` (runtime).
  async: false — the runtime hooks are global app env.

  Extension-tolerant: a downstream build that registers its own compile-time
  entries instead of the stubs still passes (every configured entry is routed).
  """

  use OrbitWeb.ConnCase, async: false

  import Phoenix.LiveViewTest
  import OrbitWeb.TestHooks

  alias Orbit.Repo
  alias OrbitWeb.TestHooks.{Badge, ForwardPlug}

  @forwards Application.compile_env(:orbit, :extra_forwards, [])
  @superadmin_live Application.compile_env(:orbit, :extra_superadmin_live, [])

  defp route(path), do: Phoenix.Router.route_info(OrbitWeb.Router, "GET", path, "localhost")

  describe ":extra_forwards" do
    test "every configured entry is forwarded to its plug" do
      for {path, plug, _opts} <- @forwards do
        assert %{plug: ^plug} = route(path <> "/anything")
      end
    end

    if {"/__test/extra-forward", ForwardPlug, [marker: :stub]} in @forwards do
      test "the stub plug owns the request, opts passed through", %{conn: conn} do
        resp = get(conn, "/__test/extra-forward/x")
        assert resp.status == 200
        assert resp.resp_body =~ "forwarded GET"
        assert resp.resp_body =~ "marker: :stub"
      end
    end
  end

  describe ":extra_superadmin_live" do
    test "every configured entry is a live route relative to OrbitWeb" do
      for {path, live_module} <- @superadmin_live do
        expected = Module.concat(OrbitWeb, live_module)
        assert %{phoenix_live_view: {^expected, _, _, _}} = route(path)
      end
    end

    if {"/__test/extra-superadmin", TestHooks.SuperadminLive} in @superadmin_live do
      test "the page sits behind the superadmin gate", %{conn: conn} do
        superadmin = login(conn, user!("admin", true))
        assert {:ok, _view, html} = live(superadmin, "/__test/extra-superadmin")
        assert html =~ "extra superadmin page"

        admin = login(conn, user!("admin", false))
        assert {:error, {:redirect, %{to: "/"}}} = live(admin, "/__test/extra-superadmin")
      end
    end
  end

  describe ":apikeys_extra_links" do
    test "unset: no extra links next to New key", %{conn: conn} do
      delete_hook(:apikeys_extra_links)
      {:ok, _view, html} = live(login(conn, user!("admin", true)), ~p"/apikeys")

      assert html =~ "New key"
      refute html =~ "/__test/"
    end

    test ":all links show to everyone, :superadmin links only to superadmins", %{conn: conn} do
      put_hook(:apikeys_extra_links, [
        {"Everyone link", "/__test/all", :all},
        {"Superadmin link", "/__test/super", :superadmin}
      ])

      {:ok, _view, html} = live(login(conn, user!("admin", true)), ~p"/apikeys")
      assert html =~ "Everyone link"
      assert html =~ "Superadmin link"
      assert html =~ ~s(href="/__test/super")

      {:ok, _view, html} = live(login(conn, user!("admin", false)), ~p"/apikeys")
      assert html =~ "Everyone link"
      refute html =~ "Superadmin link"
    end
  end

  describe ":instance_badges" do
    setup do
      group =
        Repo.insert!(%Orbit.Accounts.Group{
          name: "hooks-#{System.unique_integer([:positive])}",
          created_at: DateTime.utc_now()
        })

      %{group: group, user: user!("admin", false, [group.id])}
    end

    defp instance!(name, group) do
      {:ok, inst} =
        Orbit.Instances.create_instance(%{"name" => name, "device_type" => "linux"}, group.id)

      inst
    end

    test "unset: the header carries no extra badge", %{conn: conn, group: group, user: user} do
      delete_hook(:instance_badges)
      inst = instance!("badge-#{System.unique_integer([:positive])}", group)

      {:ok, _view, html} = live(login(conn, user), ~p"/instances/#{inst.id}")
      refute html =~ "test badge"
    end

    test "a badge function returning a map renders label + title; nil renders nothing", %{
      conn: conn,
      group: group,
      user: user
    } do
      put_hook(:instance_badges, [{Badge, :badge}])
      flagged = instance!("badge-#{System.unique_integer([:positive])}", group)
      plain = instance!("plain-#{System.unique_integer([:positive])}", group)

      {:ok, _view, html} = live(login(conn, user), ~p"/instances/#{flagged.id}")
      assert html =~ "test badge"
      assert html =~ ~s(title="set by the hook")

      {:ok, _view, html} = live(login(conn, user), ~p"/instances/#{plain.id}")
      refute html =~ "test badge"
    end
  end
end
