defmodule OrbitWeb.GuiProxyTest do
  @moduledoc """
  Host → slug resolution. The GUI origin's shape is configured
  (DASH_GUI_BASE_TEMPLATE) and must not be assumed anywhere else.
  """

  use ExUnit.Case, async: false

  alias OrbitWeb.GuiProxy

  setup do
    previous = Application.get_env(:orbit, :gui_base_template, "")
    on_exit(fn -> Application.put_env(:orbit, :gui_base_template, previous) end)
    :ok
  end

  defp with_template(template) do
    Application.put_env(:orbit, :gui_base_template, template)
  end

  describe "dev convention (no template)" do
    test "<slug>.localhost resolves, bare localhost does not" do
      with_template("")
      assert GuiProxy.slug_from_host("opn1.localhost") == "opn1"
      assert GuiProxy.slug_from_host("localhost") == nil
      assert GuiProxy.slug_from_host("dash.example.com") == nil
    end
  end

  describe "configured template" do
    test "a non-default prefix is honoured" do
      # Reported from a deployment running a second stack on one domain: the
      # prefix was hardcoded to "gui-" here while the template said "gui2-",
      # so every GUI origin fell through to the router and answered a bare
      # "Not Found" — with the reverse proxy, the template and the cookie all
      # configured correctly.
      with_template("https://gui2-{slug}.stylite-live.net")

      assert GuiProxy.slug_from_host("gui2-bonis-opnsense-test.stylite-live.net") ==
               "bonis-opnsense-test"
    end

    test "the domain is part of the match, not just the prefix" do
      with_template("https://gui2-{slug}.stylite-live.net")
      assert GuiProxy.slug_from_host("gui2-opn1.attacker.example") == nil
      assert GuiProxy.slug_from_host("gui2-opn1.stylite-live.net.evil.com") == nil
    end

    test "{id} is accepted as the back-compat spelling of {slug}" do
      with_template("https://gui-{id}.example.com")
      assert GuiProxy.slug_from_host("gui-opn1.example.com") == "opn1"
    end

    test "a template with a deeper domain still anchors correctly" do
      with_template("https://gui-{slug}.gui.example.com")
      assert GuiProxy.slug_from_host("gui-opn1.gui.example.com") == "opn1"
      assert GuiProxy.slug_from_host("gui-opn1.example.com") == nil
    end

    test "switching the template takes effect (the compiled regex is cached per value)" do
      with_template("https://gui2-{slug}.stylite-live.net")
      assert GuiProxy.slug_from_host("gui2-a.stylite-live.net") == "a"

      with_template("https://fw-{slug}.other.example")
      assert GuiProxy.slug_from_host("gui2-a.stylite-live.net") == nil
      assert GuiProxy.slug_from_host("fw-a.other.example") == "a"
    end
  end

  describe "legacy fallback" do
    test "gui-<slug> still resolves when no template is configured" do
      # Kept so a deployment that set up DNS by hand and never filled in the
      # template does not break on this change.
      with_template("")
      assert GuiProxy.slug_from_host("gui-opn1.example.com") == "opn1"
    end
  end
end
