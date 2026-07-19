defmodule Orbit.GUITest do
  @moduledoc "routes/gui.py pure helpers — open-redirect clamp + origin url."

  use ExUnit.Case, async: false

  alias Orbit.GUI
  alias Orbit.Instances.Instance

  setup do
    prev = Application.get_env(:orbit, :gui_base_template)
    on_exit(fn -> Application.put_env(:orbit, :gui_base_template, prev) end)
    :ok
  end

  describe "safe_next/1" do
    test "same-origin absolute paths pass" do
      assert GUI.safe_next("/ui/ipsec/sessions") == "/ui/ipsec/sessions"
    end

    test "open-redirect vectors collapse to /" do
      assert GUI.safe_next("//evil.com") == "/"
      assert GUI.safe_next("https://evil.com") == "/"
      assert GUI.safe_next("/\\evil.com") == "/"
      assert GUI.safe_next(nil) == "/"
      assert GUI.safe_next("") == "/"
    end
  end

  describe "base_url/1 + handoff_url/3" do
    test "dev host convention: <slug>.localhost on the app port" do
      Application.put_env(:orbit, :gui_base_template, "")
      Application.put_env(:orbit, :gui_dev_port, 8000)
      assert GUI.base_url(%Instance{id: 3, slug: "opn1"}) == "http://opn1.localhost:8000"
    end

    test "template substitutes slug and id" do
      Application.put_env(:orbit, :gui_base_template, "https://gui-{slug}.example.com")
      assert GUI.base_url(%Instance{id: 3, slug: "opn1"}) == "https://gui-opn1.example.com"
    end

    test "handoff url carries the token + deep-link on the gui origin" do
      Application.put_env(:orbit, :gui_base_template, "https://gui-{slug}.example.com")
      inst = %Instance{id: 3, slug: "opn1"}
      url = GUI.handoff_url(inst, "tok123", "/ui/x")
      assert url == "https://gui-opn1.example.com/__orbit/auth?t=tok123&next=%2Fui%2Fx"
      # A "/" next is omitted (no redirect param).
      assert GUI.handoff_url(inst, "tok123", "/") ==
               "https://gui-opn1.example.com/__orbit/auth?t=tok123"
    end
  end
end
