defmodule OrbitWeb.Components.BaseUrlLinksTest do
  @moduledoc """
  base_url_links/1 — the clickable Base URL used on the list and detail page.

  A `base_url` may be a comma-separated list (parity with the retired React
  dashboard): each endpoint gets its own link. The security-relevant part is the
  scheme guard — only http(s) is linkified, so an odd value can never render as
  a live `javascript:` href.
  """
  use ExUnit.Case, async: true

  import Phoenix.LiveViewTest

  alias OrbitWeb.CoreComponents

  test "a single URL is one link opening in a new tab" do
    html = render_component(&CoreComponents.base_url_links/1, %{base_url: "https://fw:4444"})
    assert html =~ ~s(href="https://fw:4444")
    assert html =~ ~s(target="_blank")
  end

  test "a comma-separated list becomes one link per endpoint" do
    html =
      render_component(&CoreComponents.base_url_links/1, %{
        base_url: "https://a:4444, https://b:4444"
      })

    assert html =~ ~s(href="https://a:4444")
    assert html =~ ~s(href="https://b:4444")
  end

  test "empty renders a muted dash, not a link" do
    html = render_component(&CoreComponents.base_url_links/1, %{base_url: ""})
    refute html =~ "<a"
    assert html =~ "—"
  end

  test "a non-http value is shown as text, never linkified" do
    html = render_component(&CoreComponents.base_url_links/1, %{base_url: "javascript:alert(1)"})
    refute html =~ "href"
    assert html =~ "javascript:alert(1)"
  end
end
