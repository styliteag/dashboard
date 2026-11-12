defmodule OrbitWeb.AgentUrlsTest do
  @moduledoc """
  The install snippet is pasted into a root shell, so the base URL the
  operator picks must be one the dashboard itself lists, and every listed
  entry must be a plain origin (no shell metacharacters, no path).
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.AgentUrls

  test "parse keeps plain http(s) origins, with and without port, in order" do
    assert AgentUrls.parse(
             "https://dash.lab.home, https://dash.lab.home:8443,http://10.0.0.5:8000"
           ) ==
             [
               "https://dash.lab.home",
               "https://dash.lab.home:8443",
               "http://10.0.0.5:8000"
             ]
  end

  test "parse drops entries that are not a plain origin" do
    raw =
      "https://ok.example,https://x.example/path,https://a.example;rm -rf /," <>
        "ftp://x.example,https://$(id).example,https://q.example:99999,,  "

    assert AgentUrls.parse(raw) == ["https://ok.example"]
  end

  test "parse of nil or blank is empty" do
    assert AgentUrls.parse(nil) == []
    assert AgentUrls.parse("  ") == []
  end

  test "pick accepts only a listed URL, else the default (first)" do
    urls = ["https://a.example", "https://b.example:8443"]

    assert AgentUrls.pick(urls, "https://b.example:8443") == "https://b.example:8443"
    assert AgentUrls.pick(urls, "https://evil.example") == "https://a.example"
    assert AgentUrls.pick(urls, nil) == "https://a.example"
  end
end
