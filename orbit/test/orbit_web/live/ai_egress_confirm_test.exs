defmodule OrbitWeb.AiEgressConfirmTest do
  @moduledoc """
  UI/UX review U-M6: the AI-egress confirmation must show the operator the
  ANONYMIZED payload (what actually leaves), name the provider, and cap
  the preview — DB-free over the staging helper.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.InstanceDetailLive

  test "preview is anonymized, provider is named, kind survives" do
    # 8.8.8.8: globally routable — TEST-NET etc. are deliberately KEPT by
    # the anonymizer, so they would not prove pseudonymization here.
    text = "peer 8.8.8.8 said hello, psk=supersecret"
    c = InstanceDetailLive.egress_confirm(:diagnosis, "anthropic", text)

    assert c.kind == :diagnosis
    assert c.provider == "anthropic"
    assert is_binary(c.label) and c.label != ""
    # public IP pseudonymized, secret redacted — raw values never preview
    refute c.preview =~ "8.8.8.8"
    refute c.preview =~ "supersecret"
    assert c.preview =~ "PUBIP"
    # raw text is kept for the send path (analyze_logs anonymizes again)
    assert c.text == text
  end

  test "preview caps at 800 chars, char count reflects the full payload" do
    text = String.duplicate("10.0.0.1 up\n", 200)
    c = InstanceDetailLive.egress_confirm(:logs, "openai", text)

    assert String.length(c.preview) == 800
    assert c.chars > 800
  end

  test "an unknown provider id falls back to the id as label" do
    assert InstanceDetailLive.egress_confirm(:logs, "nope", "x").label == "nope"
  end
end
