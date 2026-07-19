defmodule Orbit.ConfigBackup.StoreTest do
  @moduledoc "Pure decode_payload (DB path — encrypt/dedup/prune — verified live)."
  use ExUnit.Case, async: true

  alias Orbit.ConfigBackup.Store

  defp payload(xml) do
    gz = :zlib.gzip(xml)
    sha = :crypto.hash(:sha256, xml) |> Base.encode16(case: :lower)
    %{"content_gz_b64" => Base.encode64(gz), "sha256" => sha}
  end

  test "decode_payload round-trips a valid gzip+base64+sha payload" do
    xml = "<config><system>fw</system></config>"
    assert {:ok, {sha, ^xml}} = Store.decode_payload(payload(xml))
    assert sha == :crypto.hash(:sha256, xml) |> Base.encode16(case: :lower)
  end

  test "decode_payload rejects a mismatched sha (corrupt/truncated transfer)" do
    p = %{payload("<a/>") | "sha256" => String.duplicate("0", 64)}
    assert Store.decode_payload(p) == :error
  end

  test "decode_payload rejects malformed input" do
    assert Store.decode_payload(%{}) == :error
    assert Store.decode_payload("nope") == :error
    assert Store.decode_payload(%{"content_gz_b64" => "!!!", "sha256" => "x"}) == :error
  end
end
