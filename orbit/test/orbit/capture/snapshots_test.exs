defmodule Orbit.Capture.SnapshotsTest do
  @moduledoc "pcap summarizer (capture/routes.py _parse_pcap parity) against a synthetic capture."
  use ExUnit.Case, async: true

  alias Orbit.Capture.Snapshots

  # Classic little-endian pcap wrapping the given ethernet frames.
  defp pcap(frames) do
    global =
      <<0xD4C3B2A1::little-32, 2::little-16, 4::little-16, 0::little-32, 0::little-32,
        65_535::little-32, 1::little-32>>

    packets =
      for {frame, i} <- Enum.with_index(frames), into: <<>> do
        <<1_700_000_000 + i::little-32, 250_000::little-32, byte_size(frame)::little-32,
          byte_size(frame)::little-32>> <> frame
      end

    global <> packets
  end

  defp eth(payload, ethertype) do
    <<0::48, 1::48, ethertype::16>> <> payload
  end

  defp ipv4(proto, l4) do
    header =
      <<0x45, 0, 20 + byte_size(l4)::16, 0::16, 0::16, 64, proto, 0::16, 10, 20, 1, 198, 8, 8, 8,
        8>>

    header <> l4
  end

  test "parses tcp syn, udp and icmp frames into viewer rows" do
    tcp = <<443::16, 51_000::16, 0::32, 0::32, 0x5002::16, 0::16, 0::16>>
    udp = <<53::16, 40_000::16, 8::16, 0::16>>
    icmp = <<8, 0, 0::16>>

    rows =
      [eth(ipv4(6, tcp), 0x0800), eth(ipv4(17, udp), 0x0800), eth(ipv4(1, icmp), 0x0800)]
      |> pcap()
      |> Snapshots.parse()

    assert [
             %{proto: "TCP", src: "10.20.1.198:443", dst: "8.8.8.8:51000", info: "SYN"},
             %{proto: "UDP", src: "10.20.1.198:53", dst: "8.8.8.8:40000"},
             %{proto: "ICMP", info: "type 8/0"}
           ] = rows

    assert Enum.all?(rows, &(&1.hex != "" and is_float(&1.ts)))
  end

  test "non-ip and truncated data degrade, never crash" do
    assert [%{proto: "ARP"}] = Snapshots.parse(pcap([eth(<<1, 2, 3>>, 0x0806)]))
    assert Snapshots.parse(<<1, 2, 3>>) == []
    assert Snapshots.parse(pcap([]) <> <<9, 9, 9>>) == []
  end

  test "max_packets caps the row count" do
    frames = List.duplicate(eth(ipv4(1, <<8, 0, 0::16>>), 0x0800), 5)
    assert length(Snapshots.parse(pcap(frames), 3)) == 3
  end
end
