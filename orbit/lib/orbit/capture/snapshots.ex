defmodule Orbit.Capture.Snapshots do
  @moduledoc """
  Bounded packet-capture snapshots (capture/routes.py + store.py port):
  the agent runs a bounded tcpdump and returns the pcap inline (b64);
  snapshots live in an ETS table with a 1h TTL, keyed by a short opaque
  id. Single-node in-memory by design (same as the python store — one
  worker); the pcap parser is a minimal stdlib-only summarizer
  (Ethernet + IPv4/TCP/UDP/ICMP) for the in-browser viewer.
  """

  use GenServer

  @table __MODULE__
  @ttl_seconds 3600

  def start_link(opts) do
    GenServer.start_link(__MODULE__, :ok, name: Keyword.get(opts, :name, __MODULE__))
  end

  @impl true
  def init(:ok) do
    :ets.new(@table, [:named_table, :public, :set, read_concurrency: true])
    Process.send_after(self(), :prune, :timer.minutes(10))
    {:ok, %{}}
  end

  @impl true
  def handle_info(:prune, state) do
    cutoff = System.system_time(:second) - @ttl_seconds
    :ets.select_delete(@table, [{{:_, :"$1", :_, :_}, [{:<, :"$1", cutoff}], [true]}])
    Process.send_after(self(), :prune, :timer.minutes(10))
    {:noreply, state}
  end

  @doc "Store a snapshot; returns the opaque capture id."
  def store(instance_id, pcap, meta) when is_binary(pcap) and is_map(meta) do
    cid = Base.url_encode64(:crypto.strong_rand_bytes(9), padding: false)

    :ets.insert(
      @table,
      {cid, System.system_time(:second), pcap, Map.put(meta, "instance_id", instance_id)}
    )

    cid
  end

  def get(cid) do
    cutoff = System.system_time(:second) - @ttl_seconds

    case :ets.lookup(@table, cid) do
      [{^cid, created, pcap, meta}] when created >= cutoff -> {pcap, meta}
      _ -> nil
    end
  end

  # ---- minimal pcap parser (pure) -------------------------------------------

  @doc """
  Parse a classic little-endian pcap into viewer rows (≤ max_packets):
  `%{idx, ts, src, dst, proto, len, info, hex}`.
  """
  def parse(pcap, max_packets \\ 2000)

  def parse(<<_global_header::binary-size(24), rest::binary>>, max_packets) do
    parse_packets(rest, 0, max_packets, [])
  end

  def parse(_short, _max), do: []

  defp parse_packets(_rest, idx, max, acc) when idx >= max, do: Enum.reverse(acc)

  defp parse_packets(
         <<ts_sec::little-32, ts_usec::little-32, incl::little-32, _orig::little-32,
           frame::binary-size(incl), rest::binary>>,
         idx,
         max,
         acc
       )
       when incl > 0 do
    ts = ts_sec + ts_usec / 1_000_000
    parse_packets(rest, idx + 1, max, [summarize(frame, ts, idx) | acc])
  end

  defp parse_packets(_rest, _idx, _max, acc), do: Enum.reverse(acc)

  defp summarize(<<_dst::binary-6, _src::binary-6, 0x0800::16, ip::binary>> = frame, ts, idx) do
    ipv4(ip, ts, idx, byte_size(frame))
  end

  defp summarize(<<_dst::binary-6, _src::binary-6, 0x86DD::16, _::binary>> = frame, ts, idx) do
    %{
      idx: idx,
      ts: rounded(ts),
      src: "",
      dst: "",
      proto: "IPv6",
      len: byte_size(frame),
      info: "",
      hex: hex(frame)
    }
  end

  defp summarize(<<_dst::binary-6, _src::binary-6, 0x0806::16, _::binary>> = frame, ts, idx) do
    %{
      idx: idx,
      ts: rounded(ts),
      src: "",
      dst: "",
      proto: "ARP",
      len: byte_size(frame),
      info: "",
      hex: hex(frame)
    }
  end

  defp summarize(frame, ts, idx) do
    %{
      idx: idx,
      ts: rounded(ts),
      src: "",
      dst: "",
      proto: "RAW",
      len: byte_size(frame),
      info: "",
      hex: hex(frame)
    }
  end

  defp ipv4(
         <<_v_ihl::8, _tos::8, _tlen::16, _id::16, _fl::16, _ttl::8, proto::8, _csum::16, s1::8,
           s2::8, s3::8, s4::8, d1::8, d2::8, d3::8, d4::8, _rest::binary>> = ip,
         ts,
         idx,
         frame_len
       ) do
    <<v_ihl::8, _::binary>> = ip
    ihl_bytes = rem(v_ihl, 16) * 4
    src = "#{s1}.#{s2}.#{s3}.#{s4}"
    dst = "#{d1}.#{d2}.#{d3}.#{d4}"
    payload = binary_part(ip, min(ihl_bytes, byte_size(ip)), max(byte_size(ip) - ihl_bytes, 0))

    {proto_name, info, sport, dport} = l4(proto, payload)

    %{
      idx: idx,
      ts: rounded(ts),
      src: if(sport, do: "#{src}:#{sport}", else: src),
      dst: if(dport, do: "#{dst}:#{dport}", else: dst),
      proto: proto_name,
      len: frame_len,
      info: info,
      hex: hex(binary_part(ip, 0, min(byte_size(ip), 128)))
    }
  end

  defp ipv4(ip, ts, idx, frame_len) do
    %{
      idx: idx,
      ts: rounded(ts),
      src: "",
      dst: "",
      proto: "IP?",
      len: frame_len,
      info: "",
      hex: hex(ip)
    }
  end

  defp l4(6, <<sport::16, dport::16, _seq::32, _ack::32, off_flags::16, _::binary>>) do
    flags = rem(off_flags, 512)

    names =
      [{1, "FIN"}, {2, "SYN"}, {4, "RST"}, {8, "PSH"}, {16, "ACK"}, {32, "URG"}]
      |> Enum.filter(fn {bit, _} -> Bitwise.band(flags, bit) != 0 end)
      |> Enum.map_join(",", &elem(&1, 1))

    {"TCP", names, sport, dport}
  end

  defp l4(6, _short), do: {"TCP", "", nil, nil}

  defp l4(17, <<sport::16, dport::16, _len::16, _csum::16, _::binary>>),
    do: {"UDP", "", sport, dport}

  defp l4(17, _short), do: {"UDP", "", nil, nil}
  defp l4(1, <<type::8, code::8, _::binary>>), do: {"ICMP", "type #{type}/#{code}", nil, nil}
  defp l4(1, _short), do: {"ICMP", "", nil, nil}
  defp l4(50, _), do: {"ESP", "", nil, nil}
  defp l4(other, _), do: {"IP/#{other}", "", nil, nil}

  defp rounded(ts), do: Float.round(ts, 6)

  defp hex(bin) do
    bin
    |> binary_part(0, min(byte_size(bin), 128))
    |> Base.encode16(case: :lower)
    |> String.replace(~r/(..)/, "\\1 ")
    |> String.trim()
  end
end
