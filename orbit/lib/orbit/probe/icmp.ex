defmodule Orbit.Probe.ICMP do
  @moduledoc """
  ICMP echo with no external binary — port of the deleted `probe/icmp.py`.

  Prefers an unprivileged `:dgram`/`:icmp` socket (works whenever the kernel's
  `ping_group_range` permits it, which is the Docker default), falling back to
  `:raw`. No `ping(8)` dependency, so the runtime image needs nothing extra and
  there is no output format to parse per platform.

  Raw sockets hand back the IPv4 header in front of the ICMP message; datagram
  sockets do not — the reply parser accounts for both. The kernel also rewrites
  the echo id on a datagram socket, so replies are matched on the PAYLOAD, not
  on the id.
  """

  import Bitwise

  @icmp_echo_request 8
  @icmp_echo_reply 0
  @ip_header_len 20
  @payload_size 32

  @doc """
  One echo to `host`. Returns the round-trip time in ms, or an error.

  `host` may be an IPv4 address or a name; resolution failures are reported as
  such rather than as a timeout, because "cannot resolve" and "does not answer"
  are different operational problems.
  """
  @spec ping(String.t(), timeout: non_neg_integer()) :: {:ok, float()} | {:error, atom()}
  def ping(host, opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 2_000)

    with {:ok, addr} <- resolve(host),
         {:ok, sock} <- open() do
      try do
        echo(sock, addr, timeout)
      after
        :socket.close(sock)
      end
    end
  end

  defp resolve(host) do
    charlist = String.to_charlist(host)

    case :inet.parse_address(charlist) do
      {:ok, addr} ->
        {:ok, addr}

      _ ->
        case :inet.getaddr(charlist, :inet) do
          {:ok, addr} -> {:ok, addr}
          {:error, _} -> {:error, :nxdomain}
        end
    end
  end

  # Unprivileged first; :raw only if the kernel refuses the datagram socket.
  defp open do
    case :socket.open(:inet, :dgram, :icmp) do
      {:ok, s} -> {:ok, s}
      {:error, _} -> raw_open()
    end
  end

  defp raw_open do
    case :socket.open(:inet, :raw, :icmp) do
      {:ok, s} -> {:ok, s}
      {:error, reason} -> {:error, reason}
    end
  end

  defp echo(sock, addr, timeout) do
    payload = :crypto.strong_rand_bytes(@payload_size)
    packet = build(payload)
    dest = %{family: :inet, port: 0, addr: addr}
    started = System.monotonic_time(:microsecond)

    with :ok <- send_to(sock, packet, dest) do
      await_reply(sock, payload, started, deadline(timeout))
    end
  end

  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout

  defp send_to(sock, packet, dest) do
    case :socket.sendto(sock, packet, dest) do
      :ok -> :ok
      {:error, _} -> {:error, :send_failed}
    end
  end

  # Keep reading until OUR payload comes back: a shared ICMP socket sees other
  # replies too, and on a datagram socket the kernel rewrites the echo id, so
  # the payload is the only thing we can match on.
  defp await_reply(sock, payload, started, deadline) do
    remaining = deadline - System.monotonic_time(:millisecond)

    if remaining <= 0 do
      {:error, :timeout}
    else
      case :socket.recv(sock, 0, remaining) do
        {:ok, data} ->
          if echo_reply?(data, payload) do
            {:ok, Float.round((System.monotonic_time(:microsecond) - started) / 1000, 2)}
          else
            await_reply(sock, payload, started, deadline)
          end

        {:error, :timeout} ->
          {:error, :timeout}

        {:error, _} ->
          {:error, :recv_failed}
      end
    end
  end

  defp echo_reply?(data, payload) do
    case strip_ip_header(data) do
      <<@icmp_echo_reply, 0, _csum::16, _id::16, _seq::16, rest::binary>> -> rest == payload
      _ -> false
    end
  end

  # A raw socket prepends the IPv4 header, a datagram socket does not.
  defp strip_ip_header(<<4::4, ihl::4, _rest::binary>> = data)
       when byte_size(data) > @ip_header_len do
    skip = ihl * 4
    <<_::binary-size(^skip), icmp::binary>> = data
    icmp
  end

  defp strip_ip_header(data), do: data

  defp build(payload) do
    body = <<@icmp_echo_request, 0, 0::16, 0::16, 1::16, payload::binary>>
    <<head::binary-size(2), _::16, tail::binary>> = body
    <<head::binary, checksum(body)::16, tail::binary>>
  end

  @doc false
  def checksum(binary) do
    sum =
      for <<word::16 <- pad(binary)>>, reduce: 0 do
        acc -> acc + word
      end

    sum = (sum &&& 0xFFFF) + (sum >>> 16)
    Bitwise.bnot(sum + (sum >>> 16)) &&& 0xFFFF
  end

  defp pad(b) when rem(byte_size(b), 2) == 1, do: b <> <<0>>
  defp pad(b), do: b
end
