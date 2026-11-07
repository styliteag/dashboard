defmodule Orbit.Capture.Params do
  @moduledoc """
  Validation of packet-capture parameters (live WS capture and snapshot)
  before they reach the agent, where they become `tcpdump` argv as root.

  Security hotfix (option injection): the agent used to split the BPF filter
  into argv tokens, so a "filter" like `-w /path -C 1 -z cmd` set tcpdump
  OPTIONS (write a file, run a post-rotate command). Fixed agents pass the
  filter as one argument after `--`; this server-side guard also protects
  boxes still running an older agent. No real BPF expression starts with
  `-`, and an interface name never does.
  """

  @iface ~r/^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$/

  @doc "`:ok` or `{:error, message}`; blank interface = the agent's default."
  @spec validate(term(), term()) :: :ok | {:error, String.t()}
  def validate(interface, filter) do
    iface = String.trim(to_string(interface || ""))
    filt = String.trim(to_string(filter || ""))

    cond do
      iface != "" and not Regex.match?(@iface, iface) -> {:error, "invalid interface name"}
      String.starts_with?(filt, "-") -> {:error, "a capture filter must not start with '-'"}
      true -> :ok
    end
  end
end
