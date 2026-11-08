defmodule Orbit.Capture.Params do
  @moduledoc """
  Validation of packet-capture parameters (live WS capture and snapshot)
  before they reach the agent, where they become `tcpdump` argv as root.

  Security hotfix (option injection): the agent used to split the BPF filter
  on whitespace into argv tokens, so a "filter" like `-w /path -C 1 -z cmd`
  set tcpdump OPTIONS (write a file, run a post-rotate command) — and not
  only as the first token: `host 1.2.3.4 -w /path` did the same. Fixed
  agents pass the filter as one argument after `--`. This server-side guard
  refuses every whitespace-separated token that starts with `-` followed by
  anything (a bare `-`, BPF's minus, is no option), so boxes still running
  an older agent are protected as well. An interface name never starts with
  `-` either.
  """

  @iface ~r/^[A-Za-z0-9][A-Za-z0-9._:-]{0,31}$/
  @max_filter 1024

  @doc "`:ok` or `{:error, message}`; blank interface = the agent's default."
  @spec validate(term(), term()) :: :ok | {:error, String.t()}
  def validate(interface, filter)
      when (is_binary(interface) or is_nil(interface)) and (is_binary(filter) or is_nil(filter)) do
    iface = String.trim(interface || "")
    filt = String.trim(filter || "")

    cond do
      iface != "" and not Regex.match?(@iface, iface) -> {:error, "invalid interface name"}
      byte_size(filt) > @max_filter -> {:error, "capture filter too long"}
      option_token?(filt) -> {:error, "a capture filter must not contain '-' options"}
      true -> :ok
    end
  end

  def validate(_interface, _filter), do: {:error, "invalid capture parameters"}

  defp option_token?(filt),
    do: filt |> String.split() |> Enum.any?(&String.match?(&1, ~r/\A-./))
end
