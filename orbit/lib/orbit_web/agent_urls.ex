defmodule OrbitWeb.AgentUrls do
  @moduledoc """
  The dashboard URLs an operator may choose for the agent install snippet
  (`DASH_AGENT_URLS`, comma-separated, e.g. a name with and without a
  non-default port). The first entry is the default; without any entry the
  endpoint URL is used, as before.

  The snippet is pasted into a root shell, so only plain `http(s)://host[:port]`
  origins are accepted, and a choice from the UI must be one of the listed
  entries (`pick/2`).
  """

  @origin ~r/\Ahttps?:\/\/[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?\z/

  @doc "Parses `DASH_AGENT_URLS`; entries that are not a plain origin are dropped."
  @spec parse(String.t() | nil) :: [String.t()]
  def parse(nil), do: []

  def parse(raw) when is_binary(raw) do
    raw
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&valid?/1)
    |> Enum.uniq()
  end

  @doc "Configured choices, or the endpoint URL alone."
  @spec list() :: [String.t(), ...]
  def list do
    case parse(Application.get_env(:orbit, :agent_urls_raw)) do
      [] -> [OrbitWeb.Endpoint.url()]
      urls -> urls
    end
  end

  @doc "`choice` when it is one of `urls`, else the default (first)."
  @spec pick([String.t(), ...], String.t() | nil) :: String.t()
  def pick([default | _] = urls, choice), do: if(choice in urls, do: choice, else: default)

  defp valid?(url) do
    case Regex.match?(@origin, url) do
      true -> port_ok?(URI.parse(url).port)
      false -> false
    end
  end

  defp port_ok?(port), do: is_integer(port) and port in 1..65_535
end
