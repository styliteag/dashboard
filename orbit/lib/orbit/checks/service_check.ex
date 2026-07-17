defmodule Orbit.Checks.ServiceCheck do
  @moduledoc """
  One evaluated service for one instance — mirror of checks/models.py.

  `state` follows the Checkmk convention (0=OK 1=WARN 2=CRIT 3=UNKNOWN) so
  the export maps 1:1. Severity ordering is NOT the numeric order: UNKNOWN
  ("could not check") sorts BELOW WARN — `severity/1` gives the sort rank
  CRIT > WARN > UNKNOWN > OK.
  """

  @enforce_keys [:key, :state, :summary]
  defstruct [:key, :state, :summary, metrics: []]

  @type t :: %__MODULE__{key: String.t(), state: 0..3, summary: String.t(), metrics: [map()]}

  # Checkmk convention.
  def ok, do: 0
  def warn, do: 1
  def crit, do: 2
  def unknown, do: 3

  @doc "Sort rank so CRIT > WARN > UNKNOWN > OK (UNKNOWN below WARN)."
  @spec severity(0..3) :: 0..3
  def severity(2), do: 3
  def severity(1), do: 2
  def severity(3), do: 1
  def severity(0), do: 0

  @doc "One Checkmk perfdata datum: name=value;warn;crit (warn/crit optional)."
  def metric(name, value, opts \\ []) do
    %{
      name: name,
      value: value,
      warn: Keyword.get(opts, :warn),
      crit: Keyword.get(opts, :crit),
      unit: Keyword.get(opts, :unit, "")
    }
  end
end
