defmodule OrbitWeb.ParamId do
  @moduledoc """
  Ids in LiveView event params are client-controlled strings. `parse/1`
  turns a strict decimal string into an integer and everything else into
  nil, so handlers can no-op instead of crashing on `String.to_integer/1`.
  """

  @spec parse(term()) :: integer() | nil
  def parse(raw) when is_binary(raw) do
    case Integer.parse(raw) do
      {n, ""} -> n
      _ -> nil
    end
  end

  def parse(_), do: nil
end
