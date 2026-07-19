defmodule Orbit.Ecto.UtcDateTime do
  @moduledoc """
  MariaDB DATETIME columns come back **naive-but-UTC** (the Python side tags
  them with `as_utc()`; incident 195e9da "last seen: in 1h"). This type does
  the tagging at the Ecto boundary: loads become `DateTime` in Etc/UTC, dumps
  accept only UTC-aware datetimes and strip the zone.

  Use this for every timestamp column mirrored from the Alembic schema —
  never plain `:naive_datetime` (mirror of the backend's UtcDateTime
  TypeDecorator rule).
  """

  use Ecto.Type

  @impl true
  def type, do: :naive_datetime

  @impl true
  def cast(%DateTime{} = dt), do: {:ok, dt}
  def cast(%NaiveDateTime{} = naive), do: {:ok, DateTime.from_naive!(naive, "Etc/UTC")}

  def cast(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, dt, _offset} -> {:ok, dt}
      _ -> :error
    end
  end

  def cast(_), do: :error

  @impl true
  def load(%NaiveDateTime{} = naive), do: {:ok, DateTime.from_naive!(naive, "Etc/UTC")}
  def load(%DateTime{} = dt), do: {:ok, dt}
  def load(_), do: :error

  @impl true
  def dump(%DateTime{utc_offset: 0, std_offset: 0} = dt), do: {:ok, DateTime.to_naive(dt)}
  # Non-UTC zones are refused, not converted: a silent shift here is exactly
  # the class of bug the backend's UtcDateTime decorator exists to prevent.
  def dump(%DateTime{}), do: :error
  def dump(%NaiveDateTime{} = naive), do: {:ok, naive}
  def dump(_), do: :error
end
