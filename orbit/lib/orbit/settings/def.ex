defmodule Orbit.Settings.Def do
  @moduledoc """
  One editable setting: key, type (:int | :bool | :str), the `DASH_*` env
  variable holding the default, fallback default, optional range/options,
  secret flag. See Orbit.Settings.Registry for the whitelist.
  """

  @enforce_keys [:key, :type, :env, :default]
  defstruct [:key, :type, :env, :default, :min, :max, :options, is_secret: false]

  @type t :: %__MODULE__{}
end
