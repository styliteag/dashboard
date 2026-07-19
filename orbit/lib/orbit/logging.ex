defmodule Orbit.Logging do
  @moduledoc """
  Runtime consumer of the `log_level` / `log_format` settings. Unlike the
  python backend (uvicorn reads them once at startup → needs-restart badge),
  the BEAM reconfigures the default logger handler live: `apply/0` runs at
  boot and after every settings write of a log_* key, so a changed level or
  format takes effect immediately.

  `format_json/4` is a plain Logger `{module, function}` formatter — one
  JSON object per line (python log_format=json parity). It must never raise:
  a raising formatter takes the logger down with it, so encoding falls back
  to `inspect` on anything Jason refuses.

  Disabled via config `:orbit, :apply_log_settings, false` in :test —
  the suite pins its own level (config/test.exs) and must not have it
  flipped mid-run by settings tests.
  """

  # Mirror of the compile-time default in config.exs — restored when
  # log_format goes (back) to "console".
  @console_format "$time $metadata[$level] $message\n"
  @metadata [:request_id]

  @doc "Re-apply level+format when `key` is a log setting (settings-write hook)."
  @spec maybe_apply(String.t()) :: :ok
  def maybe_apply("log_" <> _), do: apply()
  def maybe_apply(_key), do: :ok

  @doc "Read effective log_level/log_format and reconfigure the default handler."
  @spec apply() :: :ok
  def apply do
    if Application.get_env(:orbit, :apply_log_settings, true) do
      Logger.configure(level: level_atom(Orbit.Settings.effective("log_level")))
      set_format(Orbit.Settings.effective("log_format"))
    end

    :ok
  end

  defp level_atom("debug"), do: :debug
  defp level_atom("warning"), do: :warning
  defp level_atom("error"), do: :error
  defp level_atom(_), do: :info

  defp set_format(format) do
    formatter =
      case format do
        "json" -> Logger.Formatter.new(format: {__MODULE__, :format_json}, metadata: @metadata)
        _ -> Logger.Formatter.new(format: @console_format, metadata: @metadata)
      end

    :logger.update_handler_config(:default, :formatter, formatter)
  end

  @doc "One JSON object per line: ts, level, msg + whitelisted metadata."
  def format_json(level, message, {date, {h, mi, s, ms}}, metadata) do
    {y, mo, d} = date

    entry =
      %{
        "ts" =>
          :io_lib.format("~4..0B-~2..0B-~2..0BT~2..0B:~2..0B:~2..0B.~3..0BZ", [
            y,
            mo,
            d,
            h,
            mi,
            s,
            ms
          ])
          |> IO.iodata_to_binary(),
        "level" => to_string(level),
        "msg" => IO.chardata_to_string(message)
      }
      |> Map.merge(json_metadata(metadata))

    [Jason.encode_to_iodata!(entry), "\n"]
  rescue
    # A raising formatter kills the handler — degrade to inspect, never crash.
    _ -> ["{\"level\":\"#{level}\",\"msg\":#{inspect(to_string_safe(message))}}", "\n"]
  end

  defp json_metadata(metadata) do
    for {k, v} <- metadata, into: %{} do
      {to_string(k), if(is_binary(v), do: v, else: inspect(v))}
    end
  end

  defp to_string_safe(message) do
    IO.chardata_to_string(message)
  rescue
    _ -> inspect(message)
  end
end
