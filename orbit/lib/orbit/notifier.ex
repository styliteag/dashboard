defmodule Orbit.Notifier do
  @moduledoc """
  Notification dispatcher — port of notifications/notifier.py. Channels:
  Mattermost (incoming webhook), Telegram and Email (SMTP via gen_smtp:
  starttls/ssl/none, optional auth). Per-group channel overrides stay
  python-side until their slice. Config lives in the shared settings
  registry (secrets fernet-encrypted); a channel only receives an alert
  when the selection rules resolve on for its (check_key, instance) —
  base default OFF, so nothing spams before rules exist (Orbit.Selection).

  Every real alert is mirrored onto the audit log stream regardless of
  channel config. Failures are logged, never raised; `dispatch_async/5` is
  fire-and-forget (Task.start) so latency-sensitive callers (agent ingest)
  are never blocked by channel latency.

  SSRF guard for the user-configured webhook URL: loopback, link-local
  (incl. 169.254.169.254 cloud metadata), reserved, multicast and
  unspecified addresses are refused; RFC1918 private ranges are
  deliberately ALLOWED (self-hosted Mattermost on the internal net is the
  common legitimate target — notifier.py parity).

  Test seams: `opts[:settings]` (map override), `opts[:req_plug]`.
  """

  require Logger

  @availability "availability"

  @channels ~w(mattermost telegram email)

  @mute_key %{
    "mattermost" => "notify_mattermost_muted",
    "telegram" => "notify_telegram_muted",
    "email" => "notify_email_muted"
  }

  @type result :: %{channel: String.t(), status: String.t(), detail: String.t()}

  @doc "Fire-and-forget alert about `check_key` for `instance_id`."
  def dispatch_async(title, message, instance_id, level \\ "info", check_key \\ @availability) do
    Task.start(fn -> send_notification(title, message, instance_id, level, check_key) end)
    :ok
  end

  @doc "Send an alert to every selected channel (blocking; logs, never raises)."
  def send_notification(title, message, instance_id, level \\ "info", check_key \\ @availability) do
    # Mirror onto the always-visible event stream, even with no channel set.
    Logger.info(
      "alert title=#{inspect(title)} instance_id=#{instance_id} " <>
        "check_key=#{check_key} level=#{level} message=#{inspect(message)}"
    )

    dispatch(title, message, check_key, instance_id, respect_routes: true)
  end

  @doc """
  Test send for the Settings surface: bypasses routing and mutes (a test
  proves connectivity), reaches every configured channel.
  """
  def send_test(opts \\ []) do
    dispatch(
      "✅ Orbit test notification",
      "If you can read this, Orbit notifications are working.",
      @availability,
      nil,
      Keyword.put(opts, :respect_routes, false)
    )
  end

  # Per-group channel overrides (channel_config.py): JSON key in the
  # fernet-encrypted group_channels.config_enc → the notify_* setting the
  # (unchanged) senders read. A configured group channel REPLACES the global
  # target for that send; missing JSON keys read as "" (never the global
  # value); routing + mutes stay global either way.
  @channel_fields %{
    "mattermost" => %{"notify_mattermost_url" => "url"},
    "telegram" => %{
      "notify_telegram_token" => "token",
      "notify_telegram_chat_id" => "chat_id"
    },
    "email" => %{
      "notify_email_smtp_host" => "smtp_host",
      "notify_email_smtp_port" => "smtp_port",
      "notify_email_security" => "security",
      "notify_email_from" => "from",
      "notify_email_to" => "to",
      "notify_email_username" => "username",
      "notify_email_password" => "password"
    }
  }

  @doc """
  Whether a channel has enough config to actually send — the same predicate
  the senders use to decide skip-vs-send (channel_configured parity; drives
  the "subscribed but not configured" hint in the selection tree).
  """
  def channel_configured?(channel, settings \\ &setting/1)

  def channel_configured?("mattermost", settings) do
    to_string(settings.("notify_mattermost_url") || "") != ""
  end

  def channel_configured?("telegram", settings) do
    to_string(settings.("notify_telegram_token") || "") != "" and
      to_string(settings.("notify_telegram_chat_id") || "") != ""
  end

  def channel_configured?("email", settings) do
    to_string(settings.("notify_email_smtp_host") || "") != "" and
      to_string(settings.("notify_email_from") || "") != "" and
      parse_recipients(to_string(settings.("notify_email_to") || "")) != []
  end

  def channel_configured?(_channel, _settings), do: false

  @doc false
  def dispatch(title, message, check_key, instance_id, opts) do
    respect_routes = Keyword.get(opts, :respect_routes, true)
    settings = Keyword.get(opts, :settings, &setting/1)

    # `only:` restricts a send to one channel (per-channel test button).
    channels =
      case Keyword.get(opts, :only) do
        nil -> @channels
        channel -> Enum.filter(@channels, &(&1 == channel))
      end

    overrides =
      Keyword.get_lazy(opts, :overrides, fn ->
        if instance_id, do: group_channel_overrides(instance_id), else: %{}
      end)

    Enum.map(channels, fn channel ->
      cond do
        respect_routes and not Orbit.Selection.is_on_live(channel, check_key, instance_id) ->
          %{channel: channel, status: "skipped", detail: "not subscribed"}

        respect_routes and truthy(settings.(@mute_key[channel])) ->
          %{channel: channel, status: "skipped", detail: "muted"}

        true ->
          send_channel(channel, settings_for(channel, settings, overrides), title, message, opts)
      end
    end)
  end

  @doc """
  Settings accessor for one channel send: with a group override, the
  channel's own notify_* keys come from the override config (absent JSON
  keys read as "", GroupChannelSettings parity); everything else — mutes,
  other channels — stays global.
  """
  def settings_for(channel, settings, overrides) do
    case overrides do
      %{^channel => config} when is_map(config) ->
        fields = @channel_fields[channel] || %{}

        fn key ->
          case fields do
            %{^key => json_key} -> Map.get(config, json_key, "")
            _ -> settings.(key)
          end
        end

      _ ->
        settings
    end
  end

  # `channel -> decrypted config` for the instance's group. Fail-OPEN to %{}
  # (= global targets) on any error — a broken row or missing fernet key must
  # degrade an alert to the global channel, never drop it.
  defp group_channel_overrides(instance_id) do
    rows =
      Orbit.Repo.query!(
        "SELECT gc.channel, gc.config_enc FROM group_channels gc " <>
          "JOIN instances i ON i.group_id = gc.group_id WHERE i.id = ?",
        [instance_id]
      ).rows

    Map.new(rows, fn [channel, config_enc] ->
      {channel, config_enc |> Orbit.Crypto.decrypt() |> Jason.decode!()}
    end)
  rescue
    e ->
      Logger.warning(
        "notify.group_channels_load_failed instance_id=#{instance_id} error=#{Exception.message(e)}"
      )

      %{}
  catch
    # A connection-pool checkout does not raise, it EXITS — an exhausted or
    # restarting pool therefore killed the caller straight through the rescue
    # above, in a module whose whole contract is "logs, never raises". The
    # ingest path that dispatches alerts would have died with it.
    kind, reason ->
      Logger.warning(
        "notify.group_channels_load_failed instance_id=#{instance_id} " <>
          "error=#{kind} #{inspect(reason)}"
      )

      %{}
  end

  # -- channels --------------------------------------------------------------

  defp send_channel("mattermost", settings, title, message, opts) do
    url = to_string(settings.("notify_mattermost_url") || "")
    # Seam: tests inject a guard fn — the default resolves DNS for real.
    ssrf_check = Keyword.get(opts, :ssrf_check, &ssrf_block_reason/1)

    cond do
      url == "" ->
        %{channel: "mattermost", status: "skipped", detail: ""}

      reason = ssrf_check.(url) ->
        Logger.warning("notify.mattermost.blocked reason=#{reason}")
        %{channel: "mattermost", status: "failed", detail: reason}

      true ->
        post("mattermost", url, %{text: "**#{title}**\n#{message}"}, opts)
    end
  end

  defp send_channel("telegram", settings, title, message, opts) do
    token = to_string(settings.("notify_telegram_token") || "")
    chat = to_string(settings.("notify_telegram_chat_id") || "")

    if token == "" or chat == "" do
      %{channel: "telegram", status: "skipped", detail: ""}
    else
      # Plain text, no parse_mode (notifier.py lesson): with Markdown an
      # unbalanced metacharacter in an error string made Telegram 400 the
      # whole message — reliability of delivery beats a bold title.
      post(
        "telegram",
        "https://api.telegram.org/bot#{token}/sendMessage",
        %{chat_id: chat, text: "#{title}\n#{message}"},
        opts
      )
    end
  end

  defp send_channel("email", settings, title, message, opts) do
    host = to_string(settings.("notify_email_smtp_host") || "")
    from = to_string(settings.("notify_email_from") || "")
    recipients = parse_recipients(to_string(settings.("notify_email_to") || ""))

    if host == "" or from == "" or recipients == [] do
      %{channel: "email", status: "skipped", detail: ""}
    else
      send_email(settings, host, from, recipients, title, message, opts)
    end
  end

  defp parse_recipients(raw) do
    raw |> String.split(~r/[,\s]+/, trim: true) |> Enum.reject(&(&1 == ""))
  end

  defp send_email(settings, host, from, recipients, title, message, opts) do
    # Test seam: inject a sender fn; the default is the real gen_smtp path.
    sender = Keyword.get(opts, :smtp, &deliver_email/2)

    config = %{
      host: host,
      port: to_int(settings.("notify_email_smtp_port"), 587),
      security: to_string(settings.("notify_email_security") || "starttls"),
      username: to_string(settings.("notify_email_username") || ""),
      password: to_string(settings.("notify_email_password") || ""),
      from: from,
      recipients: recipients
    }

    mail =
      "From: #{from}\r\nTo: #{Enum.join(recipients, ", ")}\r\n" <>
        "Subject: #{title}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n#{message}"

    case sender.(config, mail) do
      :ok ->
        Logger.info("notify.email.sent recipients=#{length(recipients)}")
        %{channel: "email", status: "sent", detail: ""}

      {:error, reason} ->
        Logger.warning("notify.email.failed error=#{inspect(reason)}")
        %{channel: "email", status: "failed", detail: to_string(inspect(reason))}
    end
  end

  # gen_smtp delivery (_smtp_send port). security: "ssl" = implicit TLS,
  # "starttls" = upgrade after connect, "none" = plaintext; auth only when a
  # username is set. Blocking — runs on the caller (already a Task via
  # dispatch_async, or the synchronous test path).
  defp deliver_email(cfg, mail) do
    tls =
      case cfg.security do
        "ssl" -> :always
        "starttls" -> :if_available
        _ -> :never
      end

    base = [relay: cfg.host, port: cfg.port, tls: tls, ssl: cfg.security == "ssl"]

    smtp_opts =
      if cfg.username != "",
        do: base ++ [username: cfg.username, password: cfg.password, auth: :always],
        else: base

    envelope = {cfg.from, cfg.recipients, mail}

    case :gen_smtp_client.send_blocking(envelope, smtp_opts) do
      receipt when is_binary(receipt) -> :ok
      {:error, _type, reason} -> {:error, reason}
      {:error, reason} -> {:error, reason}
    end
  end

  defp to_int(v, default) do
    case Integer.parse(to_string(v || "")) do
      {n, ""} -> n
      _ -> default
    end
  end

  defp post(channel, url, body, opts) do
    base = [url: url, json: body, receive_timeout: 10_000, retry: false]

    req_opts =
      case Keyword.get(opts, :req_plug, Application.get_env(:orbit, :notify_req_plug)) do
        nil -> base
        plug -> Keyword.put(base, :plug, plug)
      end

    case Req.post(req_opts) do
      {:ok, %{status: status}} when status < 400 ->
        Logger.info("notify.#{channel}.sent status=#{status}")
        %{channel: channel, status: "sent", detail: ""}

      {:ok, %{status: status}} ->
        Logger.warning("notify.#{channel}.failed status=#{status}")
        %{channel: channel, status: "failed", detail: "HTTP #{status}"}

      {:error, error} ->
        Logger.warning("notify.#{channel}.failed error=#{Exception.message(error)}")
        %{channel: channel, status: "failed", detail: Exception.message(error)}
    end
  end

  # -- SSRF guard ------------------------------------------------------------

  @doc """
  Reject a webhook URL whose host resolves to a dangerous-but-never-
  legitimate address. Returns a reason string or nil.
  """
  def ssrf_block_reason(url) do
    uri = URI.parse(url)

    cond do
      uri.scheme not in ["http", "https"] or uri.host in [nil, ""] ->
        "URL must be http(s) with a host"

      true ->
        case resolve_addrs(uri.host) do
          {:error, _} -> "host does not resolve"
          {:ok, addrs} -> Enum.find_value(addrs, &blocked_addr_reason/1)
        end
    end
  end

  defp resolve_addrs(host) do
    chars = String.to_charlist(host)

    case :inet.parse_strict_address(chars) do
      {:ok, addr} ->
        {:ok, [addr]}

      {:error, _} ->
        v4 = :inet_res.lookup(chars, :in, :a, timeout: 5_000)
        v6 = :inet_res.lookup(chars, :in, :aaaa, timeout: 5_000)
        if v4 == [] and v6 == [], do: {:error, :nxdomain}, else: {:ok, v4 ++ v6}
    end
  end

  # Loopback, link-local (incl. cloud metadata 169.254/16), reserved (240/4),
  # multicast, unspecified. RFC1918 stays allowed on purpose (moduledoc).
  defp blocked_addr_reason({127, _, _, _} = a), do: blocked(a)
  defp blocked_addr_reason({169, 254, _, _} = a), do: blocked(a)
  defp blocked_addr_reason({0, _, _, _} = a), do: blocked(a)
  defp blocked_addr_reason({n, _, _, _} = a) when n >= 224, do: blocked(a)
  defp blocked_addr_reason({0, 0, 0, 0, 0, 0, 0, 0} = a), do: blocked(a)
  defp blocked_addr_reason({0, 0, 0, 0, 0, 0, 0, 1} = a), do: blocked(a)

  defp blocked_addr_reason({w, _, _, _, _, _, _, _} = a) when w >= 0xFE80 and w <= 0xFEBF,
    do: blocked(a)

  defp blocked_addr_reason({w, _, _, _, _, _, _, _} = a) when w >= 0xFF00, do: blocked(a)
  defp blocked_addr_reason(_), do: nil

  defp blocked(addr), do: "blocked address #{addr |> :inet.ntoa() |> to_string()}"

  # -- helpers ---------------------------------------------------------------

  defp setting(key) do
    Orbit.Settings.effective(key)
  rescue
    # Unknown key (email settings not yet in orbit's registry) reads as unset.
    _ -> ""
  end

  defp truthy(value), do: value in [true, "true", "1", 1]
end
