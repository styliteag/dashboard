defmodule Orbit.Groups.Channels do
  @moduledoc """
  Per-group notification-channel config (groups/channels.py port). One
  fernet-encrypted JSON blob per (group, channel); a configured row REPLACES
  the global channel target for that group's instances (Orbit.Notifier reads
  it at dispatch), absence = global fallback.

  Field shapes, secret flags and the mask convention mirror
  notifications/channel_config.py — the UI shows `@mask` instead of secret
  values, and accepts it back as "keep the stored value".
  """

  require Logger

  @mask "••••••"
  @channels ~w(mattermost telegram email)

  # {json key, secret?, required?, options | nil}
  @fields %{
    "mattermost" => [{"url", true, true, nil}],
    "telegram" => [
      {"token", true, true, nil},
      {"chat_id", false, true, nil}
    ],
    "email" => [
      {"smtp_host", false, true, nil},
      {"smtp_port", false, false, nil},
      {"security", false, false, ~w(starttls ssl none)},
      {"from", false, true, nil},
      {"to", false, true, nil},
      {"username", false, false, nil},
      {"password", true, false, nil}
    ]
  }

  def channels, do: @channels
  def mask, do: @mask

  @doc "Field spec for the UI: [%{name, label?, secret, required}]."
  def fields(channel) do
    for {name, secret, required, _options} <- @fields[channel] || [] do
      %{name: name, secret: secret, required: required}
    end
  end

  @doc "Configured channels for a group: %{channel => masked config map}."
  def list(group_id) do
    rows =
      Orbit.Repo.query!(
        "SELECT channel, config_enc FROM group_channels WHERE group_id = ? ORDER BY channel",
        [group_id]
      ).rows

    Map.new(rows, fn [channel, config_enc] ->
      config = config_enc |> Orbit.Crypto.decrypt() |> Jason.decode!()
      {channel, masked(channel, config)}
    end)
  rescue
    e ->
      Logger.warning("group_channels.list_failed group_id=#{group_id} #{Exception.message(e)}")
      %{}
  catch
    kind, reason ->
      Logger.warning("group_channels.list_failed group_id=#{group_id} #{kind} #{inspect(reason)}")
      %{}
  end

  @doc """
  Validate a full-replace payload against the channel's field spec (pure).
  Unknown fields are rejected; a secret sent as the mask keeps the stored
  value; required fields must end up non-empty. Mattermost URLs are
  SSRF-checked at save time (the sender re-checks at send time).
  Returns `{:ok, config} | {:error, message}`.
  """
  def validate(channel, incoming, existing, opts \\ []) do
    fields = @fields[channel] || []
    known = MapSet.new(fields, fn {name, _, _, _} -> name end)
    unknown = incoming |> Map.keys() |> Enum.reject(&MapSet.member?(known, &1)) |> Enum.sort()

    with [] <- unknown,
         {:ok, config} <- build_config(fields, incoming, existing),
         :ok <- check_port(channel, config),
         :ok <- check_ssrf(channel, config, opts) do
      {:ok, config}
    else
      [_ | _] = unknown -> {:error, "unknown fields: #{Enum.join(unknown, ", ")}"}
      {:error, msg} -> {:error, msg}
    end
  end

  defp build_config(fields, incoming, existing) do
    Enum.reduce_while(fields, {:ok, %{}}, fn {name, secret, required, options}, {:ok, acc} ->
      value = incoming |> Map.get(name, "") |> to_string() |> String.trim()
      value = if secret and value == @mask, do: Map.get(existing, name, ""), else: value

      cond do
        required and value == "" ->
          {:halt, {:error, "field '#{name}' is required"}}

        value != "" and options != nil and value not in options ->
          {:halt, {:error, "field '#{name}' must be one of #{Enum.join(options, ", ")}"}}

        true ->
          {:cont, {:ok, Map.put(acc, name, value)}}
      end
    end)
  end

  defp check_port("email", %{"smtp_port" => port}) when port != "" do
    case Integer.parse(port) do
      {n, ""} when n >= 1 and n <= 65_535 -> :ok
      _ -> {:error, "invalid smtp_port"}
    end
  end

  defp check_port(_channel, _config), do: :ok

  defp check_ssrf("mattermost", %{"url" => url}, opts) do
    ssrf_check = Keyword.get(opts, :ssrf_check, &Orbit.Notifier.ssrf_block_reason/1)

    case ssrf_check.(url) do
      nil -> :ok
      reason -> {:error, "URL rejected: #{reason}"}
    end
  end

  defp check_ssrf(_channel, _config, _opts), do: :ok

  @doc """
  Decrypted config for one (group, channel): `{:ok, config}` — `%{}` when the
  row is absent — or `:error` when it could not be read.

  Deliberately NOT collapsing the failure into `%{}`. `upsert/5` feeds this to
  `validate/4` so that a masked secret submitted unchanged keeps its stored
  value; an empty map there means "the operator cleared it", so a read failure
  would have silently wiped the group's stored credentials on the next save.
  A pool checkout exits rather than raising, so the old rescue did not even
  cover the likeliest failure.
  """
  def existing_config(group_id, channel) do
    case Orbit.Repo.query!(
           "SELECT config_enc FROM group_channels WHERE group_id = ? AND channel = ?",
           [group_id, channel]
         ).rows do
      [[config_enc]] -> {:ok, config_enc |> Orbit.Crypto.decrypt() |> Jason.decode!()}
      [] -> {:ok, %{}}
    end
  rescue
    e ->
      Logger.warning("group_channels.existing_config_failed group_id=#{group_id} #{inspect(e)}")
      :error
  catch
    kind, reason ->
      Logger.warning(
        "group_channels.existing_config_failed group_id=#{group_id} #{kind} #{inspect(reason)}"
      )

      :error
  end

  @doc "Validate + persist one channel config. `{:ok, masked} | {:error, msg}`."
  def upsert(group_id, channel, incoming, user, opts \\ []) do
    with true <- channel in @channels || {:error, "unknown channel"},
         {:ok, existing} <- existing_config(group_id, channel),
         {:ok, config} <- validate(channel, incoming, existing, opts) do
      blob = config |> Jason.encode!() |> Orbit.Crypto.encrypt()

      Orbit.Repo.query!(
        "INSERT INTO group_channels (group_id, channel, config_enc, created_at, updated_at) " <>
          "VALUES (?, ?, ?, NOW(), NOW()) " <>
          "ON DUPLICATE KEY UPDATE config_enc = VALUES(config_enc), updated_at = NOW()",
        [group_id, channel, blob]
      )

      Orbit.Audit.write(
        action: "group.channel.set",
        result: "ok",
        user_id: user.id,
        target_type: "group",
        target_id: group_id,
        detail: %{
          "channel" => channel,
          "fields" =>
            config
            |> Enum.filter(fn {_k, v} -> v != "" end)
            |> Enum.map(&elem(&1, 0))
            |> Enum.sort()
        }
      )

      {:ok, masked(channel, config)}
    else
      # Refuse rather than save against an unknown baseline — writing here
      # would blank whatever masked secrets the form did not resend. The
      # caller's else only knows nil and {:error, msg}, so translate.
      :error ->
        {:error, "could not read the current configuration — nothing was saved"}

      other ->
        other
    end
  end

  @doc "Remove one channel override (falls back to the global target)."
  def delete(group_id, channel, user) do
    %{num_rows: n} =
      Orbit.Repo.query!(
        "DELETE FROM group_channels WHERE group_id = ? AND channel = ?",
        [group_id, channel]
      )

    if n > 0 do
      Orbit.Audit.write(
        action: "group.channel.delete",
        result: "ok",
        user_id: user.id,
        target_type: "group",
        target_id: group_id,
        detail: %{"channel" => channel}
      )
    end

    :ok
  end

  @doc "Secrets replaced by the mask; unknown stored keys dropped."
  def masked(channel, config) do
    for {name, secret, _required, _options} <- @fields[channel] || [],
        Map.has_key?(config, name),
        into: %{} do
      value = config[name]
      {name, if(secret and value not in [nil, ""], do: @mask, else: value)}
    end
  end
end
