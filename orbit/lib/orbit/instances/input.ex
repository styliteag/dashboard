defmodule Orbit.Instances.Input do
  @moduledoc """
  Server-side checks for the instance create/edit params.

  `OrbitWeb.InstanceForm` shows the same rules as inline hints, but a crafted
  LiveView event never passes through it — so the context refuses here, before
  anything is coerced or stored. Private address ranges stay allowed on
  purpose: firewalls on internal IPs are the normal case.
  """

  alias Orbit.Net.TLS

  # Byte caps follow the column widths (text columns get a sane bound).
  @max_bytes %{
    "name" => 128,
    "slug" => 63,
    "base_url" => 512,
    "ping_url" => 512,
    "location" => 255,
    "ssh_user" => 64,
    "notes" => 16_384,
    "api_key" => 1024,
    "api_secret" => 1024,
    "ssh_key" => 16_384,
    "ca_bundle" => 65_535,
    "transport" => 16,
    "device_type" => 32,
    "ssh_port" => 8,
    "poll_interval_seconds" => 8,
    "push_interval_seconds" => 8,
    "tags" => 4096
  }

  @interval_range 5..86_400
  # Text fields that may also arrive as integers (a LiveView event).
  @int_keys ~w(ssh_port poll_interval_seconds push_interval_seconds)

  @type error ::
          :bad_params
          | :bad_base_url
          | :bad_ping_url
          | :bad_ca_bundle
          | :bad_ssh_port
          | :bad_interval

  @doc "`:ok` or the first failing rule as `{:error, reason}`."
  @spec validate(map()) :: :ok | {:error, error()}
  def validate(params) when is_map(params) do
    with :ok <- check_types(params),
         :ok <- check(params, "base_url", &http_url_list?/1, :bad_base_url),
         :ok <- check(params, "ping_url", &ping_target?/1, :bad_ping_url),
         :ok <- check(params, "ca_bundle", &(TLS.bundle_opts(&1) != nil), :bad_ca_bundle),
         :ok <- check(params, "ssh_port", &int_in?(&1, 1..65_535), :bad_ssh_port),
         :ok <-
           check(params, "poll_interval_seconds", &int_in?(&1, @interval_range), :bad_interval) do
      check(params, "push_interval_seconds", &int_in?(&1, @interval_range), :bad_interval)
    end
  end

  def validate(_), do: {:error, :bad_params}

  @doc """
  True when `url` is an absolute http(s) URL with a host and no whitespace or
  control characters.
  """
  @spec http_url?(term()) :: boolean()
  def http_url?(url) when is_binary(url) do
    v = String.trim(url)

    with false <- String.match?(v, ~r/[\s\x00-\x1f\x7f]/),
         {:ok, %URI{scheme: scheme, host: host}} when scheme in ["http", "https"] <-
           URI.new(v),
         true <- is_binary(host) and host != "" do
      true
    else
      _ -> false
    end
  end

  def http_url?(_), do: false

  # base_url may list several comma-separated URLs (failover addresses).
  defp http_url_list?(v) do
    case split_urls(v) do
      [] -> false
      urls -> Enum.all?(urls, &http_url?/1)
    end
  end

  defp split_urls(v),
    do: v |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))

  @doc """
  True when `new_base_url` points at an origin (scheme, host, port — case and
  default port normalised) that `old_base_url` does not list. Dropping a
  failover URL is not a new origin; adding or changing one is.
  """
  @spec new_origin?(term(), term()) :: boolean()
  def new_origin?(new_base_url, old_base_url) do
    old = origins(old_base_url)
    Enum.any?(origins(new_base_url), &(&1 not in old))
  end

  defp origins(v) when is_binary(v), do: v |> split_urls() |> Enum.map(&origin/1)
  defp origins(_), do: []

  defp origin(url) do
    case URI.new(url) do
      {:ok, %URI{scheme: s, host: h, port: p}} when is_binary(s) and is_binary(h) ->
        {String.downcase(s), String.downcase(h), p}

      _ ->
        url
    end
  end

  # A ping target is a full http(s) URL, or a bare host / IP with an optional
  # port — the same two forms Orbit.Probe distinguishes.
  defp ping_target?(v) do
    v = String.trim(v)

    cond do
      String.contains?(v, "://") -> http_url?(v)
      String.contains?(v, "[") -> false
      true -> bare_host_port?(v)
    end
  end

  defp bare_host_port?(v) do
    case String.split(v, ":") do
      [host, port] -> Orbit.Net.host_arg?(host) and int_in?(port, 1..65_535)
      _ -> Orbit.Net.host_arg?(v)
    end
  end

  defp int_in?(v, range) when is_integer(v), do: v in range

  defp int_in?(v, range) do
    case Integer.parse(String.trim(v)) do
      {n, ""} -> n in range
      _ -> false
    end
  end

  # Blank = "not set / keep" everywhere in this form, so only a non-blank
  # value is checked. Integers are range-checked too; check_types/1 lets
  # them through only for the numeric fields.
  defp check(params, key, ok?, reason) do
    case Map.get(params, key) do
      v when is_binary(v) -> if String.trim(v) == "" or ok?.(v), do: :ok, else: {:error, reason}
      v when is_integer(v) -> if ok?.(v), do: :ok, else: {:error, reason}
      _ -> :ok
    end
  end

  defp check_types(params) do
    if Enum.all?(params, &type_ok?/1), do: :ok, else: {:error, :bad_params}
  end

  defp type_ok?({"tags", v}) when is_list(v),
    do: length(v) <= 100 and Enum.all?(v, &(is_binary(&1) and byte_size(&1) <= 255))

  defp type_ok?({key, v}) when is_integer(v),
    do: key in @int_keys or not is_map_key(@max_bytes, key)

  defp type_ok?({_key, v}) when is_nil(v) or is_boolean(v), do: true

  defp type_ok?({key, v}) when is_binary(v) do
    String.valid?(v) and byte_size(v) <= Map.get(@max_bytes, key, 4096)
  end

  defp type_ok?(_), do: false
end
