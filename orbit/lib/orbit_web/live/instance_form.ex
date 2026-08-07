defmodule OrbitWeb.InstanceForm do
  @moduledoc """
  Inline validation shared by the instance create and edit forms (UI/UX
  review U-M4): the rules the context enforces on submit, evaluated per
  keystroke for the fields the operator has TOUCHED, so mistakes surface
  next to the field while typing instead of only in the post-submit
  banner. Mirrors — never replaces — the checks in `Orbit.Instances`;
  the context stays the enforcement point.

  Touch tracking uses the `_target` field LiveView adds to every
  phx-change payload; validating untouched fields would light the whole
  form red on the first keystroke.
  """

  alias Orbit.Instances.Slug

  @doc "Record the changed field from a phx-change payload's `_target`."
  def touch(touched, %{"_target" => ["instance", field]}), do: MapSet.put(touched, field)
  def touch(touched, _payload), do: touched

  @doc "field => message for every touched field that would fail on submit."
  def errors(form, touched) do
    for {field, msg} <- failing(form),
        MapSet.member?(touched, field),
        into: %{},
        do: {field, msg}
  end

  defp failing(form) do
    [
      {"name", name_error(form["name"])},
      {"slug", slug_error(form["slug"])},
      {"base_url", url_error(form["base_url"])},
      {"ping_url", url_error(form["ping_url"])},
      {"push_interval_seconds", interval_error(form["push_interval_seconds"])},
      {"poll_interval_seconds", interval_error(form["poll_interval_seconds"])}
    ]
    |> Enum.filter(fn {_field, msg} -> msg end)
  end

  defp name_error(name), do: if(String.trim(name || "") == "", do: "name is required")

  # Blank is fine (create derives one from the name; edit keeps the stored
  # slug) — only a non-empty invalid label is an error, same as the context.
  defp slug_error(slug) do
    if presence(slug) && not Slug.valid?(slug),
      do: "must be a valid dns label (a-z, 0-9, -)"
  end

  defp url_error(url) do
    if presence(url) && not String.starts_with?(String.trim(url), ["http://", "https://"]),
      do: "must start with http:// or https://"
  end

  defp interval_error(value) do
    with v when not is_nil(v) <- presence(value),
         {n, ""} when n > 0 <- Integer.parse(v) do
      nil
    else
      nil -> nil
      _ -> "must be a positive number of seconds"
    end
  end

  defp presence(nil), do: nil

  defp presence(value) when is_binary(value) do
    case String.trim(value) do
      "" -> nil
      trimmed -> trimmed
    end
  end
end
