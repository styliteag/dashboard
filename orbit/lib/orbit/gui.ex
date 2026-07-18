defmodule Orbit.GUI do
  @moduledoc """
  GUI-proxy facade (§18) — the open-flow logic behind the controller, kept
  here so it is unit-testable without HTTP. Ports the pure parts of
  routes/gui.py: the open-redirect-safe next clamp and the per-instance
  origin URL.
  """

  alias Orbit.Instances.Instance

  @doc """
  Clamp a handoff deep-link to a same-origin absolute path (open-redirect
  defense): only "/..." passes; absolute URLs, protocol-relative "//host"
  and backslash variants (browsers normalize to "//") all collapse to "/".
  """
  def safe_next(path)
      when is_binary(path) do
    if String.starts_with?(path, "/") and not String.starts_with?(path, "//") and
         not String.contains?(path, "\\") do
      path
    else
      "/"
    end
  end

  def safe_next(_), do: "/"

  @doc "Per-instance GUI origin: {slug}/{id} template, else the dev port."
  def base_url(%Instance{} = inst) do
    case Application.get_env(:orbit, :gui_base_template, "") do
      "" ->
        "https://localhost:#{9000 + inst.id}"

      template ->
        template
        |> String.replace("{slug}", to_string(inst.slug))
        |> String.replace("{id}", to_string(inst.id))
    end
  end

  @doc "Build the handoff URL for a minted token + optional deep-link path."
  def handoff_url(inst, token, path) do
    url = "#{base_url(inst)}/__orbit/auth?t=#{token}"
    nxt = safe_next(path)
    if nxt == "/", do: url, else: url <> "&next=" <> URI.encode(nxt, &URI.char_unreserved?/1)
  end
end
