defmodule Orbit.Instances.Slug do
  @moduledoc """
  DNS-label slugs for instances — port of instances/slug.py. The slug is
  the GUI-proxy vhost label (gui-<slug>), so it must be a valid DNS label.
  German digraphs map explicitly BEFORE accent stripping (NFKD would split
  ü into u + combining mark and lose the e).
  """

  @max_len 63
  @fallback "fw"
  @digraphs [{"ä", "ae"}, {"ö", "oe"}, {"ü", "ue"}, {"ß", "ss"}]

  @slug_re ~r/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

  def max_len, do: @max_len

  @doc "True iff usable as the gui-<slug> DNS label."
  def valid?(value), do: is_binary(value) and Regex.match?(@slug_re, value)

  @doc "Free-form display name → valid DNS-label slug (never empty)."
  def slugify(name) do
    s = name |> String.trim() |> String.downcase()
    s = Enum.reduce(@digraphs, s, fn {from, to}, acc -> String.replace(acc, from, to) end)

    s =
      s
      |> String.normalize(:nfkd)
      |> String.replace(~r/\p{Mn}/u, "")
      |> String.replace(~r/[^a-z0-9]+/, "-")
      |> String.trim("-")

    # Re-trim: truncation may land on a hyphen.
    s = s |> String.slice(0, @max_len) |> String.trim("-")
    if s == "", do: @fallback, else: s
  end
end
