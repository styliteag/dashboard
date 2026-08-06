defmodule OrbitWeb.DesignContrastTest do
  use ExUnit.Case, async: true

  # WCAG 2.2 AA contrast gate over the daisyUI theme tokens in
  # assets/css/app.css. Parses every `@plugin "daisyui-theme"` block found,
  # so downstream builds that append themes (config :orbit, :designs) run
  # under the same gate without editing this file.
  #
  # UI/UX review 2026-08-06: soft-light shipped --color-warning at 2.19:1 —
  # every WARN/EXPIRING/UPDATE badge was effectively invisible, and five of
  # the seven semantic tokens failed AA in at least one light theme. The
  # eight-theme matrix decays silently without a computed check, so this
  # test pins every semantic token to >= 4.5:1 in its three real usages:
  # bare text on base-100 (page), bare text on base-200 (cards), and text
  # inside a bg-<token>/15 badge composited over base-100. It also pins the
  # <token>-content pairing (solid buttons, filled badges).

  @css_path Path.expand("../../assets/css/app.css", __DIR__)
  @semantic ~w(primary secondary accent info success warning error)
  @aa 4.5

  test "semantic tokens reach AA on page, card and /15 badge surfaces" do
    failures =
      for {theme, tokens} <- themes(),
          sem <- @semantic,
          Map.has_key?(tokens, sem),
          {surface, r} <- surface_ratios(tokens, sem),
          r < @aa do
        "#{theme} --color-#{sem} on #{surface}: #{Float.round(r, 2)}:1"
      end

    assert failures == [],
           "tokens below #{@aa}:1 (WCAG 2.2 AA):\n" <> Enum.join(failures, "\n")
  end

  test "token-content pairs reach AA (solid buttons, filled badges)" do
    # neutral included: bg-neutral + text-base-content was dark-on-dark in
    # every light design (active view toggle, CA chip, audit type chip) —
    # the pair contract is the regression pin.
    failures =
      for {theme, tokens} <- themes(),
          sem <- @semantic ++ ["neutral"],
          Map.has_key?(tokens, sem) and Map.has_key?(tokens, sem <> "-content"),
          r = ratio(srgb(tokens[sem <> "-content"]), srgb(tokens[sem])),
          r < @aa do
        "#{theme} --color-#{sem}-content on --color-#{sem}: #{Float.round(r, 2)}:1"
      end

    assert failures == [],
           "content pairs below #{@aa}:1 (WCAG 2.2 AA):\n" <> Enum.join(failures, "\n")
  end

  test "app.css parses into at least the six built-in themes" do
    # Guards the regex against CSS refactors silently emptying this gate.
    names = themes() |> Map.keys() |> MapSet.new()

    for built_in <- ~w(orbit-dark orbit-light bench-light bench-dark soft-light soft-dark) do
      assert built_in in names, "theme block #{built_in} not found in app.css"
    end
  end

  # -- token usage surfaces ---------------------------------------------------

  defp surface_ratios(tokens, sem) do
    fg = srgb(tokens[sem])
    base100 = srgb(tokens["base-100"])
    base200 = srgb(tokens["base-200"])

    [
      {"base-100", ratio(fg, base100)},
      {"base-200", ratio(fg, base200)},
      {"bg-#{sem}/15 badge", ratio(fg, composite(fg, base100, 0.15))}
    ]
  end

  # -- app.css parsing ---------------------------------------------------------

  defp themes do
    css = File.read!(@css_path)

    ~r/name:\s*"([\w-]+)";(.*?)--radius/s
    |> Regex.scan(css)
    |> Map.new(fn [_, name, body] ->
      tokens =
        ~r/--color-([\w-]+):\s*oklch\(([\d.]+)%\s+([\d.]+)\s+([\d.]+)\)/
        |> Regex.scan(body)
        |> Map.new(fn [_, token, l, c, h] ->
          {token, {to_f(l) / 100, to_f(c), to_f(h)}}
        end)

      {name, tokens}
    end)
  end

  defp to_f(s), do: s |> Float.parse() |> elem(0)

  # -- OKLCH -> sRGB -> WCAG relative luminance -------------------------------

  defp srgb({l, c, h}) do
    hr = h * :math.pi() / 180
    a = c * :math.cos(hr)
    b = c * :math.sin(hr)

    l_ = l + 0.3963377774 * a + 0.2158037573 * b
    m_ = l - 0.1055613458 * a - 0.0638541728 * b
    s_ = l - 0.0894841775 * a - 1.2914855480 * b

    {l3, m3, s3} = {l_ * l_ * l_, m_ * m_ * m_, s_ * s_ * s_}

    r = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3
    g = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3
    bl = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3

    {gamma(r), gamma(g), gamma(bl)}
  end

  defp gamma(x) do
    x = x |> max(0.0) |> min(1.0)
    if x <= 0.0031308, do: 12.92 * x, else: 1.055 * :math.pow(x, 1 / 2.4) - 0.055
  end

  defp luminance({r, g, b}) do
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
  end

  defp linear(c), do: if(c <= 0.04045, do: c / 12.92, else: :math.pow((c + 0.055) / 1.055, 2.4))

  defp ratio(fg, bg) do
    {hi, lo} = {max(luminance(fg), luminance(bg)), min(luminance(fg), luminance(bg))}
    (hi + 0.05) / (lo + 0.05)
  end

  # fg at `alpha` composited over an opaque bg (bg-<token>/15 utilities).
  defp composite(fg, bg, alpha) do
    {ff, fb} = {Tuple.to_list(fg), Tuple.to_list(bg)}
    Enum.zip_with(ff, fb, fn f, b -> f * alpha + b * (1 - alpha) end) |> List.to_tuple()
  end
end
