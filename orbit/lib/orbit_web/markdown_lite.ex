defmodule OrbitWeb.MarkdownLite do
  @moduledoc """
  A tiny, dependency-free Markdown renderer for one job: the "Analyse with AI"
  output on the IPsec-diagnosis and Log panels. The model emits a small,
  predictable GitHub-flavoured subset — `###` headings, `|` pipe tables,
  `**bold**`, `` `code` ``, bullet lists and paragraphs — which a `<pre>`
  showed as raw `| Title | Severity |` noise.

  Deliberately NOT a general Markdown library and deliberately NOT a
  dependency. The text is UNTRUSTED (it is model output, and the anonymised
  log content that seeds it is prompt-injectable). Everything here builds HEEx
  from parsed tokens, which Phoenix auto-escapes — `raw/1` is never called, so
  there is no HTML-injection surface to sanitise. Anything the parser does not
  recognise falls through as escaped plaintext: unknown input degrades, never
  breaks and never renders as markup.

  Invoke qualified so `parse/1` and friends stay out of every template's
  namespace: `<OrbitWeb.MarkdownLite.ai_markdown text={@result.findings} />`.
  """
  use Phoenix.Component

  @list_re ~r/^\s*(?:[-*+]|\d+\.)\s+(.*)$/
  @heading_re ~r/^\s{0,3}(\#{1,6})\s+(.*?)\s*\#*\s*$/

  # -- component -------------------------------------------------------------

  attr :text, :string, required: true

  @doc "Render Markdown `text` as safe, theme-aware HEEx."
  def ai_markdown(assigns) do
    assigns = assign(assigns, :blocks, parse(assigns.text))

    ~H"""
    <div class="space-y-2 text-xs leading-relaxed text-base-content/80">
      <OrbitWeb.MarkdownLite.md_block :for={b <- @blocks} block={b} />
    </div>
    """
  end

  attr :block, :map, required: true

  def md_block(%{block: %{type: :heading}} = assigns) do
    ~H"""
    <p class={heading_class(@block.level)}>
      <OrbitWeb.MarkdownLite.md_inlines tokens={@block.inline} />
    </p>
    """
  end

  def md_block(%{block: %{type: :table}} = assigns) do
    ~H"""
    <div class="overflow-x-auto">
      <table class="w-full border-collapse text-left">
        <thead>
          <tr>
            <th
              :for={cell <- @block.head}
              class="border border-base-300 bg-base-300/40 px-2 py-1 font-medium text-base-content"
            >
              <OrbitWeb.MarkdownLite.md_inlines tokens={cell} />
            </th>
          </tr>
        </thead>
        <tbody>
          <tr :for={row <- @block.rows}>
            <td
              :for={cell <- row}
              class="border border-base-300 px-2 py-1 align-top text-base-content/80"
            >
              <OrbitWeb.MarkdownLite.md_inlines tokens={cell} />
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  def md_block(%{block: %{type: :list}} = assigns) do
    ~H"""
    <ul class="list-disc space-y-0.5 pl-5">
      <li :for={item <- @block.items}><OrbitWeb.MarkdownLite.md_inlines tokens={item} /></li>
    </ul>
    """
  end

  def md_block(%{block: %{type: :code}} = assigns) do
    ~H"""
    <pre class="overflow-x-auto rounded bg-base-300/40 p-2 font-mono text-[11px] text-base-content/80"><code>{@block.text}</code></pre>
    """
  end

  def md_block(%{block: %{type: :paragraph}} = assigns) do
    ~H"""
    <p><OrbitWeb.MarkdownLite.md_inlines tokens={@block.inline} /></p>
    """
  end

  attr :tokens, :list, required: true

  def md_inlines(assigns) do
    ~H"""
    <OrbitWeb.MarkdownLite.md_inline :for={tok <- @tokens} tok={tok} />
    """
  end

  attr :tok, :any, required: true

  def md_inline(%{tok: {:strong, s}} = assigns) do
    assigns = assign(assigns, :s, s)

    ~H"""
    <strong class="font-semibold text-base-content">{@s}</strong>
    """
  end

  def md_inline(%{tok: {:code, s}} = assigns) do
    assigns = assign(assigns, :s, s)

    ~H"""
    <code class="rounded bg-base-300/40 px-1 font-mono text-[0.95em]">{@s}</code>
    """
  end

  def md_inline(%{tok: {:text, s}} = assigns) do
    assigns = assign(assigns, :s, s)

    ~H"""
    {@s}
    """
  end

  defp heading_class(level) when level <= 2, do: "text-sm font-semibold text-base-content"
  defp heading_class(3), do: "font-semibold text-base-content"
  defp heading_class(_), do: "font-medium text-base-content/90"

  # -- parser (pure, tested) -------------------------------------------------

  @doc "Parse a Markdown string into a flat list of block maps."
  def parse(text) do
    text
    |> to_string()
    |> String.replace("\r\n", "\n")
    |> String.split("\n")
    |> take_blocks([])
    |> Enum.reverse()
  end

  defp take_blocks([], acc), do: acc

  defp take_blocks([line | rest], acc) do
    cond do
      fence?(line) ->
        {code, rest2} = take_until_fence(rest, [])
        take_blocks(rest2, [%{type: :code, text: Enum.join(code, "\n")} | acc])

      String.trim(line) == "" ->
        take_blocks(rest, acc)

      hb = heading_block(line) ->
        take_blocks(rest, [hb | acc])

      table_start?(line, rest) ->
        {block, rest2} = take_table([line | rest])
        take_blocks(rest2, [block | acc])

      list_item?(line) ->
        {items, rest2} = take_list([line | rest], [])
        take_blocks(rest2, [%{type: :list, items: items} | acc])

      true ->
        {para, rest2} = take_paragraph([line | rest], [])
        block = %{type: :paragraph, inline: inline(Enum.join(para, " "))}
        take_blocks(rest2, [block | acc])
    end
  end

  # -- fenced code -----------------------------------------------------------

  defp fence?(line), do: line |> String.trim() |> String.starts_with?("```")

  defp take_until_fence([], acc), do: {Enum.reverse(acc), []}

  defp take_until_fence([line | rest], acc) do
    if fence?(line),
      do: {Enum.reverse(acc), rest},
      else: take_until_fence(rest, [line | acc])
  end

  # -- headings --------------------------------------------------------------

  defp heading_block(line) do
    case Regex.run(@heading_re, line) do
      [_, hashes, text] ->
        %{type: :heading, level: String.length(hashes), inline: inline(text)}

      _ ->
        nil
    end
  end

  # -- lists -----------------------------------------------------------------

  defp list_item?(line), do: Regex.match?(@list_re, line)

  defp take_list([], acc), do: {Enum.reverse(acc), []}

  defp take_list([line | rest] = lines, acc) do
    case (String.trim(line) != "" && Regex.run(@list_re, line)) || nil do
      [_, item] -> take_list(rest, [inline(item) | acc])
      _ -> {Enum.reverse(acc), lines}
    end
  end

  # -- tables ----------------------------------------------------------------

  defp pipe_line?(line), do: String.contains?(line, "|")

  # A `|---|:--:|` rule row: only pipes, dashes, colons and spaces, at least
  # one dash. This is what tells a pipe paragraph apart from a real table.
  defp separator?(line) do
    t = String.trim(line)
    t != "" and String.contains?(t, "-") and String.replace(t, ~r/[\s|:\-]/, "") == ""
  end

  defp table_start?(line, [next | _]), do: pipe_line?(line) and separator?(next)
  defp table_start?(_line, []), do: false

  defp take_table([header, _sep | rest]) do
    {rows, rest2} = take_rows(rest, [])
    {%{type: :table, head: cells(header), rows: rows}, rest2}
  end

  defp take_rows([], acc), do: {Enum.reverse(acc), []}

  defp take_rows([line | rest] = lines, acc) do
    if String.trim(line) != "" and pipe_line?(line) and not separator?(line) do
      take_rows(rest, [cells(line) | acc])
    else
      {Enum.reverse(acc), lines}
    end
  end

  defp cells(line) do
    line
    |> String.trim()
    |> String.trim("|")
    |> String.split("|")
    |> Enum.map(&(&1 |> String.trim() |> inline()))
  end

  # -- paragraphs ------------------------------------------------------------

  defp take_paragraph([], acc), do: {Enum.reverse(acc), []}

  defp take_paragraph([line | rest] = lines, acc) do
    stop? =
      String.trim(line) == "" or fence?(line) or not is_nil(heading_block(line)) or
        list_item?(line) or table_start?(line, rest)

    # The first line always joins (it is a plain line by construction); only a
    # later block-starter ends the paragraph. Without the `acc != []` guard a
    # lone pipe line that is not a table would loop forever.
    if stop? and acc != [] do
      {Enum.reverse(acc), lines}
    else
      take_paragraph(rest, [line | acc])
    end
  end

  # -- inline ----------------------------------------------------------------

  @doc """
  Split one line of text into inline tokens: `{:text, s}`, `{:strong, s}`,
  `{:code, s}`. Code spans are lifted first so `**` inside a backtick span is
  not mistaken for bold. Unbalanced markers stay literal text.
  """
  def inline(text) do
    text
    |> to_string()
    |> split_code()
    |> Enum.flat_map(fn
      {:code, _} = tok -> [tok]
      {:text, s} -> split_bold(s)
    end)
    |> Enum.reject(fn {_, s} -> s == "" end)
  end

  defp split_code(text) do
    ~r/`[^`]+`/
    |> Regex.split(text, include_captures: true)
    |> Enum.map(fn seg ->
      if wrapped?(seg, "`", 2),
        do: {:code, String.slice(seg, 1..-2//1)},
        else: {:text, seg}
    end)
  end

  defp split_bold(text) do
    ~r/\*\*[^*]+\*\*/
    |> Regex.split(text, include_captures: true)
    |> Enum.map(fn seg ->
      if wrapped?(seg, "**", 4),
        do: {:strong, String.slice(seg, 2..-3//1)},
        else: {:text, seg}
    end)
  end

  defp wrapped?(seg, marker, min_len) do
    String.length(seg) >= min_len and
      String.starts_with?(seg, marker) and String.ends_with?(seg, marker)
  end
end
