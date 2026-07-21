defmodule OrbitWeb.MarkdownLiteTest do
  @moduledoc """
  The dependency-free renderer for LLM analysis output. Two things matter:
  the small GFM subset the model emits parses into the right blocks, and —
  because the text is untrusted model output — nothing renders as live markup.
  """

  use ExUnit.Case, async: true
  import Phoenix.LiveViewTest

  alias OrbitWeb.MarkdownLite

  describe "parse/1" do
    test "an ATX heading keeps its level and inline text" do
      assert [%{type: :heading, level: 3, inline: [{:text, "Findings"}]}] =
               MarkdownLite.parse("### Findings")
    end

    test "a pipe table with a rule row becomes a table block" do
      md = """
      | Title | Severity | Evidence |
      |-------|:--------:|----------|
      | Tunnels flapping | **critical** | `DICVT-SB` deleted |
      | Zero traffic | warn | selectors idle |
      """

      assert [%{type: :table, head: head, rows: rows}] = MarkdownLite.parse(md)
      assert head == [[{:text, "Title"}], [{:text, "Severity"}], [{:text, "Evidence"}]]
      assert length(rows) == 2
      # Inline markup inside cells is tokenised, not left literal.
      assert [[{:text, "Tunnels flapping"}], [{:strong, "critical"}], _ev] = hd(rows)
    end

    test "bold and inline code inside a paragraph become tokens" do
      assert [%{type: :paragraph, inline: tokens}] =
               MarkdownLite.parse("The **critical** issue is `swanctl` config.")

      assert {:strong, "critical"} in tokens
      assert {:code, "swanctl"} in tokens
    end

    test "a bullet list collects its items" do
      md = "- first\n- second point\n"

      assert [%{type: :list, items: [[{:text, "first"}], [{:text, "second point"}]]}] =
               MarkdownLite.parse(md)
    end

    test "a fenced code block is kept verbatim, never parsed as markup" do
      md = "```\nlocal: 5.181.119.30\n**not bold**\n```"
      assert [%{type: :code, text: "local: 5.181.119.30\n**not bold**"}] = MarkdownLite.parse(md)
    end

    test "a lone pipe line that is not a table is a paragraph, not an infinite loop" do
      # Regression guard: the paragraph scanner must consume its first line
      # even when that line contains a pipe but no rule row follows.
      assert [%{type: :paragraph, inline: [{:text, "a | b but no table here"}]}] =
               MarkdownLite.parse("a | b but no table here")
    end

    test "unbalanced markers stay literal text" do
      assert [%{type: :paragraph, inline: [{:text, "two ** stars, one ` tick"}]}] =
               MarkdownLite.parse("two ** stars, one ` tick")
    end
  end

  describe "ai_markdown/1 (rendered)" do
    test "a table renders as an HTML table" do
      md = "| A | B |\n|---|---|\n| 1 | 2 |"
      html = render_component(&MarkdownLite.ai_markdown/1, text: md)
      assert html =~ "<table"
      assert html =~ "1"
      assert html =~ "2"
    end

    test "untrusted HTML in the text is escaped, never emitted as markup" do
      # The text is model output seeded by anonymised (prompt-injectable) logs.
      html =
        render_component(&MarkdownLite.ai_markdown/1, text: "<script>alert(1)</script> **x**")

      refute html =~ "<script>"
      assert html =~ "&lt;script&gt;"
      assert html =~ "<strong"
    end
  end
end
