defmodule OrbitWeb.CsvFormulaTest do
  @moduledoc """
  CSV export: a cell an operator (or an agent-reported error message)
  starts with `=`, `+`, `-`, `@`, TAB or CR is prefixed with `'` so a
  spreadsheet shows it as text instead of evaluating a formula.
  """
  use ExUnit.Case, async: true

  alias OrbitWeb.ExportController, as: E

  test "formula-looking cells are neutralised" do
    assert E.csv_escape("=HYPERLINK(\"http://x\")") == "\"'=HYPERLINK(\"\"http://x\"\")\""
    assert E.csv_escape("+1") == "'+1"
    assert E.csv_escape("-2+3") == "'-2+3"
    assert E.csv_escape("@SUM(A1)") == "'@SUM(A1)"
    assert E.csv_escape("\tcmd") == "'\tcmd"
  end

  test "ordinary cells are unchanged" do
    assert E.csv_escape("fw-1") == "fw-1"
    assert E.csv_escape("a,b") == "\"a,b\""
    assert E.csv_escape("") == ""
  end
end
