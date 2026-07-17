defmodule OrbitWeb.ExportController do
  @moduledoc """
  Machine-export surfaces (checks/routes.py): Checkmk JSON + Prometheus text.
  Same auth + scoping as the python exports — a session user gets their
  groups' instances; api-key callers honor their binding (unbound = global).
  Hub state is unscoped in-memory data, so both filter through the principal's
  instance list (invariant 5).

  Fleet-wide evaluate + render is CPU; the python side runs it off the event
  loop, but on the BEAM each request is its own process, so no extra offloading
  is needed here.
  """

  use OrbitWeb, :controller

  alias Orbit.Checks.{Export, Prometheus}

  def checkmk(conn, _params) do
    principal = conn.assigns.principal
    json(conn, Export.checkmk(principal, DateTime.utc_now()))
  end

  def prometheus(conn, _params) do
    principal = conn.assigns.principal
    text = Export.prometheus(principal, DateTime.utc_now())

    conn
    |> put_resp_content_type(Prometheus.content_type())
    |> send_resp(200, text)
  end

  @doc """
  CSV export of the caller's visible instances (bulk/routes.py parity) —
  session-authed browser download, scoped through list_visible.
  """
  def instances_csv(conn, _params) do
    rows =
      conn.assigns.current_user
      |> Orbit.Instances.list_visible()
      |> Enum.map(&csv_row/1)

    header = ~w(Name URL Location Tags Status) ++ ["Last Success", "Last Error", "Error Message"]
    body = Enum.map_join([header | rows], "\r\n", &csv_line/1)
    ts = Calendar.strftime(DateTime.utc_now(), "%Y%m%d_%H%M")

    conn
    |> put_resp_content_type("text/csv")
    |> put_resp_header("content-disposition", ~s(attachment; filename="instances_#{ts}.csv"))
    |> send_resp(200, body <> "\r\n")
  end

  defp csv_row(inst) do
    status =
      cond do
        inst.last_success_at != nil and
            (inst.last_error_at == nil or
               DateTime.compare(inst.last_success_at, inst.last_error_at) == :gt) ->
          "online"

        inst.last_error_at != nil ->
          "offline"

        true ->
          "unknown"
      end

    [
      inst.name,
      inst.base_url || "",
      inst.location || "",
      Enum.join(inst.tags || [], ", "),
      status,
      (inst.last_success_at && DateTime.to_iso8601(inst.last_success_at)) || "",
      (inst.last_error_at && DateTime.to_iso8601(inst.last_error_at)) || "",
      inst.last_error_message || ""
    ]
  end

  defp csv_line(fields), do: Enum.map_join(fields, ",", &csv_escape/1)

  # RFC-4180 escaping: quote when the field carries a comma/quote/newline.
  defp csv_escape(field) do
    text = to_string(field)

    if String.contains?(text, [",", "\"", "\n", "\r"]) do
      "\"" <> String.replace(text, "\"", "\"\"") <> "\""
    else
      text
    end
  end
end
