defmodule OrbitWeb.DesignController do
  @moduledoc """
  Persists the user's design/mode choice (see `OrbitWeb.Design`) in
  year-long cookies and bounces back to where they came from
  (link-shortener design_controller port).
  """

  use OrbitWeb, :controller

  alias OrbitWeb.Design

  @max_age 60 * 60 * 24 * 365
  @design_cookie "orbit_design"
  @mode_cookie "orbit_mode"

  def update(conn, %{"design" => design}) do
    design = Design.validate(design)

    conn
    |> put_resp_cookie(@design_cookie, design, max_age: @max_age, same_site: "Lax")
    |> bounce_back()
  end

  def update_mode(conn, %{"mode" => mode}) do
    case Design.validate_mode(mode) do
      nil ->
        conn |> delete_resp_cookie(@mode_cookie) |> bounce_back()

      mode ->
        conn
        |> put_resp_cookie(@mode_cookie, mode, max_age: @max_age, same_site: "Lax")
        |> bounce_back()
    end
  end

  defp bounce_back(conn) do
    to =
      case get_req_header(conn, "referer") do
        [ref | _] -> URI.parse(ref).path || "/"
        _ -> "/"
      end

    redirect(conn, to: to)
  end
end
