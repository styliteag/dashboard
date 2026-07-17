defmodule OrbitWeb.PageController do
  use OrbitWeb, :controller

  def home(conn, _params) do
    render(conn, :home, layout: false)
  end
end
