defmodule OrbitWeb.PageController do
  use OrbitWeb, :controller

  # The old M0 landing page is gone (user decision): the hub roster is the
  # default view after login.
  def home(conn, _params) do
    redirect(conn, to: ~p"/hub")
  end
end
