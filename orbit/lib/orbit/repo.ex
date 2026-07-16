defmodule Orbit.Repo do
  use Ecto.Repo,
    otp_app: :orbit,
    adapter: Ecto.Adapters.MyXQL

  @impl true
  def init(_type, config) do
    # Pin every connection to UTC so NOW()/CURRENT_TIMESTAMP and DATETIME
    # round-trips are timezone-stable regardless of the server's TZ setting.
    # Mirror of the backend's _pin_session_utc listener (db/base.py) — removing
    # it produced incident 195e9da ("last seen: in 1h"). Do not remove.
    {:ok, Keyword.put(config, :after_connect, {MyXQL, :query!, ["SET time_zone = '+00:00'", []]})}
  end
end
