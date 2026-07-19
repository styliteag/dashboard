defmodule OrbitWeb.CaptureDownloadController do
  @moduledoc """
  Raw pcap download for a stored capture snapshot (capture/routes.py
  download_pcap parity). Session-authed <a href> download (sanctioned
  bypass); the capture id is opaque, and the snapshot's instance re-checks
  against the caller's scope — a guessed id across groups 404s, never 403
  (no existence oracle).
  """

  use OrbitWeb, :controller

  alias Orbit.Auth.Scope
  alias Orbit.Capture.Snapshots

  def pcap(conn, %{"cap_id" => cap_id}) do
    user = conn.assigns.current_user

    with {pcap, meta} <- Snapshots.get(cap_id),
         inst when not is_nil(inst) <- Scope.get_instance(meta["instance_id"], user) do
      Orbit.Audit.write(
        action: "packet_capture.download",
        result: "ok",
        user_id: user.id,
        target_type: "instance",
        target_id: inst.id,
        detail: %{"capture_id" => cap_id}
      )

      conn
      |> put_resp_content_type("application/vnd.tcpdump.pcap")
      |> put_resp_header("content-disposition", ~s(attachment; filename="capture-#{cap_id}.pcap"))
      |> send_resp(200, pcap)
    else
      _ -> conn |> put_status(404) |> json(%{detail: "capture not found or expired"})
    end
  end
end
