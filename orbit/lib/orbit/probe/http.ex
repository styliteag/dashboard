defmodule Orbit.Probe.HTTP do
  @moduledoc """
  HTTP reachability axis — port of the deleted `probe/http.py`.

  ANY status the server produces counts as up: the question is "does the web
  service answer", not "is the answer a 200". A 401 or 403 from a firewall GUI
  is a perfectly alive box. Only a transport failure (refused, timeout, TLS
  handshake, DNS) is down.

  TLS verification is off by design — firewall GUIs serve self-signed
  certificates, and this probe reads no content and sends no credentials.
  """

  @doc "GET the URL; merges the http axis into a probe result map."
  def get(url, opts \\ []) do
    timeout = Keyword.get(opts, :http_timeout, 4_000)

    base = [
      url: url,
      method: :get,
      receive_timeout: timeout,
      connect_options: [timeout: timeout, transport_opts: [verify: :verify_none]],
      retry: false,
      redirect: false,
      decode_body: false,
      into: &discard_body/2
    ]

    # Test seam: a Req plug replaces the network.
    req = Req.new(if plug = opts[:req_plug], do: Keyword.put(base, :plug, plug), else: base)

    case Req.request(req) do
      {:ok, %Req.Response{status: status}} ->
        %{http_up: true, http_status: status}

      {:error, reason} ->
        %{http_up: false, http_status: nil, error: describe(reason)}
    end
  rescue
    e -> %{http_up: false, http_status: nil, error: Exception.message(e)}
  end

  @doc """
  Body sink: the status is all the probe needs, so the first body chunk
  ends the response — a box answering with a huge (or endless) body is never
  buffered.
  """
  def discard_body({:data, _data}, acc), do: {:halt, acc}

  defp describe(%{reason: reason}), do: to_string(inspect(reason))
  defp describe(reason) when is_atom(reason), do: to_string(reason)
  defp describe(reason), do: inspect(reason)
end
