defmodule Orbit.Gzip do
  @moduledoc """
  Bounded gunzip. `:zlib.gunzip/1` inflates the whole stream before anyone
  can look at its size, so a gzip bomb (kilobytes in, gigabytes out) is fully
  materialised first. This inflates chunk by chunk and stops as soon as the
  output passes `max_bytes`.
  """

  @doc "`{:ok, binary}`, `{:error, :too_large}` or `{:error, :bad_gzip}`."
  @spec gunzip_bounded(binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :too_large | :bad_gzip}
  def gunzip_bounded(gz, max_bytes) when is_binary(gz) do
    z = :zlib.open()

    try do
      # windowBits 31 = gzip wrapper.
      :ok = :zlib.inflateInit(z, 31)
      result = inflate_loop(z, :zlib.safeInflate(z, gz), [], 0, max_bytes)
      if result != {:error, :too_large}, do: :zlib.inflateEnd(z)
      result
    rescue
      _ -> {:error, :bad_gzip}
    catch
      _, _ -> {:error, :bad_gzip}
    after
      :zlib.close(z)
    end
  end

  def gunzip_bounded(_gz, _max_bytes), do: {:error, :bad_gzip}

  defp inflate_loop(z, {status, out}, acc, size, max) do
    size = size + IO.iodata_length(out)

    cond do
      size > max -> {:error, :too_large}
      status == :continue -> inflate_loop(z, :zlib.safeInflate(z, []), [acc, out], size, max)
      status == :finished -> {:ok, IO.iodata_to_binary([acc, out])}
    end
  end
end
