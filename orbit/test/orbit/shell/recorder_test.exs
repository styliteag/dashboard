defmodule Orbit.Shell.RecorderTest do
  @moduledoc "asciicast writing, the byte cap and the never-break-the-shell rules."

  use ExUnit.Case, async: false

  alias Orbit.Shell.Recorder

  setup do
    dir = Path.join(System.tmp_dir!(), "orbit-rec-test-#{System.unique_integer([:positive])}")
    Application.put_env(:orbit, :shell_record_dir, dir)

    on_exit(fn ->
      Application.put_env(:orbit, :shell_record_dir, "")
      File.rm_rf(dir)
    end)

    %{dir: dir}
  end

  defp lines(dir) do
    [path] = Path.wildcard(Path.join(dir, "*.cast"))
    path |> File.read!() |> String.split("\n", trim: true)
  end

  test "off by default: no directory, no recorder, no file" do
    Application.put_env(:orbit, :shell_record_dir, "")
    assert Recorder.dir() == nil
    assert Recorder.open(1, 2, "agent") == nil
    # Every call must tolerate the nil recorder, or the shell breaks when the
    # feature is off — which is the normal case.
    assert Recorder.write(nil, "x") == nil
    assert Recorder.close(nil) == :ok
  end

  test "a session writes a replayable asciicast v2 file", %{dir: dir} do
    rec = Recorder.open(7, 3, "agent")
    rec = Recorder.write(rec, "root@pf1:~ # uname\n")
    rec = Recorder.write(rec, "FreeBSD\n")
    :ok = Recorder.close(rec)

    [header | events] = lines(dir)

    assert %{"version" => 2, "width" => 80} = Jason.decode!(header)

    assert [[t1, "o", "root@pf1:~ # uname\n"], [_, "o", "FreeBSD\n"]] =
             Enum.map(events, &Jason.decode!/1)

    assert is_number(t1)
  end

  test "the byte cap closes the recording and leaves the session alone", %{dir: dir} do
    rec = Recorder.open(7, 3, "agent")
    # One write past the cap: the file gets a note, not 8 MB of garbage, and
    # write/2 keeps accepting bytes so the caller never has to care.
    rec = Recorder.write(rec, String.duplicate("x", 9 * 1024 * 1024))

    assert rec.capped
    assert Recorder.write(rec, "more") == rec
    assert :ok = Recorder.close(rec)
    assert Enum.any?(lines(dir), &(&1 =~ "cap reached"))
  end

  test "invalid utf-8 from the pty does not lose the recording", %{dir: dir} do
    # A multi-byte character split across two PTY frames arrives as invalid
    # UTF-8; encoding it raw would raise inside Jason and kill the event.
    rec = Recorder.open(7, 3, "ssh")
    rec = Recorder.write(rec, <<0xC3>>)
    :ok = Recorder.close(rec)

    assert [_header, event] = lines(dir)
    assert [_, "o", _] = Jason.decode!(event)
  end

  test "an unwritable directory disables recording instead of failing the shell" do
    Application.put_env(:orbit, :shell_record_dir, "/proc/orbit-cannot-write-here")
    assert Recorder.open(7, 3, "agent") == nil
  end

  describe "prune/0" do
    defp aged(dir, name, days_old) do
      path = Path.join(dir, name)
      File.write!(path, "x")
      old = System.os_time(:second) - days_old * 86_400
      File.touch!(path, old)
      path
    end

    test "deletes recordings past the retention and keeps the rest", %{dir: dir} do
      File.mkdir_p!(dir)
      stale = aged(dir, "orbit-agent-i1-u1-20260101T000000Z.cast", 90)
      fresh = aged(dir, "orbit-agent-i1-u1-20260720T000000Z.cast", 1)

      assert {1, 0} = Recorder.prune()
      refute File.exists?(stale)
      assert File.exists?(fresh)
    end

    test "never touches files it did not write", %{dir: dir} do
      File.mkdir_p!(dir)
      # A directory pointed somewhere shared must not turn a retention job
      # into a delete-everything job.
      foreign = aged(dir, "important.tar.gz", 400)
      also = aged(dir, "orbit-notes.txt", 400)

      assert {0, 0} = Recorder.prune()
      assert File.exists?(foreign)
      assert File.exists?(also)
    end

    test "off, missing directory and unreadable directory are all no-ops" do
      Application.put_env(:orbit, :shell_record_dir, "")
      assert Recorder.prune() == {0, 0}

      Application.put_env(:orbit, :shell_record_dir, "/nonexistent/orbit-rec")
      assert Recorder.prune() == {0, 0}
    end
  end
end
