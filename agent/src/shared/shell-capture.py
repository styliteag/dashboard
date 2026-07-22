# to orbit_agent.py AND orbit_agent_linux.py — test_agent_split enforces
# byte equality of this block.
    async def _open_shell(self, stream: str, rows: int, cols: int) -> None:
        """Fork root's login shell on a fresh PTY and pump its output to the dashboard.

        We exec exactly what sshd would: root's own login shell (from the passwd
        db) as a *login* shell, chdir'd to its home. On pfSense that is /bin/sh,
        whose /root/.profile launches the console menu (/etc/rc.initial); on
        OPNsense the shell IS the menu (/usr/local/sbin/opnsense-shell). So the box
        presents its familiar console screen instead of a bare prompt.

        pty.fork() gives the child a controlling terminal (login_tty), so the menu,
        job control and password prompts behave like a real ssh session. The parent
        keeps the master fd non-blocking and feeds it to the event loop.
        """
        if not _shell_allowed():
            log.warning("shell %s: refused (not enabled on this box)", stream)
            await self._send(stream, "close")
            return
        try:
            pid, master_fd = pty.fork()
        except OSError as exc:
            log.warning("shell %s: fork failed: %s", stream, exc)
            await self._send(stream, "close")
            return
        if pid == 0:
            # Child: become root's login shell. Never returns; _exit on any failure
            # so a broken exec can't fall back into agent code inside the fork.
            try:
                pw = pwd.getpwuid(0)
                shell = pw.pw_shell or "/bin/sh"
                home = pw.pw_dir or "/root"
                env = os.environ.copy()
                env["TERM"] = "xterm-256color"
                env["HOME"] = home
                env["USER"] = pw.pw_name or "root"
                env["LOGNAME"] = pw.pw_name or "root"
                env["SHELL"] = shell
                env.setdefault("PATH", _SHELL_PATH)
                # Mark this as an interactive remote-tty login (which it is): the
                # pfSense /root/.profile only launches the console menu when SSH_TTY
                # is set OR TERM is in a short whitelist that excludes
                # xterm-256color. sshd sets SSH_TTY to the slave tty — do the same.
                with contextlib.suppress(OSError):
                    env["SSH_TTY"] = os.ttyname(0)
                with contextlib.suppress(OSError):
                    os.chdir(home)
                # argv0 with a leading "-" marks a LOGIN shell, so it sources the
                # box profile — that is what raises the native console menu, exactly
                # as sshd does. Fall back to /bin/sh if the passwd shell is broken.
                argv0 = "-" + os.path.basename(shell)
                try:
                    os.execve(shell, [argv0], env)
                except OSError:
                    os.execve("/bin/sh", ["-sh"], env)
            except Exception:  # noqa: BLE001 — child must die, not raise
                os._exit(127)
        # Parent.
        os.set_blocking(master_fd, False)
        self._shells[stream] = {"pid": pid, "fd": master_fd, "task": None}
        if rows and cols:
            self._set_winsize(master_fd, rows, cols)
        log.info("shell %s: pty opened (pid %d)", stream, pid)
        self._shells[stream]["task"] = asyncio.create_task(self._pty_pump(stream, master_fd))

    async def _pty_pump(self, stream: str, fd: int) -> None:
        """Drain the PTY master and forward output, awaiting each send so a flood of
        box output (e.g. a root `yes`) applies backpressure instead of piling up
        unbounded in-flight send tasks. Waits for readability between reads."""
        loop = asyncio.get_event_loop()
        try:
            while True:
                try:
                    data = os.read(fd, 65536)
                except (BlockingIOError, InterruptedError):
                    fut = loop.create_future()
                    loop.add_reader(fd, lambda f=fut: f.done() or f.set_result(None))
                    try:
                        await fut
                    finally:
                        with contextlib.suppress(Exception):
                            loop.remove_reader(fd)
                    continue
                except OSError:
                    break
                if not data:  # EOF — the shell exited
                    break
                await self._send(stream, "data", base64.b64encode(data).decode())
        finally:
            self._reap_shell(stream)

    def _shell_write(self, stream: str, data_b64: str) -> None:
        sh = self._shells.get(stream)
        if sh is None:
            return
        try:
            os.write(sh["fd"], base64.b64decode(data_b64))
        except (OSError, ValueError):
            self._reap_shell(stream)

    def _shell_resize(self, stream: str, rows: int, cols: int) -> None:
        sh = self._shells.get(stream)
        if sh is None or not rows or not cols:
            return
        self._set_winsize(sh["fd"], rows, cols)

    @staticmethod
    def _set_winsize(fd: int, rows: int, cols: int) -> None:
        with contextlib.suppress(OSError):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def _reap_shell(self, stream: str, notify: bool = True) -> None:
        sh = self._shells.pop(stream, None)
        if sh is None:
            return
        task = sh.get("task")
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        with contextlib.suppress(Exception):
            asyncio.get_event_loop().remove_reader(sh["fd"])
        with contextlib.suppress(OSError):
            os.close(sh["fd"])
        with contextlib.suppress(OSError):
            os.kill(sh["pid"], signal.SIGKILL)
        with contextlib.suppress(OSError):
            os.waitpid(sh["pid"], 0)
        log.info("shell %s: closed (pid %d)", stream, sh["pid"])
        if notify:
            asyncio.create_task(self._send(stream, "close"))

    def shutdown(self) -> None:
        for task in list(self._tasks.values()):
            task.cancel()
        for writer in list(self._writers.values()):
            with contextlib.suppress(OSError):
                writer.close()
        for stream in list(self._shells):
            self._reap_shell(stream, notify=False)
        for stream in list(self._captures):
            self._close_capture(stream, notify=False)
        self._tasks.clear()
        self._writers.clear()
        self._captures.clear()

    # --- live packet capture stream (pcap over tunnel) -----------------------

    async def _open_capture(self, stream: str, interface: str, filt: str) -> None:
        """Start tcpdump and stream raw pcap bytes back as tunnel data frames.

        This enables live capture/view in the browser tab.
        """
        if stream in self._captures:
            await self._send(stream, "close")
            return
        iface = interface.strip() or "em0"
        # Robust lookup: agent's daemon env may have minimal PATH (no /usr/sbin)
        # while interactive root shell does. Common locations on OPNsense/pfSense.
        search_path = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/local/sbin"
        tcpdump_bin = shutil.which("tcpdump", path=search_path) or "/usr/sbin/tcpdump"
        cmd: list[str] = [tcpdump_bin, "-i", iface, "-U", "-w", "-"]
        user_filt = (filt or "").strip()
        agent_excl = _agent_ws_exclude_bpf()
        if user_filt and agent_excl:
            final_filt = f"({user_filt}) and {agent_excl}"
        elif user_filt:
            final_filt = user_filt
        elif agent_excl:
            final_filt = agent_excl
        else:
            final_filt = ""
        if final_filt:
            cmd += final_filt.split()
        log.info("capture %s: exec %s", stream, " ".join(cmd))
        try:
            env = os.environ.copy()
            env["PATH"] = search_path  # ensure child sees tcpdump etc.
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            self._captures[stream] = proc
            self._tasks[stream] = asyncio.create_task(self._pump_capture(stream, proc))
            log.info("capture %s: started tcpdump on %s filter=%r", stream, iface, filt)
            await self._send(stream, "started")  # confirm to dashboard that pump is running
            # drain stderr for diagnostics (e.g. "no such interface", permission)
            asyncio.create_task(self._drain_stderr(stream, proc))
        except Exception as exc:  # noqa: BLE001
            log.warning("capture %s: failed to start: %s", stream, exc)
            await self._send(stream, "error", str(exc)[:200])
            await self._send(stream, "close")
            self._captures.pop(stream, None)

    async def _drain_stderr(self, stream: str, proc: "asyncio.subprocess.Process") -> None:
        """Log any stderr from tcpdump (errors like bad interface appear here)."""
        try:
            assert proc.stderr is not None
            while True:
                line = await proc.stderr.readline()
                if not line:
                    break
                msg = line.decode(errors="replace").strip()
                if msg:
                    if "listening on" in msg.lower():
                        # Normal startup banner from tcpdump (goes to stderr), not an error.
                        log.info("capture %s: tcpdump: %s", stream, msg)
                    else:
                        log.warning("capture %s: tcpdump stderr: %s", stream, msg)
                        # surface real errors (e.g. "no such interface", permission) to UI
                        await self._send(stream, "error", msg[:200])
        except Exception:
            pass

    async def _pump_capture(self, stream: str, proc: "asyncio.subprocess.Process") -> None:
        """Read tcpdump stdout (pcap stream) and forward as base64 data frames."""
        try:
            assert proc.stdout is not None
            while True:
                chunk = await proc.stdout.read(8192)
                if not chunk:
                    break
                await self._send(stream, "data", base64.b64encode(chunk).decode())
        except Exception:  # noqa: BLE001
            pass
        finally:
            await self._send(stream, "close")
            self._close_capture(stream, cancel_task=False)

    def _close_capture(self, stream: str, notify: bool = True, cancel_task: bool = True) -> None:
        proc = self._captures.pop(stream, None)
        if proc is not None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            # ensure it dies even if tcpdump ignores SIGTERM
            asyncio.create_task(self._force_kill(proc, delay=2))
        task = self._tasks.pop(stream, None)
        if cancel_task and task is not None and task is not asyncio.current_task():
            task.cancel()
        if notify:
            asyncio.create_task(self._send(stream, "close"))

    @staticmethod
    async def _force_kill(proc: "asyncio.subprocess.Process", delay: float = 2) -> None:
        await asyncio.sleep(delay)
        if proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await _TunnelManager._wait_proc(proc)  # wait after kill too

    @staticmethod
    async def _wait_proc(proc: "asyncio.subprocess.Process") -> None:
        with contextlib.suppress(Exception):
            await proc.wait()
