// If you want to use Phoenix channels, run `mix help phx.gen.channel`
// to get started and then uncomment the line below.
// import "./user_socket.js"

// You can include dependencies in two ways.
//
// The simplest option is to put them in assets/vendor and
// import them using relative paths:
//
//     import "../vendor/some-package.js"
//
// Alternatively, you can `npm install some-package --prefix assets` and import
// them using a path starting with the package name:
//
//     import "some-package"
//
// If you have dependencies that try to import CSS, esbuild will generate a separate `app.css` file.
// To load it, simply add a second `<link>` to your `root.html.heex` file.

// Include phoenix_html to handle method=PUT/DELETE in forms and buttons.
import "phoenix_html"
// Establish Phoenix Socket and LiveView configuration.
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import {hooks as colocatedHooks} from "phoenix-colocated/orbit"
import topbar from "../vendor/topbar"
import {Terminal as Xterm} from "../vendor/xterm.js"
import {FitAddon} from "../vendor/addon-fit.js"
// xterm.css is inlined into the app stylesheet via assets/css/app.css (@import).

// Close-code → readable note (parity with the old React ShellTerminal).
const SHELL_CLOSE = {
  4401: "Session expired — please log in again.",
  4403: "Shell is disabled on this server (DASH_SHELL_ENABLED is off).",
  // 4404 covers both transports: no connected agent, and no usable SSH shell
  // (a Securepoint needs SSH enabled with a key and a pinned host key).
  4404: "No shell available — the agent is not connected, or SSH is not configured for this box.",
  4008: "Too many terminal sessions — close one and retry.",
  // Idle timeout / max session lifetime — an abandoned root shell is closed
  // rather than left open on the box.
  4009: "Session closed — idle too long, or it hit the maximum session time.",
}

// Terminal hook: a real xterm.js terminal wired to a root PTY on the box over
// the session-authed shell WS (/api/ws/shell/:id). Keystrokes go out as binary,
// output comes back as binary, window-size changes as a JSON `resize` control
// frame; the server keepalive `ping` is answered with `pong`. The full auth
// order runs server-side in the WS route (write role, scope, shell_enabled,
// slot cap → close codes). Status is pushed to the LiveView via a hidden input.
const Terminal = {
  mounted() {
    const id = this.el.dataset.instanceId
    const mount = this.el.querySelector("[data-term-mount]")
    const status = this.el.querySelector("[data-term-status]")
    const setStatus = (text, cls) => {
      if (!status) return
      status.textContent = text
      status.className = cls
    }

    const term = new Xterm({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: {background: "#000000", foreground: "#e2e8f0", cursor: "#34d399"},
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(mount)
    fit.fit()
    this.term = term

    const proto = location.protocol === "https:" ? "wss" : "ws"
    const ws = new WebSocket(`${proto}://${location.host}/api/ws/shell/${id}`)
    ws.binaryType = "arraybuffer"
    this.ws = ws

    const sendResize = () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type: "resize", cols: term.cols, rows: term.rows}))
      }
    }

    ws.onopen = () => {
      setStatus("connected", "text-xs text-emerald-400")
      fit.fit()
      sendResize()
      term.focus()
    }
    ws.onmessage = e => {
      if (e.data instanceof ArrayBuffer) {
        term.write(new Uint8Array(e.data))
        return
      }
      // Text frame = control channel; answer the server keepalive ping so the
      // socket stays warm in both directions. Never fed to the terminal.
      if (typeof e.data === "string") {
        try {
          const m = JSON.parse(e.data)
          if (m.type === "ping" && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({type: "pong"}))
          }
        } catch (_) {}
      }
    }
    ws.onclose = e => {
      setStatus(SHELL_CLOSE[e.code] || "connection closed", "text-xs text-red-400")
      term.write("\r\n\x1b[90m[session closed]\x1b[0m\r\n")
    }

    const enc = new TextEncoder()
    this.onData = term.onData(d => {
      if (ws.readyState === WebSocket.OPEN) ws.send(enc.encode(d))
    })

    this.ro = new ResizeObserver(() => {
      fit.fit()
      sendResize()
    })
    this.ro.observe(mount)
  },
  destroyed() {
    this.ro && this.ro.disconnect()
    this.onData && this.onData.dispose()
    // Detach handlers before closing so a late onclose can't touch a torn-down
    // terminal (LiveView navigation reuses the DOM under a fresh hook).
    if (this.ws) {
      this.ws.onopen = this.ws.onmessage = this.ws.onclose = null
      this.ws.close()
    }
    this.term && this.term.dispose()
  },
}

// Capture hook: streams a live tcpdump on the box over the session-authed
// capture WS (/api/ws/capture/:id). The agent sends base64 pcap-ish text
// lines as binary frames; started/error arrive as JSON control frames.
// interface/filter come from the element's data attrs (set by the form).
const Capture = {
  mounted() {
    const el = this.el
    const out = el.querySelector("[data-cap-out]")
    const status = el.querySelector("[data-cap-status]")
    const id = el.dataset.instanceId
    const iface = encodeURIComponent(el.dataset.interface || "")
    const filter = encodeURIComponent(el.dataset.filter || "")
    const proto = location.protocol === "https:" ? "wss" : "ws"
    const ws = new WebSocket(
      `${proto}://${location.host}/api/ws/capture/${id}?interface=${iface}&filter=${filter}`,
    )
    ws.binaryType = "arraybuffer"
    this.ws = ws
    let lines = 0
    ws.onmessage = e => {
      if (typeof e.data === "string") {
        try {
          const msg = JSON.parse(e.data)
          if (msg.op === "started") status.textContent = "capturing…"
          else if (msg.op === "error") status.textContent = `error: ${msg.message || "capture failed"}`
        } catch (_) {}
        return
      }
      const text = new TextDecoder().decode(e.data)
      out.textContent += text
      lines += (text.match(/\n/g) || []).length
      // Bound the DOM: keep the last ~2000 lines.
      if (lines > 2000) {
        const kept = out.textContent.split("\n").slice(-2000)
        out.textContent = kept.join("\n")
        lines = kept.length
      }
      out.scrollTop = out.scrollHeight
    }
    ws.onclose = e => { status.textContent = `closed (${e.code})` }
    ws.onerror = () => { status.textContent = "connection error" }
  },
  destroyed() { this.ws && this.ws.close() },
}

// --- Passkeys (WebAuthn) --------------------------------------------------
// Minimal WebAuthn registration client (no @simplewebauthn dep): the WebAuthn
// JSON wire format is base64url without padding; navigator.credentials.create
// wants ArrayBuffers. Convert in, run the ceremony, convert the response out.
function b64urlToBuf(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4)
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"))
  const buf = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf.buffer
}
function bufToB64url(buf) {
  const bytes = new Uint8Array(buf)
  let bin = ""
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i])
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}
async function createCredential(options) {
  const publicKey = {
    ...options,
    challenge: b64urlToBuf(options.challenge),
    user: {...options.user, id: b64urlToBuf(options.user.id)},
    excludeCredentials: (options.excludeCredentials || []).map(c => ({...c, id: b64urlToBuf(c.id)})),
  }
  const cred = await navigator.credentials.create({publicKey})
  const resp = cred.response
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || null,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
    response: {
      clientDataJSON: bufToB64url(resp.clientDataJSON),
      attestationObject: bufToB64url(resp.attestationObject),
      transports: resp.getTransports ? resp.getTransports() : [],
    },
  }
}

// Passkey hook: the "Add passkey" button. Click → ask the LiveView for options
// (the challenge stays server-side), run the browser ceremony, hand the result
// back. Failures (dismissed prompt, no authenticator) report a readable note.
const Passkey = {
  mounted() {
    this.el.addEventListener("click", e => {
      e.preventDefault()
      this.register()
    })
  },
  register() {
    if (!window.PublicKeyCredential) {
      this.pushEvent("passkey_error", {message: "This browser has no passkey support."})
      return
    }
    const nameEl = document.getElementById("passkey-name")
    const name = nameEl ? nameEl.value.trim() : ""
    this.el.disabled = true
    this.pushEvent("passkey_register_begin", {}, reply => {
      createCredential(reply.options)
        .then(credential => {
          if (nameEl) nameEl.value = ""
          this.pushEvent("passkey_register_finish", {credential, name})
        })
        .catch(err => {
          const dismissed = err && (err.name === "NotAllowedError" || err.name === "AbortError")
          this.pushEvent("passkey_error", {
            message: dismissed ? "Passkey prompt was dismissed." : "Could not create passkey.",
          })
        })
        .finally(() => { this.el.disabled = false })
    })
  },
}


// Position a comment-editor <details> popover as a fixed panel so it escapes
// the list table's overflow-x-auto clip. Placed just below the pencil, clamped
// into the viewport; the server re-render (after save) resets it to closed.
const CommentPop = {
  mounted() {
    this._reposition = () => this.position()
    this.el.addEventListener("toggle", this._reposition)
    window.addEventListener("resize", this._reposition)
    window.addEventListener("scroll", this._reposition, true)
  },
  updated() { this.position() },
  destroyed() {
    window.removeEventListener("resize", this._reposition)
    window.removeEventListener("scroll", this._reposition, true)
  },
  position() {
    const panel = this.el.querySelector("[data-cmt-panel]")
    const summary = this.el.querySelector("summary")
    if (!panel || !summary) return
    if (!this.el.open) { panel.classList.add("hidden"); return }
    panel.classList.remove("hidden")
    const r = summary.getBoundingClientRect()
    const w = panel.offsetWidth || 256
    const left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8))
    panel.style.left = left + "px"
    panel.style.top = (r.bottom + 4) + "px"
    panel.querySelector("textarea")?.focus()
  },
}

// Copy a value to the clipboard with a brief confirmation on the button.
// navigator.clipboard needs a secure context; the textarea path keeps the
// button working on a plain-http dev host.
const CopyValue = {
  mounted() {
    this.el.addEventListener("click", async () => {
      const value = this.el.dataset.copy
      if (!value) return
      try {
        await navigator.clipboard.writeText(value)
      } catch {
        const ta = document.createElement("textarea")
        ta.value = value
        ta.style.cssText = "position:fixed;opacity:0"
        document.body.appendChild(ta)
        ta.select()
        try { document.execCommand("copy") } finally { ta.remove() }
      }
      this.el.classList.add("text-primary")
      clearTimeout(this._t)
      this._t = setTimeout(() => this.el.classList.remove("text-primary"), 1200)
    })
  },
  destroyed() { clearTimeout(this._t) },
}

// Metric charts: a crosshair plus a readout that follows the pointer. The
// SVG already carries one <title> per sample dot, but a native tooltip only
// appears after a hover delay and only exactly on the dot — on a 720-point
// series that is effectively undiscoverable. Values are read from the dots'
// own titles, so the server stays the single source of the numbers.
const ChartHover = {
  mounted() { this.wire() },
  updated() { this.wire() },
  wire() {
    const svg = this.el.querySelector("svg")
    const line = this.el.querySelector("[data-crosshair]")
    const out = this.el.querySelector("[data-readout]")
    if (!svg || !line || !out) return
    this._dots = [...svg.querySelectorAll("circle")].map(c => ({
      x: parseFloat(c.getAttribute("cx")),
      label: c.querySelector("title")?.textContent || "",
    }))
    if (this._bound) return
    this._bound = true
    const move = e => {
      if (!this._dots.length) return
      const r = svg.getBoundingClientRect()
      const pct = Math.max(0, Math.min(100, ((e.clientX - r.left) / r.width) * 100))
      let best = this._dots[0]
      for (const d of this._dots) {
        if (Math.abs(d.x - pct) < Math.abs(best.x - pct)) best = d
      }
      line.setAttribute("x1", best.x)
      line.setAttribute("x2", best.x)
      line.style.opacity = "0.5"
      out.textContent = best.label
    }
    const leave = () => { line.style.opacity = "0"; out.textContent = "" }
    svg.addEventListener("pointermove", move)
    svg.addEventListener("pointerleave", leave)
  },
}

// Settings rows: keep the Save button inert until the field actually
// differs from what the server rendered. Twenty always-green Save buttons
// read as twenty pending changes. Deliberately a JS hook and not
// phx-change: a keystroke-per-roundtrip on every settings row is real
// traffic for what is a purely local "has this input been touched" fact.
const DirtySave = {
  mounted() { this.wire() },
  updated() { this.wire() },
  wire() {
    const field = this.el.querySelector("input[name=value], select[name=value]")
    const save = this.el.querySelector("button[type=submit]")
    if (!field || !save) return
    // Secrets render blank with a placeholder — any typing is a real change.
    this._initial = field.value
    const sync = () => {
      const dirty = field.value !== this._initial
      save.disabled = !dirty
      save.classList.toggle("opacity-40", !dirty)
      save.classList.toggle("cursor-not-allowed", !dirty)
    }
    if (!this._bound) {
      field.addEventListener("input", sync)
      field.addEventListener("change", sync)
      this._bound = true
    }
    sync()
  },
}

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  // phoenix.js defaults to 30s, which is exactly the idle timeout a lot of
  // reverse proxies and load balancers ship with — so every heartbeat becomes
  // a race against the proxy's timer, and losing one drops the socket mid-form
  // (measured in a customer swarm: a 30s idle cut, heartbeats at 25s always
  // survived, at 30s died immediately). The agent picked 20s for the same
  // reason (_PING_INTERVAL in orbit_agent.py); the browser now matches it.
  // This is resilience, not a fix for a broken proxy — it just stops us from
  // sitting on the single worst possible interval.
  heartbeatIntervalMs: 20000,
  params: {_csrf_token: csrfToken},
  hooks: {...colocatedHooks, Terminal, Capture, Passkey, CommentPop, DirtySave, ChartHover, CopyValue, RuleReorder},
})

// GUI-proxy "Open GUI": the LiveView pushes the minted handoff URL; open it
// in a new tab (the handoff sets the origin cookie, then lands in the GUI).
window.addEventListener("phx:gui_open_url", e => {
  if (e.detail && e.detail.url) window.open(e.detail.url, "_blank", "noopener")
})

// Show progress bar on live navigation and form submits
topbar.config({barColors: {0: "#29d"}, shadowColor: "rgba(0, 0, 0, .3)"})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

// connect if there are any LiveViews on the page
liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
// >> liveSocket.enableLatencySim(1000)  // enabled for duration of browser session
// >> liveSocket.disableLatencySim()
window.liveSocket = liveSocket

// The lines below enable quality of life phoenix_live_reload
// development features:
//
//     1. stream server logs to the browser console
//     2. click on elements to jump to their definitions in your code editor
//
if (process.env.NODE_ENV === "development") {
  window.addEventListener("phx:live_reload:attached", ({detail: reloader}) => {
    // Enable server log streaming to client.
    // Disable with reloader.disableServerLogs()
    reloader.enableServerLogs()

    // Open configured PLUG_EDITOR at file:line of the clicked element's HEEx component
    //
    //   * click with "c" key pressed to open at caller location
    //   * click with "d" key pressed to open at function component definition location
    let keyDown
    window.addEventListener("keydown", e => keyDown = e.key)
    window.addEventListener("keyup", _e => keyDown = null)
    window.addEventListener("click", e => {
      if(keyDown === "c"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtCaller(e.target)
      } else if(keyDown === "d"){
        e.preventDefault()
        e.stopImmediatePropagation()
        reloader.openEditorAtDef(e.target)
      }
    }, true)

    window.liveReloader = reloader
  })
}


// Mark the active design/mode inside the theme switcher. The server renders
// the buttons without state (LiveViews don't carry the design assigns); the
// html element's data-theme ("orbit-dark", …) is the single source of truth.
const markThemeChoices = () => {
  const theme = document.documentElement.getAttribute("data-theme") || ""
  const [design, mode] = theme.split("-")
  const mark = (el, on) => {
    el.classList.toggle("text-primary", on)
    el.classList.toggle("border-primary", on)
    el.classList.toggle("bg-primary/10", on)
  }
  document.querySelectorAll("[data-theme-design]").forEach(b =>
    mark(b, b.dataset.themeDesign === design))
  document.querySelectorAll("[data-theme-mode]").forEach(b =>
    mark(b, b.dataset.themeMode === mode))
}
markThemeChoices()
window.addEventListener("phx:page-loading-stop", markThemeChoices)

// Close the <details> theme switcher on any click outside it — native
// details stays open until its own summary is clicked again, which reads
// as a stuck popover next to every other dismiss-on-blur menu.
document.addEventListener("click", e => {
  document.querySelectorAll("details[data-popover]").forEach(d => {
    if (d.open && !d.contains(e.target)) d.open = false
  })
})

// Firewall rules: drag a row onto another to move it before that rule. The
// server already has move_before (the ↑/↓ buttons use it) — this only adds
// the pointer path, so keyboard and touch users keep the buttons. Rows that
// are not editable (OPNsense's own internal rules) are inert.
const RuleReorder = {
  mounted() { this.wire() },
  updated() { this.wire() },
  wire() {
    if (this._bound) return
    this._bound = true
    let dragged = null

    this.el.addEventListener("dragstart", e => {
      const row = e.target.closest("tr[data-fw-uuid]")
      if (!row || row.dataset.fwEditable !== "true") return e.preventDefault()
      dragged = row
      row.classList.add("opacity-50")
      e.dataTransfer.effectAllowed = "move"
    })

    this.el.addEventListener("dragover", e => {
      const row = e.target.closest("tr[data-fw-uuid]")
      if (!dragged || !row || row === dragged) return
      e.preventDefault()
      row.classList.add("border-t-2", "border-t-primary")
    })

    this.el.addEventListener("dragleave", e => {
      e.target.closest("tr[data-fw-uuid]")?.classList.remove("border-t-2", "border-t-primary")
    })

    this.el.addEventListener("drop", e => {
      const row = e.target.closest("tr[data-fw-uuid]")
      if (!dragged || !row || row === dragged) return
      e.preventDefault()
      row.classList.remove("border-t-2", "border-t-primary")
      this.pushEvent("move_before", {uuid: dragged.dataset.fwUuid, target: row.dataset.fwUuid})
    })

    this.el.addEventListener("dragend", () => {
      dragged?.classList.remove("opacity-50")
      this.el.querySelectorAll("tr").forEach(r =>
        r.classList.remove("border-t-2", "border-t-primary"))
      dragged = null
    })
  },
}
