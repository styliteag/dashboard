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
  4404: "Agent is not connected — no box to attach to.",
  4008: "Too many terminal sessions — close one and retry.",
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

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: {...colocatedHooks, Terminal, Capture},
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

