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

// Terminal hook: bridges a root PTY on the box to the browser over the
// session-authed shell WS (/api/ws/shell/:id). Raw byte stream — no ANSI
// emulator (vendoring xterm is a later polish); output lands in a <pre>,
// keystrokes go back as bytes. The full auth order runs server-side in the
// WS route (write role, scope, shell_enabled, slot cap → close codes).
const Terminal = {
  mounted() {
    const id = this.el.dataset.instanceId
    const out = this.el.querySelector("[data-term-out]")
    const proto = location.protocol === "https:" ? "wss" : "ws"
    const ws = new WebSocket(`${proto}://${location.host}/api/ws/shell/${id}`)
    ws.binaryType = "arraybuffer"
    this.ws = ws
    ws.onmessage = e => {
      if (typeof e.data === "string") return // json control frames (ping)
      out.textContent += new TextDecoder().decode(e.data)
      out.scrollTop = out.scrollHeight
    }
    ws.onclose = e => { out.textContent += `\n[connection closed: ${e.code}]\n` }
    this.el.querySelector("[data-term-input]").addEventListener("keydown", e => {
      let data
      if (e.key === "Enter") data = "\r"
      else if (e.key === "Backspace") data = "\x7f"
      else if (e.key === "Tab") data = "\t"
      else if (e.ctrlKey && e.key === "c") data = "\x03"
      else if (e.key.length === 1) data = e.key
      else return
      e.preventDefault()
      if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data))
    })
  },
  destroyed() { this.ws && this.ws.close() },
}

const csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
const liveSocket = new LiveSocket("/live", Socket, {
  longPollFallbackMs: 2500,
  params: {_csrf_token: csrfToken},
  hooks: {...colocatedHooks, Terminal},
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

