import { createServer } from "node:http"
import { randomBytes } from "node:crypto"

const escape = (text) => String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c])

// A short-lived loopback guide supplies the choice missing from the host's
// one-shot OAuth callback. Tokens never enter this page or its responses.
export async function enterpriseLoginPage(loginUrl, timeout = 5 * 60 * 1000) {
  const path = "/" + randomBytes(24).toString("hex")
  const controller = new AbortController()
  let state = { stage: "waiting", message: "请先打开企业微信扫码页，完成扫码后回到此页。" }
  let members = [], choose, origin, closed = false, closeTimer
  const close = () => {
    if (closed) return
    closed = true
    clearTimeout(timer)
    clearTimeout(closeTimer)
    server.close()
    server.closeAllConnections?.()
  }
  const abort = (message) => {
    state = { stage: "failed", message }
    const error = new Error(message)
    controller.abort(error)
    choose?.reject(error)
    choose = undefined
  }
  const server = createServer(async (req, res) => {
    const send = (status, type, body) => {
      res.writeHead(status, { "Content-Type": type, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'" })
      res.end(body)
    }
    if (req.headers.host !== new URL(origin).host || (req.headers.origin && req.headers.origin !== origin))
      return send(403, "text/plain", "Forbidden")
    const url = new URL(req.url, origin)
    if (req.method === "GET" && url.pathname === path + "/")
      return send(200, "text/html; charset=utf-8", page(loginUrl))
    if (req.method === "GET" && url.pathname === path + "/status")
      return send(200, "application/json; charset=utf-8", JSON.stringify(state))
    if (req.method !== "POST" || ![path + "/select", path + "/cancel"].includes(url.pathname))
      return send(404, "text/plain", "Not found")
    if (req.headers.origin !== origin || !String(req.headers["content-type"]).startsWith("application/json"))
      return send(403, "text/plain", "Forbidden")
    if (url.pathname.endsWith("/cancel")) {
      abort("已取消企业登录，未保存账号")
      send(200, "application/json", '{"ok":true}')
      closeTimer = setTimeout(close, 1500)
      closeTimer.unref?.()
      return
    }
    try {
      let body = ""
      for await (const chunk of req) {
        body += chunk
        if (body.length > 1024) return send(413, "text/plain", "Too large")
      }
      const { choice } = JSON.parse(body)
      if (state.stage !== "choose" || !choose || !Number.isInteger(choice) || !members[choice])
        return send(409, "application/json", '{"error":"请从当前企业列表选择"}')
      const pending = choose
      choose = undefined
      state = { stage: "authorizing", message: "正在完成所选企业的授权…" }
      pending.resolve(members[choice])
      send(200, "application/json", '{"ok":true}')
    } catch {
      send(400, "application/json", '{"error":"无效的选择"}')
    }
  })
  await new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(0, "127.0.0.1", resolve)
  })
  origin = `http://127.0.0.1:${server.address().port}`
  server.unref()
  const timer = setTimeout(() => { abort("企业登录已超时，请重新添加账号"); close() }, timeout)
  timer.unref?.()
  return {
    url: origin + path + "/",
    deadline: Date.now() + timeout,
    signal: controller.signal,
    async select(accounts) {
      if (controller.signal.aborted) throw controller.signal.reason
      if (accounts.length === 1) return accounts[0]
      members = accounts
      state = { stage: "choose", message: "选择本次要添加的企业账号", choices: accounts.map((a, i) => ({
        choice: i, name: a.enterpriseName || a.name || "企业 " + (i + 1), member: a.nickname || a.uid,
      })) }
      return new Promise((resolve, reject) => { choose = { resolve, reject } })
    },
    finish(error) {
      clearTimeout(timer)
      state = error ? { stage: "failed", message: error } : { stage: "complete", message: "企业授权已完成，请回到 Magpie 查看账号保存结果。" }
      closeTimer = setTimeout(close, 15000)
      closeTimer.unref?.()
    },
    close,
  }
}

function page(loginUrl) {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WorkBuddy 企业账号登录</title><style>
body{margin:0;background:#f5f6f8;color:#20252b;font:16px/1.6 system-ui,sans-serif}main{max-width:600px;margin:10vh auto;padding:32px;background:white;border-radius:16px}h1{font-size:24px}a,button{display:block;box-sizing:border-box;width:100%;padding:12px 16px;margin:12px 0;border:1px solid #ddd;border-radius:9px;text-align:left;background:white;color:inherit;font:inherit;text-decoration:none;cursor:pointer}a{background:#087f67;color:white;text-align:center}button:disabled{opacity:.5;cursor:wait}small{display:block;color:#68727e}#cancel{width:auto;color:#68727e}p{white-space:pre-wrap}</style>
<main><h1>添加 WorkBuddy 企业账号</h1><p>打开扫码页完成企业微信登录，然后回到此页。若有多个企业，将在这里列出供你选择。</p>
<a href="${escape(loginUrl)}" target="_blank" rel="noopener noreferrer">打开企业微信扫码页 ↗</a>
<p id="message" role="status"></p><div id="choices"></div><button id="cancel">取消本次登录</button></main>
<script>
let rendered=false, stopped=false;
const message=document.getElementById('message'), choices=document.getElementById('choices'), cancel=document.getElementById('cancel');
async function post(action, body){const r=await fetch(action,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!r.ok)throw Error('选择未提交，请刷新页面重试');return r.json()}
cancel.onclick=async()=>{try{await post('cancel',{});stopped=true;message.textContent='已取消登录，未保存账号';choices.replaceChildren();cancel.hidden=true}catch(e){message.textContent=e.message}};
async function tick(){if(stopped)return;try{const r=await fetch('status');if(!r.ok)throw Error();const s=await r.json();message.textContent=s.message;
if(s.stage==='choose'&&!rendered){rendered=true;for(const c of s.choices){const b=document.createElement('button');b.textContent=c.name;const detail=document.createElement('small');detail.textContent=c.member;b.append(detail);b.onclick=async()=>{for(const x of choices.children)x.disabled=true;try{await post('select',{choice:c.choice});choices.replaceChildren()}catch(e){message.textContent=e.message;for(const x of choices.children)x.disabled=false}};choices.append(b)}}
if(s.stage==='complete'||s.stage==='failed'){stopped=true;cancel.hidden=true;choices.replaceChildren()}}catch{message.textContent='本次登录页面已结束，请返回 Magpie 查看结果或重新添加账号';stopped=true}if(!stopped)setTimeout(tick,800)}tick();
</script></html>`
}
