import { afterEach, expect, test } from "bun:test"
import { WorkBuddyAuthPlugin, WorkBuddyAIAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => {
  globalThis.fetch = real
  _internal.renewing.clear()
  _internal.renewed.clear()
})
const ok = (data) => new Response(JSON.stringify({ code: 0, data }))
const link = "https://www.workbuddy.cn/login?platform=workbuddy&state=test-session&version=5.9.3&loginSessionId=test-login&login_owner_id=test-owner&ww_device_nonce=test-nonce"
const member = (id = "ent-a", uid = "user-a") => ({ uid, enterpriseId: id, enterpriseName: "Example", nickname: "User", type: "enterprise", pluginEnabled: true })
const token = { accessToken: "personal", refreshToken: "personal-refresh", expiresIn: 3600, domain: "www.workbuddy.cn" }
const enterpriseToken = { ...token, accessToken: "enterprise", refreshToken: "enterprise-refresh" }
async function method(ai = false) {
  const hooks = await (ai ? WorkBuddyAIAuthPlugin : WorkBuddyAuthPlugin)({ client: {} })
  return { hooks, login: hooks.auth.methods.find((m) => m.prompts?.some((p) => p.key === "loginUrl")) }
}
function server({ accounts = [member()], switched = enterpriseToken, after = accounts } = {}) {
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url)), headers = new Headers(init?.headers)
    calls.push({ url: u, headers, method: init?.method })
    expect(u.origin).toBe("https://www.workbuddy.cn")
    if (u.pathname.endsWith("/auth/token")) return ok(token)
    if (u.pathname.includes("/login/enterprise/")) return ok(switched)
    if (u.pathname.endsWith("/accounts")) return ok(headers.get("authorization") === "Bearer personal" ? { accounts } : { accounts: after })
    throw new Error("Unexpected request")
  }
  return calls
}
async function sign(inputs = {}, options = {}) {
  const calls = server(options)
  const { login } = await method()
  const flow = await login.authorize({ loginUrl: link })
  const result = flow.callback()
  if (inputs.pick !== undefined) {
    await waiting(flow.url)
    await select(flow.url, inputs.pick)
  }
  return { result: await result, calls, flow }
}

async function waiting(url) {
  for (let i = 0; i < 100; i++) {
    const state = await (await real(url + "status")).json()
    if (state.stage === "choose") return state
    await new Promise((r) => setTimeout(r, 3))
  }
  throw new Error("enterprise list never appeared")
}
async function select(url, choice) {
  return real(url + "select", { method: "POST", headers: { Origin: new URL(url).origin, "Content-Type": "application/json" }, body: JSON.stringify({ choice }) })
}

test("enterprise login is a separate domestic method; old method indices stay unchanged", async () => {
  const { hooks, login } = await method()
  expect(hooks.auth.methods.map((m) => m.type)).toEqual(["oauth", "oauth", "api", "oauth"])
  expect(login).toBeDefined()
  expect(login.prompts.map((p) => p.key)).toEqual(["loginUrl"])
  expect((await method(true)).login).toBeUndefined()
})

test("uses the pasted state and preserves owner/device parameters without another auth state", async () => {
  const { result, calls, flow } = await sign()
  expect(result.type).toBe("success")
  expect(new URL(flow.url).hostname).toBe("127.0.0.1")
  const html = await (await real(flow.url)).text()
  const url = new URL(html.match(/href="([^"]+)"/)[1].replaceAll("&amp;", "&"))
  for (const key of ["state", "version", "loginSessionId", "login_owner_id", "ww_device_nonce"])
    expect(url.searchParams.get(key)).toBe(new URL(link).searchParams.get(key))
  expect(url.searchParams.get("force_login_type")).toBe("wecom")
  expect(calls[0].url.searchParams.get("state")).toBe("test-session")
  expect(calls.some((c) => c.url.pathname.endsWith("/auth/state"))).toBe(false)
  expect(JSON.stringify(result)).not.toContain("test-owner")
  expect(JSON.stringify(result)).not.toContain("test-session")
})

test("rejects foreign hosts, misleading hosts, credentials, invalid paths and ambiguous sessions before networking", async () => {
  globalThis.fetch = () => { throw new Error("must not request") }
  const { login } = await method()
  for (const url of ["not a URL", link.replace("https:", "http:"), link.replace("www.workbuddy.cn", "www.workbuddy.ai"), link.replace("www.workbuddy.cn", "www.workbuddy.cn.evil.test"), link.replace("https://", "https://user:pass@"), link.replace("/login?", "/other?"), link + "&state=other", link.replace("state=test-session", "state="), link.replace("platform=workbuddy", "platform=other")]) {
    expect(login.prompts[0].validate(url)).toBeTypeOf("string")
    await expect(login.authorize({ loginUrl: url })).rejects.toThrow()
  }
})

test("switches explicitly to the only enabled enterprise and keeps its own tokens", async () => {
  const { result, calls } = await sign({}, { accounts: [member(), { ...member("disabled"), pluginEnabled: false }, { ...member("personal"), type: "personal" }] })
  expect(result.access).toBe("enterprise")
  expect(result.refresh).toBe("enterprise-refresh")
  expect(result.enterpriseId).toBe("ent-a")
  expect(result.uid).toBe("user-a")
  expect(result.enterpriseLogin).toBe(true)
  const switched = calls.find((c) => c.url.pathname.includes("/login/enterprise/"))
  expect(switched.method).toBe("POST")
  expect(switched.headers.get("x-enterprise-id")).toBe("ent-a")
  expect(switched.headers.get("x-tenant-id")).toBe("ent-a")
})

test("multiple enterprises are shown by name after scanning and wait for a click without switching", async () => {
  const calls = server({ accounts: [member(), { ...member("ent-b"), enterpriseName: "Second company" }] })
  const { login } = await method()
  const flow = await login.authorize({ loginUrl: link })
  const pending = flow.callback()
  const state = await waiting(flow.url)
  expect(state.choices.map((c) => c.name)).toEqual(["Example", "Second company"])
  expect(JSON.stringify(state)).not.toContain("enterprise-refresh")
  expect(calls.some((c) => c.url.pathname.includes("/login/enterprise/"))).toBe(false)
  expect((await select(flow.url, 99)).status).toBe(409)
  expect((await select(flow.url, 1)).status).toBe(200)
  const result = await pending
  expect(result.type).toBe("success")
  expect(result.enterpriseId).toBe("ent-b")
})

test("each selected enterprise is a separate stable account, even after names change", async () => {
  const accounts = [member(), member("ent-b")]
  const a = (await sign({ pick: 0 }, { accounts })).result
  const b = (await sign({ pick: 1 }, { accounts })).result
  const renamed = (await sign({}, { accounts: [{ ...member(), nickname: "Renamed", enterpriseName: "New name" }] })).result
  expect(a.type).toBe("success")
  expect(b.type).toBe("success")
  expect(a.accountId).not.toBe(b.accountId)
  expect(a.accountId).toBe(renamed.accountId)
  expect(a.uid).toBe(b.uid)
})

test("personal-only and unlisted enterprise identities fail without switching", async () => {
  for (const options of [{ accounts: [] }, { accounts: [{ ...member(), type: "personal" }] }]) {
    const { result, calls } = await sign({}, options)
    expect(result.type).toBe("failed")
    expect(calls.some((c) => c.url.pathname.includes("/login/enterprise/"))).toBe(false)
  }
})

test("missing enterprise token or mismatched returned identity never falls back to a personal sign-in", async () => {
  for (const switched of [{}, { ...enterpriseToken, uid: "other" }, { ...enterpriseToken, enterpriseId: "other" }])
    expect((await sign({}, { switched })).result.type).toBe("failed")
  expect((await sign({}, { after: [member("other")] })).result.type).toBe("failed")
})

test("an enterprise switch without a refresh token does not keep the personal refresh token", async () => {
  const { refreshToken, ...switched } = enterpriseToken
  const { result } = await sign({}, { switched })
  expect(result.type).toBe("success")
  expect(result.refresh).toBe("")
})

test("expired login state fails with the upstream error without saving or switching", async () => {
  globalThis.fetch = async () => new Response(JSON.stringify({ code: 11218, msg: "login state expired" }), { status: 400 })
  const { login } = await method()
  const flow = await login.authorize({ loginUrl: link })
  const result = await flow.callback()
  expect(result.type).toBe("failed")
  expect(result.error).toContain("expired")
})

test("renewal verifies enterprise membership before returning new credentials", async () => {
  const { hooks } = await method()
  const a = { type: "oauth", access: "old", refresh: "refresh-verify", uid: "user-a", enterpriseId: "ent-a", enterpriseLogin: true }
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url))
    calls.push(u.pathname)
    expect(new Headers(init.headers).get("x-enterprise-id")).toBe("ent-a")
    return ok(u.pathname.endsWith("/refresh") ? enterpriseToken : { accounts: [member("other")] })
  }
  await expect(hooks.auth.refresh(a)).rejects.toThrow("企业")
  expect(calls).toEqual(["/v2/plugin/auth/token/refresh", "/v2/plugin/accounts"])
})

test("concurrent enterprise renewals stay isolated even with the same input refresh token", async () => {
  const { hooks } = await method()
  globalThis.fetch = async (url, init) => {
    const id = new Headers(init.headers).get("x-enterprise-id")
    return ok(String(url).endsWith("/refresh") ? { accessToken: `new-${id}`, refreshToken: `refresh-${id}` } : { accounts: [member(id)] })
  }
  const a = { type: "oauth", access: "old", refresh: "same", uid: "user-a", enterpriseId: "ent-a", enterpriseLogin: true }
  const [x, y] = await Promise.all([hooks.auth.refresh(a), hooks.auth.refresh({ ...a, enterpriseId: "ent-b" })])
  expect(x.access).toBe("new-ent-a")
  expect(y.access).toBe("new-ent-b")
})

test("enterprise account usage never reads the personal wallet, including on a renewal", async () => {
  const { hooks } = await method()
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url)), h = new Headers(init.headers)
    calls.push(u.pathname)
    expect(u.pathname).not.toContain("get-user-resource-summary")
    if (u.pathname.endsWith("get-enterprise-user-usage")) {
      expect(h.get("x-enterprise-id")).toBe("ent-a")
      if (h.get("authorization") === "Bearer old") return new Response("Unauthorized", { status: 401 })
      return ok({ credit: 30, limitNum: 100, nextQuotaDate: "2026-11-01" })
    }
    if (u.pathname.endsWith("/refresh")) return ok(enterpriseToken)
    if (u.pathname.endsWith("/accounts")) return ok({ accounts: [member()] })
    return ok({ agents: [], models: [] })
  }
  const got = await hooks.auth.usage(async () => ({ type: "oauth", access: "old", refresh: "usage-refresh", uid: "user-a", enterpriseId: "ent-a", enterpriseLogin: true }))
  expect(got.error).toBeUndefined()
  expect(got.plan).toBe("Enterprise")
  expect(got.signIn).toBe("renewed")
  expect(calls.filter((p) => p.endsWith("get-enterprise-user-usage"))).toHaveLength(2)
})

test("a tenant mismatch on pre-request renewal never sends the chat with old credentials", async () => {
  const { hooks } = await method()
  let chat = false
  globalThis.fetch = async (url) => {
    if (String(url).includes("chat/completions")) { chat = true; throw new Error("must not send") }
    return ok(String(url).endsWith("/refresh") ? enterpriseToken : { accounts: [member("other")] })
  }
  const opts = await hooks.auth.loader(async () => ({ type: "oauth", access: "old", refresh: "mismatch-refresh", expires: 1, uid: "user-a", enterpriseId: "ent-a", enterpriseLogin: true }))
  await expect(opts.fetch("https://copilot.tencent.com/v2/chat/completions", { method: "POST", body: "{}" })).rejects.toThrow("企业")
  expect(chat).toBe(false)
})
