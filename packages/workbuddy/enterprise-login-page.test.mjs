import { expect, test } from "bun:test"
import { enterpriseLoginPage } from "./enterprise-login-page.mjs"

const accounts = [{ enterpriseName: "Company A", nickname: "Member A", enterpriseId: "a", uid: "u" },
  { enterpriseName: "Company B", nickname: "Member B", enterpriseId: "b", uid: "u" }]
const send = (url, body, origin = new URL(url).origin) => fetch(url, {
  method: "POST", headers: { Origin: origin, "Content-Type": "application/json" }, body: JSON.stringify(body),
})

test("only a same-session same-origin choice selects a server-listed member, once", async () => {
  const page = await enterpriseLoginPage("https://www.workbuddy.cn/login?state=example")
  try {
    const picked = page.select(accounts)
    const state = await (await fetch(page.url + "status")).json()
    expect(state.choices.map((c) => c.name)).toEqual(["Company A", "Company B"])
    expect((await send(page.url + "select", { choice: 1 }, "https://evil.invalid")).status).toBe(403)
    expect((await send(page.url.replace(/\/[a-f0-9]+\/$/, "/wrong/") + "select", { choice: 1 })).status).toBe(404)
    expect((await send(page.url + "select", { choice: "1" })).status).toBe(409)
    expect((await send(page.url + "select", { choice: 1 })).status).toBe(200)
    expect(await picked).toEqual(accounts[1])
    expect((await send(page.url + "select", { choice: 0 })).status).toBe(409)
    page.finish()
    expect((await (await fetch(page.url + "status")).json()).stage).toBe("complete")
  } finally { page.close() }
})

test("cancel rejects a pending selection and leaves no account selected", async () => {
  const page = await enterpriseLoginPage("https://www.workbuddy.cn/login?state=example")
  try {
    const pending = page.select(accounts).catch((error) => error)
    expect((await send(page.url + "cancel", {})).status).toBe(200)
    expect((await pending).message).toContain("取消")
    expect(page.signal.aborted).toBe(true)
    expect((await send(page.url + "select", { choice: 0 })).status).toBe(409)
  } finally { page.close() }
})

test("a login never completed by its host expires and releases its listener", async () => {
  const page = await enterpriseLoginPage("https://www.workbuddy.cn/login?state=example", 40)
  const outcome = page.select(accounts).catch((error) => error)
  expect((await outcome).message).toContain("超时")
  expect(page.signal.aborted).toBe(true)
  await expect(fetch(page.url)).rejects.toThrow()
})

test("upstream names are data and the login link is escaped in the guide", async () => {
  const page = await enterpriseLoginPage('https://www.workbuddy.cn/login?state=example&x="<script>alert(1)</script>')
  try {
    const html = await (await fetch(page.url)).text()
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).toContain("&lt;script&gt;")
    expect(html).toContain("textContent=c.name")
    const response = await fetch(page.url)
    expect(response.headers.get("cache-control")).toBe("no-store")
    expect(response.headers.get("content-security-policy")).toContain("frame-ancestors 'none'")
  } finally { page.close() }
})
