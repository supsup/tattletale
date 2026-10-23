"use strict";
// Runs the real page script in an inert DOM. No browser, network, watcher or host inventory.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const html = fs.readFileSync(path.join(__dirname, "../dashboard/tattletale.html"), "utf8");
const clock = "2000-01-01T00:00:00Z";
class Node {
  constructor(tag = "", text = null) {
    this.nodeType = text === null ? 1 : 3;
    this.tagName = tag;
    this.children = [];
    this.data = text || "";
    this.attrs = {};
    this.dataset = {};
    this.style = {};
    this.value = "";
    this.clientWidth = 600;
    this.listeners = {};
    this.classList = {
      contains: (s) => this.className.split(/\s+/).includes(s),
      add: (s) => { if (!this.classList.contains(s)) this.className += " " + s; },
      remove: (s) => { this.className = this.className.split(/\s+/).filter((x) => x !== s).join(" "); }
    };
  }
  get className() { return this.attrs.class || ""; }
  set className(s) { this.attrs.class = s; }
  get textContent() { return this.nodeType === 3 ? this.data : this.children.map((n) => n.textContent).join(""); }
  set textContent(s) { if (this.nodeType === 3) this.data = String(s); else this.replaceChildren(new Node("", String(s))); }
  append(...kids) { for (let n of kids) { if (!(n instanceof Node)) n = new Node("", String(n)); n.parent = this; this.children.push(n); } }
  appendChild(n) { this.append(n); return n; }
  replaceChildren(...kids) { this.children = []; this.append(...kids); }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k.startsWith("data-")) this.dataset[k.slice(5)] = String(v); }
  removeAttribute(k) { delete this.attrs[k]; }
  addEventListener(k, cb) { this.listeners[k] = cb; }
  querySelector(s) { return this.querySelectorAll(s)[0] || null; }
  querySelectorAll(s) {
    const match = (n) => s[0] === "." ? n.classList.contains(s.slice(1)) : n.tagName === s;
    return this.children.flatMap((n) => [...(match(n) ? [n] : []), ...n.querySelectorAll(s)]);
  }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter((n) => n !== this); }
  get options() { return this.querySelectorAll("option"); }
}
function page() {
  const ids = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => [m[1], new Node("div")]));
  const head = new Node("head"), root = new Node("html"), body = new Node("tbody");
  const headers = ["exe", "signerClass", "user", "firstSeen", "lastSeen"].map((k) => {
    const n = new Node("th"); n.dataset.k = k; n.textContent = k; return n;
  });
  const document = {
    head, documentElement: root,
    createElement: (s) => new Node(s),
    createElementNS: (_, s) => new Node(s),
    createTextNode: (s) => new Node("", s),
    getElementById: (s) => ids.get(s) || null,
    querySelector: (s) => s === "#progs tbody" ? body : ids.get(s.slice(1)) || null,
    querySelectorAll: (s) => s === "#progs th" ? headers : []
  };
  let now = Date.parse(clock);
  class ClockDate extends Date { constructor(...args) { super(...(args.length ? args : [now])); } static now() { return now; } }
  const intervals = [];
  const context = {
    document, Date: ClockDate, console,
    localStorage: { getItem: () => null, setItem: () => {} },
    MutationObserver: class { observe() {} },
    matchMedia: () => ({ matches: false }), addEventListener: () => {},
    innerWidth: 1024, innerHeight: 768, setInterval: (fn, ms) => { intervals.push({ fn, ms }); },
    fetch: () => { throw Error("network forbidden in fixture"); }
  };
  context.window = context;
  vm.createContext(context);
  const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)[1];
  assert.match(script, /\}\)\(\);\s*$/);
  vm.runInContext(script.replace(/\}\)\(\);\s*$/, "globalThis.fixture = {render, tick, load}; })();"), context, { timeout: 1000 });
  return {
    ...context.fixture, ids, head,
    setPayload: (d, script = head.children.at(-1)) => {
      document.currentScript = script; context.TATTLETALE = d; document.currentScript = null;
    },
    text: (id) => ids.get(id).textContent,
    shown: () => ids.get("banner").classList.contains("show"),
    advance: (seconds) => { now += seconds * 1000; },
    tickInterval: () => intervals.find((x) => x.ms === 15000).fn()
  };
}
function data(status = "ok") {
  return {
    formatVersion: 2, generatedAt: clock, version: "fixture",
    collectionHealth: Object.fromEntries(["processes", "listeners", "startup", "crontab"].map((k) =>
      [k, { status, lastAttempt: status === "unknown" ? null : clock, lastSuccess: status === "ok" ? clock : null,
        error: status === "degraded" ? "collection-io" : null }])),
    map: { programs: {}, listeners: {}, credentials: [], startup: {} }, log: []
  };
}
test("fresh legacy data is unknown and cannot produce an all-clear", () => {
  const p = page(), d = data(); delete d.formatVersion; delete d.collectionHealth; p.render(d);
  assert.match(p.text("live"), /Live/);
  assert.match(p.text("collection-health"), /Process list: unknown/);
  assert.match(p.text("banner"), /Collection incomplete/);
  assert.match(p.text("att-list"), /Collection incomplete/);
  assert.doesNotMatch(p.text("tiles"), /all signed|none exposed|no changes$/i);
});
test("degraded fresh data keeps warning across the actual 15 second callback", () => {
  const p = page(); p.render(data("degraded")); p.advance(15); p.tickInterval();
  assert.match(p.text("live"), /Live/);
  assert.equal(p.shown(), true);
  assert.match(p.text("banner"), /last-known/);
  assert.match(p.text("listeners"), /no all-clear/);
});
test("healthy empty accepted sample and recovery clear only the health warning", () => {
  const p = page(); p.render(data("degraded")); p.render(data());
  assert.equal(p.shown(), false);
  assert.match(p.text("listeners"), /No listeners in the last accepted sample/);
  assert.match(p.text("att-list"), /No new observations to review/);
  assert.doesNotMatch(p.text("att-list"), /Nothing needs attention/);
});
test("stale file remains independent of successful health", () => {
  const p = page(); p.render(data()); p.advance(181); p.tick();
  assert.match(p.text("live"), /Stale/);
  assert.match(p.text("banner"), /Stale/);
  assert.match(p.text("collection-health"), /Listening sockets: ok/);
  assert.equal(p.shown(), true);
});
test("load error survives timer and a successful render recovers", () => {
  const p = page(); p.render(data()); p.load(); p.head.children.at(-1).onerror();
  p.tickInterval(); assert.match(p.text("live"), /No data/); assert.equal(p.shown(), true);
  p.render(data()); assert.match(p.text("live"), /Live/); assert.equal(p.shown(), false);
});
for (const [name, mutate] of [
  ["unsupported format", (d) => { d.formatVersion = 3; }],
  ["missing health entry", (d) => { delete d.collectionHealth.crontab; }],
  ["extra health entry", (d) => { d.collectionHealth.extra = d.collectionHealth.startup; }],
  ["missing success", (d) => { d.collectionHealth.listeners.lastSuccess = null; }],
  ["impossible date", (d) => { d.collectionHealth.listeners.lastAttempt = "2000-02-31T00:00:00Z"; }],
  ["raw error", (d) => { d.collectionHealth.listeners.error = "<script>fixture</script>"; }],
  ["extra entry field", (d) => { d.collectionHealth.listeners.extra = true; }],
  ["unattempted degraded", (d) => { d.collectionHealth.listeners = { status: "degraded", lastAttempt: null, lastSuccess: null, error: "lsof-command" }; }]
]) test(name + " fails closed to unknown", () => {
  const p = page(), d = data(); mutate(d); p.render(d);
  assert.match(p.text("collection-health"), /Listening sockets: unknown/);
  assert.match(p.text("banner"), /Collection incomplete/);
  assert.equal(p.shown(), true);
});
test("bind labels cover each scope without inferring legacy false means loopback", () => {
  const p = page(), d = data("degraded");
  ["wildcard", "non-loopback", "loopback", undefined].forEach((scope, i) => {
    d.map.listeners["/fixture/service" + i + " 192.0.2.10:" + (12000 + i)] =
      { present: true, bindScope: scope, exposed: false, firstSeen: clock, lastSeen: clock, command: "fixture" };
  });
  p.render(d);
  for (const s of ["All interfaces bind", "Explicit non-loopback bind", "Loopback bind", "Unknown bind scope"]) assert.match(p.text("listeners"), new RegExp(s));
  assert.match(p.text("listeners"), /Last-known values/);
  assert.doesNotMatch(p.text("listeners"), /This Mac only|reachable from|Nothing exposed/);
  assert.match(p.text("tiles"), /Non-loopback binds2/);
});
test("health success may follow attempt start without being rejected", () => {
  const p = page(), d = data(); d.collectionHealth.listeners.lastSuccess = "2000-01-01T00:00:01Z"; p.render(d);
  assert.match(p.text("collection-health"), /Listening sockets: ok/);
});
test("retained absent rows are described as last accepted observations", () => {
  const p = page(), d = data("degraded");
  d.map.listeners["/fixture/service 127.0.0.1:12345"] = { present: false, bindScope: "loopback", lastSeen: clock };
  p.render(d); assert.match(p.text("listeners"), /Absent from last accepted sample/);
});
test("static copy makes no reachability claim", () => {
  assert.doesNotMatch(html, /Exposed means reachable|reachable from the network|This Mac only|Nothing needs attention/);
});
test("missing file timestamp cannot retain an earlier Live indicator", () => {
  const p = page(), d = data(); p.render(d); delete d.generatedAt; p.render(d);
  assert.match(p.text("live"), /Stale, unknown timestamp/);
  assert.equal(p.shown(), true);
});
test("non-string bind scope is unknown without coercing untrusted data", () => {
  const p = page(), d = data();
  d.map.listeners["/fixture/service 192.0.2.10:12345"] = { present: true, bindScope: { toString: null } };
  p.render(d); assert.match(p.text("listeners"), /Unknown bind scope/);
});
test("a loaded script without a fresh assignment cannot reuse the last payload", () => {
  const p = page(); p.setPayload(data()); p.load(); p.head.children.at(-1).onload();
  p.tick(); assert.match(p.text("live"), /No data/); assert.equal(p.shown(), true);
});
test("malformed map after a good sample leaves a persistent error, not green health", () => {
  const p = page(), d = data(); p.render(d); d.map.programs["/fixture/service"] = null; p.render(d);
  p.tick(); assert.match(p.text("live"), /No data/);
  assert.match(p.text("collection-health"), /Process list: unknown/);
  assert.match(p.text("att-list"), /no accepted refresh/);
  assert.equal(p.shown(), true);
});
test("obsolete load callback cannot clear the newer failure", () => {
  const p = page(); p.load(); const old = p.head.children.at(-1); p.load(); const current = p.head.children.at(-1);
  current.onerror(); p.setPayload(data()); old.onload(); p.tick();
  assert.match(p.text("live"), /No data/);
});
test("new assignment on current load recovers after load failure", () => {
  const p = page(); p.head.children.at(-1).onerror(); p.load(); p.setPayload(data()); p.head.children.at(-1).onload();
  assert.match(p.text("live"), /Live/); assert.equal(p.shown(), false);
});
test("older overlapping assignment cannot supply an empty current script", () => {
  const p = page(), old = p.head.children.at(-1); p.load(); const current = p.head.children.at(-1);
  p.setPayload(data(), old); old.onload(); current.onload(); p.tick();
  assert.match(p.text("live"), /No data/); assert.match(p.text("collection-health"), /Listening sockets: unknown/);
});
