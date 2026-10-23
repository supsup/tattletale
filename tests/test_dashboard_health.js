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
    programText: () => body.textContent,
    failNextProgramRender: () => {
      const replace = body.replaceChildren.bind(body);
      body.replaceChildren = (...kids) => {
        body.replaceChildren = replace;
        throw Error("synthetic one-shot final program-panel DOM failure");
      };
    },
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
  p.tickInterval(); assert.match(p.text("live"), /Refresh failed/); assert.equal(p.shown(), true);
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
test("malformed map retains last accepted health under a persistent refresh error", () => {
  const p = page(), d = data(); p.render(d); d.map.programs["/fixture/service"] = null; p.render(d);
  p.tick(); assert.match(p.text("live"), /Refresh failed/);
  assert.match(p.text("collection-health"), /Process list: ok/);
  assert.match(p.text("collection-health"), /Last-known health/);
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

for (const [name, fields, expected] of [
  ["legacy true", { exposed: true }, "All interfaces bind"],
  ["legacy false", { exposed: false }, "Unknown bind scope"],
  ["legacy missing", {}, "Unknown bind scope"],
  ["legacy number", { exposed: 1 }, "Unknown bind scope"],
  ["legacy string", { exposed: "true" }, "Unknown bind scope"],
  ["explicit unknown", { exposed: true, bindScope: "unknown" }, "Unknown bind scope"],
  ["explicit null", { exposed: true, bindScope: null }, "Unknown bind scope"],
  ["explicit undefined", { exposed: true, bindScope: undefined }, "Unknown bind scope"],
  ["explicit invalid", { exposed: true, bindScope: "invalid" }, "Unknown bind scope"],
  ["explicit loopback", { exposed: true, bindScope: "loopback" }, "Loopback bind"]
]) test(name + " scope uses only the precise legacy fallback", () => {
  const p = page(), d = data(); delete d.formatVersion; delete d.collectionHealth;
  d.map.listeners["/fixture/legacy *:12345"] = { present: true, ...fields };
  p.render(d);
  assert.match(p.text("listeners"), new RegExp(expected));
  assert.match(p.text("collection-health"), /Listening sockets: unknown/);
  assert.match(p.text("tiles"), new RegExp("Non-loopback binds" + (expected === "All interfaces bind" ? "1" : "0")));
  if (expected === "All interfaces bind") assert.match(p.text("att-list"), /Non-loopback listener binds/);
});
test("legacy wildcard inference cannot resurrect an absent listener", () => {
  const p = page(), d = data(); d.map.listeners["/fixture/legacy *:12345"] = { present: false, exposed: true, lastSeen: clock };
  p.render(d); assert.match(p.text("tiles"), /Non-loopback binds0/);
  assert.doesNotMatch(p.text("att-list"), /Non-loopback listener binds/);
});
test("fixed incomplete check names coexist with both fresh and stale file status", () => {
  const p = page(), d = data();
  d.collectionHealth.listeners = { status: "degraded", lastAttempt: clock, lastSuccess: clock, error: "lsof-command" };
  d.collectionHealth.startup = { status: "unknown", lastAttempt: null, lastSuccess: null, error: null };
  p.render(d);
  for (const age of [0, 180, 181]) {
    if (age === 180) p.advance(180);
    if (age === 181) p.advance(1);
    p.tickInterval();
    assert.match(p.text("live"), age > 180 ? /Stale/ : /Live/);
    assert.match(p.text("banner"), /Listening sockets: degraded/);
    assert.match(p.text("banner"), /Startup items: unknown/);
    assert.doesNotMatch(p.text("banner"), /Process list: degraded|Crontab: degraded/);
  }
});
test("first in-flight attempt is truthful unknown health without discarding other checks", () => {
  const p = page(), d = data();
  d.collectionHealth.startup = { status: "unknown", lastAttempt: clock, lastSuccess: null, error: null };
  p.render(d);
  assert.match(p.text("collection-health"), /Process list: ok/);
  assert.match(p.text("collection-health"), /Startup items: unknown \| attempted: 2000-01-01T00:00:00Z/);
  assert.match(p.text("banner"), /Startup items: unknown/);
});
test("refresh failure retains actual last accepted metadata and inventory", () => {
  const p = page(), d = data();
  d.collectionHealth.listeners = { status: "degraded", lastAttempt: clock, lastSuccess: clock, error: "lsof-command" };
  d.map.listeners["/fixture/accepted 127.0.0.1:12345"] = { present: true, bindScope: "loopback", command: "accepted" };
  p.render(d);
  const health = p.text("collection-health"), updated = p.text("updated"), inventory = p.text("listeners");
  p.load(); p.head.children.at(-1).onerror(); p.advance(181); p.tickInterval();
  assert.match(p.text("live"), /Refresh failed/);
  assert.match(p.text("collection-health"), /Last-known health/);
  assert.ok(p.text("collection-health").includes(health));
  assert.ok(p.text("updated").includes(updated));
  assert.equal(p.text("listeners"), inventory);
  assert.match(p.text("banner"), /last-known/);
  assert.match(p.text("banner"), /Listening sockets: degraded/);
  assert.doesNotMatch(p.text("collection-health"), /Listening sockets: unknown/);
});
test("late rejected render restores the complete accepted view and detached payload", () => {
  const p = page(), accepted = data();
  accepted.map.listeners["/fixture/accepted 127.0.0.1:12345"] = { present: true, bindScope: "loopback", command: "accepted" };
  p.render(accepted);
  const inventory = p.text("listeners"), tiles = p.text("tiles"), updated = p.text("updated");
  // The caller must not be able to mutate the retained snapshot after acceptance.
  accepted.collectionHealth.listeners.status = "degraded";
  accepted.collectionHealth.listeners.error = "lsof-command";
  const rejected = data("degraded"); rejected.generatedAt = "2000-01-01T00:01:00Z"; rejected.version = "rejected";
  rejected.map.programs["/fixture/rejected"] = { firstSeen: "invalid-date" };
  p.render(rejected); p.tickInterval();
  assert.match(p.text("live"), /Refresh failed/);
  assert.match(p.text("collection-health"), /Listening sockets: ok/);
  assert.ok(p.text("updated").includes(updated));
  assert.equal(p.text("listeners"), inventory);
  assert.equal(p.text("tiles"), tiles);
  assert.doesNotMatch(p.text("ver"), /rejected/);
  p.render(data()); assert.match(p.text("live"), /Live/); assert.equal(p.shown(), false);
});
test("initial late render failure leaves no mixed inventory or false accepted metadata", () => {
  const p = page(), d = data(); d.map.programs["/fixture/rejected"] = { firstSeen: "invalid-date" };
  p.render(d); p.tickInterval();
  assert.match(p.text("live"), /No data/);
  assert.match(p.text("collection-health"), /Process list: unknown/);
  assert.equal(p.text("updated"), ""); assert.equal(p.text("tiles"), "");
  assert.equal(p.text("listeners"), ""); assert.equal(p.shown(), true);
});
test("final panel failure restores every earlier inventory panel from the fully accepted payload", () => {
  const p = page(), accepted = data(); accepted.version = "accepted";
  const program = (name) => ({ firstSeen: clock, lastSeen: clock, user: "fixture", signer: "adhoc", firstArgs: name });
  accepted.map.programs["/fixture/old"] = program("old");
  accepted.map.listeners["/fixture/old 127.0.0.1:12345"] = { present: true, bindScope: "loopback", command: "old" };
  accepted.map.startup["/fixture/old"] = "old-hash";
  accepted.map.credentials.push({ time: clock, exe: "/fixture/old", args: "old", chain: "old", source: "ps" });
  accepted.log = [clock + "  STARTUP+  added: /fixture/old | copy: /fixture/copies/old"];
  p.render(accepted);
  const panels = ["tiles", "listeners", "creds", "timeline", "signers", "startup", "feed", "chips", "progCount", "ver"];
  const old = Object.fromEntries(panels.map((id) => [id, p.text(id)]));
  const oldPrograms = p.programText(), oldUpdated = p.text("updated"), oldHealth = p.text("collection-health");
  accepted.map.listeners["/fixture/old 127.0.0.1:12345"].command = "caller-mutated";
  accepted.map.programs["/fixture/old"].signer = "caller-mutated";
  const rejected = data("degraded"); rejected.version = "rejected"; rejected.generatedAt = "2000-01-01T00:01:00Z";
  rejected.map.programs["/fixture/new"] = program("new");
  rejected.map.listeners["/fixture/new *:23456"] = { present: true, bindScope: "wildcard", command: "new" };
  rejected.map.startup["/fixture/new"] = "new-hash";
  rejected.map.credentials.push({ time: clock, exe: "/fixture/new", args: "new", chain: "new", source: "ps" });
  rejected.log = [clock + "  STARTUP+  added: /fixture/new | copy: /fixture/copies/new"];
  p.failNextProgramRender(); p.render(rejected); p.tickInterval();
  for (const id of panels) assert.equal(p.text(id), old[id], id + " retained rejected data");
  assert.equal(p.programText(), oldPrograms);
  assert.ok(p.text("collection-health").includes(oldHealth));
  assert.ok(p.text("updated").includes(oldUpdated));
  assert.match(p.text("live"), /Refresh failed/);
  assert.doesNotMatch(p.text("listeners") + p.programText(), /caller-mutated|\/fixture\/new/);
});
test("strict lsof warning is named with retained listeners in both Live and Stale views", () => {
  const p = page(), d = data();
  d.collectionHealth.listeners = { status: "degraded", lastAttempt: clock, lastSuccess: clock, error: "lsof-warning" };
  d.map.listeners["/fixture/retained 127.0.0.1:12345"] = { present: true, bindScope: "loopback", command: "retained" };
  p.render(d);
  for (const stale of [false, true]) {
    if (stale) p.advance(181);
    p.tickInterval();
    assert.match(p.text("live"), stale ? /Stale/ : /Live/);
    assert.match(p.text("banner"), /Listening sockets: degraded \(lsof-warning\)/);
    assert.match(p.text("collection-health"), /Listening sockets: degraded.*lsof-warning/);
    assert.match(p.text("listeners"), /retained/);
    assert.match(p.text("listeners"), /Last-known values; collection degraded/);
    assert.doesNotMatch(p.text("att-list"), /No new observations to review/);
  }
});

function publication(d, status = "ok", asOf = clock) {
  d.publicationHealth = { lastAttempt: status === "unknown" ? null : clock,
    lastSuccess: status === "unknown" ? null : clock, status,
    error: status === "degraded" ? "collection-db" : null };
  d.inventoryAsOf = asOf;
  return d;
}
test("database fallback names publication and labels every inventory last-known in Live and Stale views", () => {
  const p = page(), d = publication(data(), "degraded");
  d.map.listeners["/fixture/retained 127.0.0.1:12345"] = { present: true, bindScope: "loopback", command: "retained" };
  p.render(d);
  for (const stale of [false, true]) {
    if (stale) p.advance(181);
    p.tickInterval();
    assert.match(p.text("live"), stale ? /Stale/ : /Live/);
    assert.match(p.text("banner"), /Database publication: degraded \(collection-db\)/);
    assert.match(p.text("collection-health"), /Process list: ok/);
    assert.match(p.text("collection-health"), /Inventory as of: 2000-01-01T00:00:00Z/);
    for (const id of ["listeners", "creds", "startup", "tiles"]) assert.match(p.text(id), /Last-known inventory/);
    assert.doesNotMatch(p.text("att-list"), /No new observations to review/);
  }
});
test("publication recovery clears only publication warning and uses the fresh projection timestamp", () => {
  const p = page(); p.render(publication(data(), "degraded"));
  const d = publication(data()); d.inventoryAsOf = "2000-01-01T00:01:00Z"; d.generatedAt = "2000-01-01T00:02:00Z";
  p.render(d);
  assert.equal(p.shown(), false);
  assert.match(p.text("collection-health"), /Database publication: ok/);
  assert.match(p.text("collection-health"), /Inventory as of: 2000-01-01T00:01:00Z/);
  assert.equal(p.text("listeners"), "No listeners in the last accepted sample.");
  assert.doesNotMatch(p.text("listeners"), /Last-known inventory/);
});
test("new epoch can have a real cached projection with unknown publication and no invented success", () => {
  const p = page(); p.render(publication(data(), "unknown"));
  assert.match(p.text("collection-health"), /Database publication: unknown \| attempted: not yet \| last successful publication: not yet/);
  assert.match(p.text("banner"), /Database publication: unknown/);
  assert.match(p.text("collection-health"), /Inventory as of: 2000-01-01T00:00:00Z/);
  assert.match(p.text("listeners"), /Last-known inventory/);
});
for (const [name, mutate] of [
  ["missing projection time", (d) => { delete d.inventoryAsOf; }],
  ["projection without publication", (d) => { delete d.publicationHealth; }],
  ["invalid projection time", (d) => { d.inventoryAsOf = "2000-02-31T00:00:00Z"; }],
  ["numeric projection time", (d) => { d.inventoryAsOf = 0; }],
  ["ok without projection", (d) => { d.inventoryAsOf = null; }],
  ["invalid publication shape", (d) => { d.publicationHealth.extra = true; }],
  ["unknown fixed diagnostic", (d) => { d.publicationHealth = { status: "degraded", lastAttempt: clock, lastSuccess: null, error: "lsof-warning" }; }],
  ["raw publication diagnostic", (d) => { d.publicationHealth = { status: "degraded", lastAttempt: clock, lastSuccess: null, error: "<script>private</script>" }; }],
  ["undefined present publication", (d) => { d.publicationHealth = undefined; }]
]) test(name + " cannot hide a malformed additive publication contract behind legacy behavior", () => {
  const p = page(), d = publication(data()); mutate(d); p.render(d); p.tickInterval();
  assert.match(p.text("collection-health"), /Database publication: unknown/);
  assert.match(p.text("banner"), /Database publication: unknown/);
  assert.doesNotMatch(p.text("att-list"), /No new observations to review/);
  assert.doesNotMatch(p.text("collection-health"), /<script>|private/);
  assert.equal(p.shown(), true);
});
test("the bounded in-memory I/O diagnostic is supported without implying that its failed write was delivered", () => {
  const p = page(), d = publication(data(), "degraded"); d.publicationHealth.error = "collection-io"; p.render(d);
  assert.match(p.text("banner"), /Database publication: degraded \(collection-io\)/);
  assert.match(p.text("listeners"), /Last-known inventory/);
});
test("late render failure and failed refresh preserve the exact prior publication and inventory age", () => {
  const p = page(), old = publication(data(), "degraded"); p.render(old);
  const oldHealth = p.text("collection-health"), oldUpdated = p.text("updated");
  old.publicationHealth.status = "ok"; old.inventoryAsOf = "2000-01-01T00:02:00Z";
  const fresh = publication(data()); fresh.inventoryAsOf = "2000-01-01T00:03:00Z";
  p.failNextProgramRender(); p.render(fresh); p.tickInterval();
  assert.ok(p.text("collection-health").includes(oldHealth));
  assert.ok(p.text("updated").includes(oldUpdated));
  assert.match(p.text("collection-health"), /Database publication: degraded/);
  assert.match(p.text("collection-health"), /Inventory as of: 2000-01-01T00:00:00Z/);
  p.load(); p.head.children.at(-1).onerror(); p.tickInterval();
  assert.match(p.text("collection-health"), /Database publication: degraded/);
});

for (const legacy of [false, true]) test((legacy ? "legacy" : "format-2") + " first readable content is one safe-rendered STARTUP~ observation", () => {
  const p = page(), d = data();
  if (legacy) { delete d.formatVersion; delete d.collectionHealth; }
  const item = "/fixture/<img src=x onerror=fixture>.plist";
  const after = "/fixture/copies/fixture_entry/06f961b802bc46ee";
  d.map.startup[item] = "06f961b802bc46ee168555f066d28f4f0e9afdf3f88174c1ee6f9de004fc30a0";
  d.log = [clock + "  STARTUP~  changed: " + item + " | before: None | after: " + after];
  p.render(d);
  assert.match(p.text("startup"), /1 change/);
  assert.match(p.text("att-list"), /Startup item changes1/);
  assert.match(p.text("feed"), /STARTUP~/);
  assert.ok(p.text("feed").includes("before: None | after: " + after));
  assert.ok(p.text("feed").includes(item));
  for (const id of ["startup", "att-list", "feed"]) {
    assert.equal(p.ids.get(id).querySelectorAll("img").length, 0);
    assert.equal(p.ids.get(id).querySelectorAll("script").length, 0);
  }
  if (legacy) assert.match(p.text("collection-health"), /Startup items: unknown/);
  // Re-rendering the same accepted event history must not duplicate the observation.
  p.render(d);
  assert.equal((p.text("feed").match(/STARTUP~/g) || []).length, 1);
  assert.match(p.text("startup"), /1 change/);
});
