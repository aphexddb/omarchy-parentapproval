// Simulates resumePaired / boot handoff routing without a browser.
// Run: node web/safari_home_sim.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(root, "app.js"), "utf8");

function extract(name) {
  const re = new RegExp(`function ${name}\\(\\) \\{([\\s\\S]*?)\\n\\}`);
  const m = src.match(re);
  if (!m) throw new Error("missing " + name);
  return m[1];
}

function noArg(name, env) {
  return new Function(...Object.keys(env), `"use strict";${extract(name)}`).bind(null, ...Object.values(env));
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function idleFor({ ios, standalone, granted, paired }) {
  const calls = [];
  const names = [
    "isStandalone",
    "notificationsGranted",
    "pushNeedsStandalone",
    "startWatch",
    "showNotifySetup",
    "showIdle",
    "settleHomeURL",
    "hydrateRecords",
  ];
  const values = [
    () => standalone,
    () => granted,
    () => ios && !standalone,
    () => calls.push("watch"),
    () => calls.push("notify-setup"),
    (recs) => calls.push(recs && recs.length ? "home-paired" : "home-unpaired"),
    () => {},
    async () => (paired ? [{ host_id: "h" }] : []),
  ];
  const start = src.indexOf("async function resumePaired()");
  const end = src.indexOf("async function boot()");
  const resume = new Function(
    ...names,
    `"use strict";\n${src.slice(start, end)}\nreturn resumePaired;`
  )(...values);
  return resume().then(() => calls);
}

const cases = [
  { name: "iOS Safari unpaired", ios: true, standalone: false, granted: false, paired: false, want: ["home-unpaired"] },
  { name: "iOS Safari leftover pair records", ios: true, standalone: false, granted: false, paired: true, want: ["home-unpaired"] },
  { name: "iOS Home Screen needs notify", ios: true, standalone: true, granted: false, paired: true, want: ["watch", "notify-setup"] },
  { name: "iOS Home Screen ready", ios: true, standalone: true, granted: true, paired: true, want: ["watch", "home-paired"] },
  { name: "desktop / Android paired", ios: false, standalone: false, granted: false, paired: true, want: ["watch", "home-paired"] },
  { name: "desktop unpaired", ios: false, standalone: false, granted: false, paired: false, want: ["home-unpaired"] },
];

for (const c of cases) {
  const got = await idleFor(c);
  assert(JSON.stringify(got) === JSON.stringify(c.want), `${c.name}: got ${JSON.stringify(got)} want ${JSON.stringify(c.want)}`);
}

assert(noArg("shouldApplyPairHandoff", { isStandalone: () => false })() === false, "Safari must not apply pair handoff");
assert(noArg("shouldApplyPairHandoff", { isStandalone: () => true })() === true, "Home Screen must apply pair handoff");

console.log("safari_home_sim: " + cases.length + " resume paths + handoff gate ok");
