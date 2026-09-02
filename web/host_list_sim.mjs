// Idle home must list each paired computer hostname.
// Run: node web/host_list_sim.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(root, "app.js"), "utf8");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

const start = src.indexOf("function renderHostList(");
if (start < 0) throw new Error("missing renderHostList");
const next = [
  src.indexOf("\nfunction ", start + 1),
  src.indexOf("\nasync function ", start + 1),
].filter((i) => i > start);
const end = next.length ? Math.min(...next) : src.length;
const body = src.slice(start, end);

function fakeList() {
  const children = [];
  return {
    children,
    textContent: "",
    replaceChildren(...nodes) {
      children.length = 0;
      for (const n of nodes) children.push(n);
    },
    appendChild(n) {
      children.push(n);
      return n;
    },
  };
}

const document = {
  createElement(tag) {
    return { tagName: tag, textContent: "" };
  },
};

const renderHostList = new Function("document", `"use strict";\n${body}\nreturn renderHostList;`)(document);

const el = fakeList();
renderHostList(el, [
  { host_id: "a", host_name: "milo-laptop" },
  { host_id: "b", host_name: "living-room" },
  { host_id: "c" },
]);

assert(el.children.length === 3, "list length " + el.children.length);
assert(el.children[0].tagName === "li", "items must be li");
assert(el.children[0].textContent === "milo-laptop", el.children[0].textContent);
assert(el.children[1].textContent === "living-room", el.children[1].textContent);
assert(el.children[2].textContent === "laptop", "missing hostname must fall back");

renderHostList(el, []);
assert(el.children.length === 0, "empty recs must clear the list");

renderHostList(null, [{ host_name: "x" }]);

console.log("host_list_sim: paired-with list ok");
