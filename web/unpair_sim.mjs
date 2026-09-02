// Unpair must wipe every parent key on the phone after a full-screen confirm.
// Run: node web/unpair_sim.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(root, "app.js"), "utf8");

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

function sliceFn(name) {
  const start = src.indexOf(`async function ${name}(`);
  const alt = src.indexOf(`function ${name}(`);
  const at = start >= 0 ? start : alt;
  if (at < 0) throw new Error("missing " + name);
  const next = [
    src.indexOf("\nasync function ", at + 1),
    src.indexOf("\nfunction ", at + 1),
  ].filter((i) => i > at);
  const end = next.length ? Math.min(...next) : src.length;
  return src.slice(at, end);
}

class FakeReq {
  constructor(result) {
    this.result = result;
    this.onsuccess = null;
    queueMicrotask(() => {
      if (this.onsuccess) this.onsuccess();
    });
  }
}

function fakeIDB() {
  const map = new Map();
  const store = {
    put(val, key) {
      map.set(key, val);
      return new FakeReq(undefined);
    },
    getAll() {
      return new FakeReq([...map.values()]);
    },
    clear() {
      map.clear();
      return new FakeReq(undefined);
    },
  };
  return {
    map,
    idb: async () => ({
      transaction() {
        const tx = { objectStore: () => store, oncomplete: null, onerror: null };
        queueMicrotask(() => {
          if (tx.oncomplete) tx.oncomplete();
        });
        return tx;
      },
    }),
  };
}

const mem = { localStorage: new Map(), cookie: "pa_rec=%5B%7B%22host_id%22%3A%22h%22%7D%5D; Path=/" };
const fake = fakeIDB();
let watchStopped = false;

const envNames = ["idb", "localStorage", "document", "STORE", "stopWatch"];
const body =
  sliceFn("saveRecord") +
  sliceFn("listRecords") +
  sliceFn("writeBridge") +
  sliceFn("clearAllRecords") +
  `\nreturn { saveRecord, listRecords, writeBridge, clearAllRecords };`;

const api = new Function(
  ...envNames,
  `"use strict";\n${body}`
)(
  fake.idb,
  {
    setItem(k, v) {
      mem.localStorage.set(k, v);
    },
    getItem(k) {
      return mem.localStorage.get(k) ?? null;
    },
    removeItem(k) {
      mem.localStorage.delete(k);
    },
  },
  {
    get cookie() {
      return mem.cookie;
    },
    set cookie(v) {
      mem.cookie = v;
    },
  },
  "keys",
  () => {
    watchStopped = true;
  }
);

await api.saveRecord("host-laptop", {
  host_id: "host-laptop",
  host_name: "milo-laptop",
  device_id: "phone-1",
  secret: "secret-aaa",
});
await api.saveRecord("host-living", {
  host_id: "host-living",
  host_name: "living-room",
  device_id: "phone-1",
  secret: "secret-bbb",
});
assert((await api.listRecords()).length === 2, "setup should store two hosts");
assert(mem.localStorage.get("pa_rec"), "bridge should hold keys before unpair");

await api.clearAllRecords();

assert(fake.map.size === 0, "IndexedDB keys must be gone");
assert((await api.listRecords()).length === 0, "listRecords must be empty after unpair");
assert(!mem.localStorage.get("pa_rec"), "localStorage pa_rec must be removed");
assert(/pa_rec=;/.test(mem.cookie) && /Max-Age=0/.test(mem.cookie), "cookie must expire pa_rec: " + mem.cookie);
assert(watchStopped, "unpair must stop live watch");

console.log("unpair_sim: all phone keys deleted ok");
