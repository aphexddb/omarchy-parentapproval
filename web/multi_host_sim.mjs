// Phone-side pairing store: one key per host_id, each with a hostname.
// Run: node web/multi_host_sim.mjs

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
    this.error = null;
    this.onsuccess = null;
    this.onerror = null;
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
    get(key) {
      return new FakeReq(map.get(key));
    },
    getAll() {
      return new FakeReq([...map.values()]);
    },
    clear() {
      map.clear();
      return new FakeReq(undefined);
    },
    get size() {
      return map.size;
    },
  };
  return {
    store,
    map,
    idb: async () => ({
      transaction() {
        const tx = {
          objectStore: () => store,
          oncomplete: null,
          onerror: null,
        };
        queueMicrotask(() => {
          if (tx.oncomplete) tx.oncomplete();
        });
        return tx;
      },
    }),
  };
}

const mem = { localStorage: new Map(), cookie: "" };

function storageEnv(idbFn) {
  return {
    idb: idbFn,
    listRecords: null,
    writeBridge: null,
    localStorage: {
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
    document: {
      get cookie() {
        return mem.cookie;
      },
      set cookie(v) {
        mem.cookie = v;
      },
    },
  };
}

function bindStorage(idbFn) {
  const env = storageEnv(idbFn);
  const names = ["idb", "localStorage", "document", "STORE"];
  const body =
    sliceFn("saveRecord") +
    sliceFn("loadRecord") +
    sliceFn("listRecords") +
    sliceFn("writeBridge") +
    sliceFn("readBridge") +
    sliceFn("hydrateRecords") +
    `\nreturn { saveRecord, loadRecord, listRecords, writeBridge, readBridge, hydrateRecords };`;
  const factory = new Function(...names, `"use strict";\n${body}`);
  return factory(env.idb, env.localStorage, env.document, "keys");
}

const fake = fakeIDB();
const api = bindStorage(fake.idb);

const laptop = {
  host_id: "host-laptop",
  host_name: "milo-laptop",
  device_id: "phone-1",
  secret: "secret-aaa",
};
const living = {
  host_id: "host-living",
  host_name: "living-room",
  device_id: "phone-1",
  secret: "secret-aaa",
};

await api.saveRecord(laptop.host_id, laptop);
await api.saveRecord(living.host_id, living);

const recs = await api.listRecords();
assert(recs.length === 2, "phone must keep a record per paired computer, got " + recs.length);
const names = recs.map((r) => r.host_name).sort();
assert(JSON.stringify(names) === JSON.stringify(["living-room", "milo-laptop"]), "hostnames " + names);
const ids = recs.map((r) => r.host_id).sort();
assert(JSON.stringify(ids) === JSON.stringify(["host-laptop", "host-living"]), "host_ids " + ids);

const loaded = await api.loadRecord("host-living");
assert(loaded && loaded.host_name === "living-room", "loadRecord must return that computer's hostname");

const hydrated = await api.hydrateRecords();
assert(hydrated.length === 2, "hydrateRecords must surface every paired host");
assert(
  hydrated.every((r) => r.host_name && r.host_id),
  "every paired record must carry host_id and host_name for the phone UX"
);

const bridged = JSON.parse(mem.localStorage.get("pa_rec"));
assert(Array.isArray(bridged) && bridged.length === 2, "bridge must list every paired host");
assert(
  bridged.every((r) => r.host_name && r.host_id && r.secret),
  "bridge records must include hostname and key material"
);

console.log("multi_host_sim: 2 hosts with hostnames ok");
