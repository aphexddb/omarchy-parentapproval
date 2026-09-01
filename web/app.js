const enc = new TextEncoder();

function b64url(bytes) {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function b64urlToBytes(s) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function concatNul(parts) {
  const bins = parts.map((p) => enc.encode(p));
  const len = bins.reduce((n, b) => n + b.length, 0) + bins.length;
  const buf = new Uint8Array(len);
  let o = 0;
  for (const b of bins) {
    buf.set(b, o);
    o += b.length;
    buf[o++] = 0;
  }
  return buf;
}

async function cmdHash(user, service, cwd, cmd) {
  const digest = await crypto.subtle.digest("SHA-256", concatNul([user, service, cwd, cmd]));
  return b64url(new Uint8Array(digest));
}

function canonical(decision, req, hash) {
  return enc.encode(
    `OMARCHY-APPROVE/1\n${decision}\n${req.rid}\n${req.nonce}\n${req.exp}\n${req.host_id}\n${req.user}\n${req.service}\n${hash}\n`
  );
}

function $(id) {
  return document.getElementById(id);
}

function show(id) {
  document.querySelectorAll("section").forEach((s) => s.classList.add("hidden"));
  $(id).classList.remove("hidden");
}

function banner(el, kind, text) {
  el.className = "banner " + kind;
  el.textContent = text;
}

const DB_NAME = "omarchy-qr-sudo";
const STORE = "keys";

function idb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function saveRecord(hostId, rec) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(rec, hostId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function loadRecord(hostId) {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(hostId);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

async function hasEd25519() {
  try {
    const k = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    return !!k;
  } catch {
    return false;
  }
}

async function importPrivate(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "Ed25519" }, true, ["sign"]);
}

function deviceNameGuess() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  return "Parent phone";
}

async function boot() {
  const path = location.pathname.replace(/\/+$/, "");
  if (!(await hasEd25519())) {
    show("unsupported");
    return;
  }
  if (path.startsWith("/pair/")) {
    return bootPair(path.slice("/pair/".length));
  }
  if (path.startsWith("/a/")) {
    return bootApprove(path.slice("/a/".length));
  }
  show("home");
}

async function bootPair(sid) {
  show("pair");
  $("device-name").value = deviceNameGuess();
  $("pair-form").onsubmit = async (e) => {
    e.preventDefault();
    $("pair-btn").disabled = true;
    try {
      const pairKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pairKey.publicKey));
      const jwk = await crypto.subtle.exportKey("jwk", pairKey.privateKey);
      const deviceId = crypto.randomUUID();
      const name = $("device-name").value.trim() || deviceNameGuess();
      const res = await fetch("/pair/" + sid, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          v: 1,
          device_id: deviceId,
          name,
          alg: "Ed25519",
          pubkey: b64url(rawPub),
        }),
      });
      if (!res.ok) throw new Error(await res.text());
      const offered = await res.json();
      $("sas").textContent = (offered.sas || "").split("").join(" ");
      show("pair-wait");
      const wait = await fetch("/pair/" + sid + "/wait");
      if (!wait.ok) throw new Error("Pairing was not confirmed on the laptop.");
      const done = await wait.json();
      await saveRecord(done.host_id, {
        host_id: done.host_id,
        host_name: done.host_name,
        device_id: done.device_id,
        jwk,
      });
      $("paired-host").textContent = done.host_name;
      show("pair-done");
    } catch (err) {
      banner($("pair-err"), "err", err.message || String(err));
      $("pair-btn").disabled = false;
    }
  };
}

async function bootApprove(rid) {
  show("approve");
  const res = await fetch("/a/" + rid, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    show("gone");
    return;
  }
  const req = await res.json();
  $("host").textContent = req.host_name;
  $("who").textContent = req.user + " · " + req.service;
  $("cmd").textContent = req.cmd;
  $("match").textContent = req.match;
  const hash = await cmdHash(req.user, req.service, req.cwd, req.cmd);
  if (hash !== req.cmd_hash) {
    banner($("approve-err"), "err", "Request was tampered with in transit. Do not approve.");
    $("approve-btn").disabled = true;
    $("deny-btn").disabled = true;
    return;
  }
  const rec = await loadRecord(req.host_id);
  if (!rec) {
    $("unpaired").classList.remove("hidden");
    $("approve-btn").disabled = true;
    $("actions").classList.add("hidden");
    return;
  }
  const tick = () => {
    const left = Math.max(0, req.exp - Math.floor(Date.now() / 1000));
    $("countdown").textContent = left + "s left";
    if (left <= 0) {
      show("gone");
    }
  };
  tick();
  const iv = setInterval(tick, 250);

  const decide = async (decision) => {
    $("approve-btn").disabled = true;
    $("deny-btn").disabled = true;
    try {
      const priv = await importPrivate(rec.jwk);
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, priv, canonical(decision, req, hash)));
      const posted = await fetch("/a/" + rid + "/decision", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          v: 1,
          device_id: rec.device_id,
          decision,
          sig: b64url(sig),
        }),
      });
      if (!posted.ok) throw new Error(await posted.text());
      clearInterval(iv);
      $("result-text").textContent = decision === "allow" ? "Approved. The laptop can continue." : "Denied.";
      show("result");
    } catch (err) {
      banner($("approve-err"), "err", err.message || String(err));
      $("approve-btn").disabled = false;
      $("deny-btn").disabled = false;
    }
  };
  $("approve-btn").onclick = () => decide("allow");
  $("deny-btn").onclick = () => decide("deny");
}

boot();
