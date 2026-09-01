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

function cmdHash(user, service, cwd, cmd) {
  const digest = Uint8Array.from(sha256.array(concatNul([user, service, cwd, cmd])));
  return b64url(digest);
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

const DB_NAME = "parentapproval";
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
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(rec, hostId);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  const recs = await listRecords().catch(() => [rec]);
  writeBridge(recs.length ? recs : [rec]);
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

async function listRecords() {
  const db = await idb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}

function writeBridge(recs) {
  const slim = (recs || [])
    .filter((r) => r && r.host_id && r.device_id && r.secret)
    .map((r) => ({
      host_id: r.host_id,
      host_name: r.host_name,
      device_id: r.device_id,
      secret: r.secret,
    }));
  const raw = JSON.stringify(slim);
  try {
    localStorage.setItem("pa_rec", raw);
  } catch (e) {
    /* private mode */
  }
  document.cookie = "pa_rec=" + encodeURIComponent(raw) + "; Max-Age=31536000; Path=/; Secure; SameSite=Lax";
}

function readBridge() {
  let raw = null;
  try {
    raw = localStorage.getItem("pa_rec");
  } catch (e) {
    raw = null;
  }
  if (!raw) {
    const m = document.cookie.match(/(?:^|; )pa_rec=([^;]*)/);
    if (m) {
      try {
        raw = decodeURIComponent(m[1]);
      } catch (e) {
        raw = null;
      }
    }
  }
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((r) => r && r.host_id && r.device_id && r.secret) : [];
  } catch (e) {
    return [];
  }
}

async function hydrateRecords() {
  let recs = await listRecords().catch(() => []);
  if (recs.length) {
    writeBridge(recs);
    return recs;
  }
  recs = readBridge();
  for (const r of recs) {
    await saveRecord(r.host_id, r);
  }
  return recs;
}

function hasSign() {
  return typeof nacl !== "undefined" && nacl.sign && typeof sha256 !== "undefined";
}

function newKeyPair() {
  return nacl.sign.keyPair();
}

function signCanonical(secretKey, msg) {
  return nacl.sign.detached(msg, secretKey);
}

function newDeviceId() {
  if (globalThis.crypto && crypto.randomUUID) return crypto.randomUUID();
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function deviceNameGuess() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  if (/Android/.test(ua)) return "Android phone";
  return "Parent phone";
}

function isStandalone() {
  return (
    window.matchMedia("(display-mode: standalone)").matches ||
    window.navigator.standalone === true
  );
}

function isIOS() {
  return (
    /iPhone|iPad|iPod/.test(navigator.userAgent) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
  );
}

function pushNeedsStandalone() {
  return isIOS() && !isStandalone();
}

function settleHomeURL() {
  if (location.pathname !== "/") {
    history.replaceState({}, "", "/");
  }
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}

async function registerSW() {
  if (!("serviceWorker" in navigator)) return null;
  try {
    return await navigator.serviceWorker.register("/sw.js");
  } catch (e) {
    return null;
  }
}

function notificationsGranted() {
  return typeof Notification !== "undefined" && Notification.permission === "granted";
}

function wireNotifyButton(btn, hostId, deviceId, msgEl) {
  if (!btn) return;
  btn.disabled = false;
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      await enableNotifications(hostId, deviceId, msgEl);
    } catch (err) {
      if (msgEl) banner(msgEl, "err", err.message || String(err));
      btn.disabled = false;
    }
  };
}

async function enableNotifications(hostId, deviceId, msgEl) {
  const say = (kind, text) => {
    if (msgEl) banner(msgEl, kind, text);
  };
  if (pushNeedsStandalone()) {
    show("a2hs");
    $("a2hs-done").onclick = () => {
      if (isStandalone()) {
        enableNotifications(hostId, deviceId, msgEl);
      } else {
        show("a2hs");
      }
    };
    return;
  }
  if (!("Notification" in window) || !("PushManager" in window)) {
    say("err", "This browser cannot receive push notifications.");
    return;
  }
  const perm = await Notification.requestPermission();
  if (perm !== "granted") {
    say(
      "err",
      isIOS()
        ? "Notifications were not allowed. On iPhone: Settings → Parent Approval → Notifications."
        : "Notifications were not allowed."
    );
    return;
  }
  if (!hostId || !deviceId) {
    say("ok", "Notifications allowed. Scan a pairing QR from this Home Screen app so it can buzz.");
    return;
  }
  const vapidRes = await fetch("/vapid-public");
  if (!vapidRes.ok) throw new Error("Could not load VAPID key");
  const vapid = await vapidRes.json();
  const reg = (await registerSW()) || (await navigator.serviceWorker.ready);
  if (!reg) throw new Error("Service worker failed to register");
  await navigator.serviceWorker.ready;
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapid.publicKey),
  });
  const posted = await fetch("/push/subscribe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      device_id: deviceId,
      host_id: hostId,
      subscription: sub.toJSON(),
    }),
  });
  if (!posted.ok) throw new Error(await posted.text());
  say("ok", "Notifications on. Next time the kid needs sudo, this phone will buzz.");
}

function showNotifySetup(recs) {
  const rec = recs && recs[0];
  show("notify-setup");
  if (rec) {
    $("notify-setup-host").textContent = rec.host_name || "this laptop";
    $("notify-setup-paired").classList.remove("hidden");
    $("notify-setup-lead").textContent =
      "iPhone will not buzz until you tap Allow in this Home Screen app. Safari pairing does not copy over.";
  } else {
    $("notify-setup-paired").classList.add("hidden");
    $("notify-setup-lead").textContent =
      "iPhone Home Screen apps have their own storage. Pairing in Safari does not count. Tap Allow, then scan a pairing QR from this app.";
  }
  wireNotifyButton($("notify-setup-btn"), rec && rec.host_id, rec && rec.device_id, $("notify-setup-msg"));
}

function showGone() {
  show("gone");
  const btn = $("gone-home");
  if (!btn) return;
  btn.onclick = async () => {
    settleHomeURL();
    await resumePaired();
  };
}

async function resumePaired() {
  settleHomeURL();
  const recs = await hydrateRecords();
  if (isStandalone() && !notificationsGranted()) {
    showNotifySetup(recs);
    return;
  }
  if (pushNeedsStandalone()) {
    show("a2hs");
    $("a2hs-done").onclick = () => {
      if (isStandalone()) {
        showNotifySetup(recs);
      } else {
        show("a2hs");
      }
    };
    return;
  }
  show("home");
  if (!recs.length) return;
  $("home-paired").classList.remove("hidden");
  $("home-hosts").textContent = recs.map((r) => r.host_name || "laptop").join(", ");
  const rec = recs[0];
  wireNotifyButton($("home-notify-btn"), rec.host_id, rec.device_id, $("home-paired"));
  wireNotifyButton($("notify-btn"), rec.host_id, rec.device_id, $("notify-msg"));
  if (notificationsGranted()) {
    try {
      await enableNotifications(rec.host_id, rec.device_id, $("home-paired"));
    } catch (e) {
      /* subscribe can be retried from the button */
    }
  }
}

async function boot() {
  registerSW();
  const path = location.pathname.replace(/\/+$/, "");
  if (!hasSign()) {
    show("unsupported");
    return;
  }
  if (path.startsWith("/p/")) {
    const token = path.slice("/p/".length);
    try {
      const meta = await fetch("/p/" + token + "/meta");
      if (!meta.ok) {
        return resumePaired();
      }
      const m = await meta.json();
      if (m.kind === "pair" && m.sid) {
        const recs = await hydrateRecords();
        if (recs.length) return resumePaired();
        return bootPair(m.sid);
      }
      if (m.kind === "ask" && m.rid) return bootApprove(m.rid);
      return resumePaired();
    } catch (e) {
      return resumePaired();
    }
  }
  if (path.startsWith("/pair/")) {
    return bootPair(path.slice("/pair/".length));
  }
  if (path.startsWith("/a/")) {
    return bootApprove(path.slice("/a/".length));
  }
  await resumePaired();
}

async function bootPair(sid) {
  show("pair");
  $("device-name").value = deviceNameGuess();
  $("pair-form").onsubmit = async (e) => {
    e.preventDefault();
    $("pair-btn").disabled = true;
    try {
      const pairKey = newKeyPair();
      const rawPub = pairKey.publicKey;
      const secretB64 = b64url(pairKey.secretKey);
      const deviceId = newDeviceId();
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
        secret: secretB64,
      });
      settleHomeURL();
      $("paired-host").textContent = done.host_name;
      if (isStandalone()) {
        showNotifySetup([
          {
            host_id: done.host_id,
            host_name: done.host_name,
            device_id: done.device_id,
          },
        ]);
      } else if (pushNeedsStandalone()) {
        show("a2hs");
        $("a2hs-done").onclick = () => {
          if (isStandalone()) {
            showNotifySetup([
              {
                host_id: done.host_id,
                host_name: done.host_name,
                device_id: done.device_id,
              },
            ]);
          } else {
            show("a2hs");
          }
        };
      } else {
        show("pair-done");
        wireNotifyButton($("notify-btn"), done.host_id, done.device_id, $("notify-msg"));
      }
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
    showGone();
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
  await hydrateRecords();
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
      showGone();
    }
  };
  tick();
  const iv = setInterval(tick, 250);

  const decide = async (decision) => {
    $("approve-btn").disabled = true;
    $("deny-btn").disabled = true;
    try {
      if (!rec.secret) throw new Error("This phone's key is from an older build. Pair again from the laptop.");
      const sig = signCanonical(b64urlToBytes(rec.secret), canonical(decision, req, hash));
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
