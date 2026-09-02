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

function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    document.body.appendChild(ta);
    ta.select();
    try {
      if (!document.execCommand("copy")) reject(new Error("copy failed"));
      else resolve();
    } catch (err) {
      reject(err);
    } finally {
      ta.remove();
    }
  });
}

document.addEventListener("click", async (e) => {
  const btn = e.target.closest(".copy-btn");
  if (!btn) return;
  const box = btn.closest("[data-copy]");
  if (!box) return;
  e.preventDefault();
  const text = box.getAttribute("data-copy");
  if (!text) return;
  try {
    await copyText(text);
    box.classList.add("copied");
    btn.setAttribute("aria-label", "Copied");
    setTimeout(() => {
      box.classList.remove("copied");
      btn.setAttribute("aria-label", "Copy command");
    }, 1500);
  } catch (err) {
    /* ignore */
  }
});

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
    window.matchMedia("(display-mode: fullscreen)").matches ||
    window.matchMedia("(display-mode: minimal-ui)").matches ||
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

function pairTokenFromPath() {
  const path = location.pathname.replace(/\/+$/, "");
  if (path.startsWith("/p/")) return path.slice("/p/".length);
  return "";
}

async function fetchHandoff(token) {
  if (!token) return null;
  try {
    const res = await fetch("/p/" + token + "/handoff");
    if (!res.ok) return null;
    const rec = await res.json();
    if (!rec || !rec.host_id || !rec.device_id || !rec.secret) return null;
    return rec;
  } catch (e) {
    return null;
  }
}

async function postHandoff(rec) {
  const token = pairTokenFromPath();
  if (!token || !rec || !rec.host_id || !rec.device_id || !rec.secret) return;
  try {
    await fetch("/p/" + token + "/handoff", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        host_id: rec.host_id,
        host_name: rec.host_name,
        device_id: rec.device_id,
        secret: rec.secret,
      }),
    });
  } catch (e) {
    /* laptop wait still polls subscribe */
  }
}

async function enableNotifications(hostId, deviceId, msgEl) {
  const say = (kind, text) => {
    if (msgEl) banner(msgEl, kind, text);
  };
  if (pushNeedsStandalone()) {
    wireA2HS([]);
    return;
  }
  if (!("Notification" in window) || !("PushManager" in window)) {
    say("err", "This browser cannot receive push notifications.");
    return;
  }
  if (!hostId || !deviceId) {
    const rec = await fetchHandoff(pairTokenFromPath());
    if (rec) {
      hostId = rec.host_id;
      deviceId = rec.device_id;
      await saveRecord(rec.host_id, rec);
    }
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
      device_id: deviceId || newDeviceId(),
      host_id: hostId || "",
      subscription: sub.toJSON(),
    }),
  });
  if (!posted.ok) throw new Error(await posted.text());
  say("ok", "Notifications on. Next time the kid needs sudo, this phone will buzz.");
  settleHomeURL();
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

let idleTimer = 0;
let watchAbort = null;
let lastAskRid = "";
let approveTimer = 0;

function clearIdleTimer() {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = 0;
  }
}

function showIdleSoon(ms) {
  clearIdleTimer();
  idleTimer = setTimeout(() => {
    idleTimer = 0;
    resumePaired();
  }, ms);
}

function showGone() {
  settleHomeURL();
  show("gone");
  const btn = $("gone-home");
  if (!btn) return;
  btn.onclick = async () => {
    await resumePaired();
  };
}

function wireA2HS(recs) {
  show("a2hs");
  $("a2hs-done").onclick = () => {
    if (isStandalone()) {
      showNotifySetup(recs || []);
      return;
    }
    banner($("a2hs-msg"), "warn", "Still Safari. Leave it and open the Parent Approval icon on the Home Screen.");
  };
}

function wireHomeNotify(rec) {
  const btn = $("home-notify-btn");
  const row = $("home-notify-row");
  const hint = $("home-paired-hint");
  const granted = notificationsGranted();
  if (hint) {
    hint.textContent = granted
      ? "If this page is open, the request shows here right away. You'll also get a buzz."
      : "Enable notifications so this phone can buzz when the page is closed.";
  }
  if (row) row.classList.toggle("hidden", granted);
  if (!btn || granted) return;
  btn.disabled = false;
  btn.classList.remove("hidden");
  btn.onclick = async () => {
    btn.disabled = true;
    try {
      await enableNotifications(rec.host_id, rec.device_id, $("home-notify-msg"));
      wireHomeNotify(rec);
    } catch (err) {
      banner($("home-notify-msg"), "err", err.message || String(err));
      btn.disabled = false;
    }
  };
}

function showIdle(recs) {
  show("home");
  const msg = $("home-notify-msg");
  if (msg) {
    msg.textContent = "";
    msg.className = "";
  }
  const paired = recs && recs.length > 0;
  $("home-unpaired").classList.toggle("hidden", paired);
  $("home-paired").classList.toggle("hidden", !paired);
  if (!paired) return;
  $("home-hosts").textContent = recs.map((r) => r.host_name || "laptop").join(", ");
  const rec = recs[0];
  wireHomeNotify(rec);
  if (notificationsGranted()) {
    enableNotifications(rec.host_id, rec.device_id, null).catch(() => {});
  }
  startWatch(recs);
}

function showDecision(decision) {
  const allowed = decision === "allow";
  $("result-title").textContent = allowed ? "Approved" : "Denied";
  $("result-text").textContent = allowed ? "The person can continue." : "The request was denied.";
  show("result");
  settleHomeURL();
  const el = $("result");
  el.onclick = () => {
    clearIdleTimer();
    el.onclick = null;
    resumePaired();
  };
  showIdleSoon(2200);
}

function openSection() {
  return document.querySelector("section:not(.hidden)");
}

function maybeResumeIdle() {
  const open = openSection();
  if (!open) return;
  if (open.id === "result" || open.id === "gone") {
    clearIdleTimer();
    resumePaired();
    return;
  }
  if (isStandalone() && !notificationsGranted()) {
    if (open.id === "home" || open.id === "a2hs" || open.id === "pair-done") {
      resumePaired();
    }
  }
}

async function resumePaired() {
  settleHomeURL();
  const recs = await hydrateRecords();
  if (recs && recs.length) startWatch(recs);
  if (isStandalone() && !notificationsGranted()) {
    showNotifySetup(recs);
    return;
  }
  if (pushNeedsStandalone()) {
    wireA2HS(recs);
    return;
  }
  showIdle(recs);
}

async function boot() {
  clearIdleTimer();
  registerSW();
  listenLiveAsk();
  const path = location.pathname.replace(/\/+$/, "");
  if (!hasSign()) {
    show("unsupported");
    return;
  }
  if (path.startsWith("/p/")) {
    const token = path.slice("/p/".length);
    const handed = await fetchHandoff(token);
    if (handed) {
      await saveRecord(handed.host_id, handed);
      return finishPair("", handed);
    }
    try {
      const meta = await fetch("/p/" + token + "/meta");
      if (!meta.ok) {
        return resumePaired();
      }
      const m = await meta.json();
      if (m.kind === "pair" && m.sid) {
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

async function offerPair(sid, deviceId, name, pubkeyB64) {
  const res = await fetch("/pair/" + sid, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      v: 1,
      device_id: deviceId,
      name,
      alg: "Ed25519",
      pubkey: pubkeyB64,
    }),
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function waitForPair(sid, deviceId) {
  const confirmBtn = $("pair-confirm-btn");
  const abortBtn = $("pair-abort-btn");
  const errEl = $("pair-wait-err");
  if (confirmBtn) {
    confirmBtn.disabled = false;
    confirmBtn.onclick = async () => {
      confirmBtn.disabled = true;
      if (abortBtn) abortBtn.disabled = true;
      try {
        const res = await fetch("/pair/" + sid + "/confirm", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_id: deviceId }),
        });
        if (!res.ok) throw new Error(await res.text());
      } catch (err) {
        if (errEl) banner(errEl, "err", err.message || String(err));
        confirmBtn.disabled = false;
        if (abortBtn) abortBtn.disabled = false;
      }
    };
  }
  if (abortBtn) {
    abortBtn.disabled = false;
    abortBtn.onclick = async () => {
      abortBtn.disabled = true;
      if (confirmBtn) confirmBtn.disabled = true;
      try {
        await fetch("/pair/" + sid + "/abort", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ device_id: deviceId }),
        });
      } catch (e) {
        /* wait will fail */
      }
    };
  }
  const wait = await fetch("/pair/" + sid + "/wait");
  if (!wait.ok) throw new Error("Pairing was not confirmed.");
  return wait.json();
}

async function finishPair(sid, rec) {
  await postHandoff(rec);
  startWatch([rec]);
  $("paired-host").textContent = rec.host_name || "this laptop";
  if (isStandalone()) {
    showNotifySetup([rec]);
  } else if (pushNeedsStandalone()) {
    wireA2HS([rec]);
  } else {
    show("pair-done");
    wireNotifyButton($("notify-btn"), rec.host_id, rec.device_id, $("notify-msg"));
  }
}

async function bootPair(sid) {
  show("pair");
  $("device-name").value = deviceNameGuess();
  const existing = (await hydrateRecords().catch(() => []))[0];
  if (existing && existing.secret) {
    try {
      const kp = nacl.sign.keyPair.fromSecretKey(b64urlToBytes(existing.secret));
      const offered = await offerPair(sid, existing.device_id, deviceNameGuess(), b64url(kp.publicKey));
      $("sas").textContent = (offered.sas || "").split("").join(" ");
      show("pair-wait");
      const done = await waitForPair(sid, existing.device_id);
      existing.host_id = done.host_id;
      existing.host_name = done.host_name;
      existing.device_id = done.device_id;
      await saveRecord(done.host_id, existing);
      return finishPair(sid, existing);
    } catch (e) {
      /* fall through to the pair form */
    }
  }
  $("pair-form").onsubmit = async (e) => {
    e.preventDefault();
    $("pair-btn").disabled = true;
    try {
      const pairKey = newKeyPair();
      const rawPub = pairKey.publicKey;
      const secretB64 = b64url(pairKey.secretKey);
      const deviceId = newDeviceId();
      const name = $("device-name").value.trim() || deviceNameGuess();
      const offered = await offerPair(sid, deviceId, name, b64url(rawPub));
      $("sas").textContent = (offered.sas || "").split("").join(" ");
      show("pair-wait");
      const done = await waitForPair(sid, deviceId);
      const rec = {
        host_id: done.host_id,
        host_name: done.host_name,
        device_id: done.device_id,
        secret: secretB64,
      };
      await saveRecord(done.host_id, rec);
      return finishPair(sid, rec);
    } catch (err) {
      banner($("pair-err"), "err", err.message || String(err));
      $("pair-btn").disabled = false;
    }
  };
}

function stopWatch() {
  if (!watchAbort) return;
  watchAbort.abort();
  watchAbort = null;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(resolve, ms);
    if (!signal) return;
    const onAbort = () => {
      clearTimeout(t);
      reject(new DOMException("aborted", "AbortError"));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function canonicalWatch(hostId, deviceId, exp) {
  return enc.encode(`OMARCHY-WATCH/1\n${hostId}\n${deviceId}\n${exp}\n`);
}

function watchQuery(rec) {
  const exp = Math.floor(Date.now() / 1000) + 60;
  const sig = b64url(signCanonical(b64urlToBytes(rec.secret), canonicalWatch(rec.host_id, rec.device_id, exp)));
  return (
    "host_id=" +
    encodeURIComponent(rec.host_id) +
    "&device_id=" +
    encodeURIComponent(rec.device_id) +
    "&exp=" +
    exp +
    "&sig=" +
    encodeURIComponent(sig)
  );
}

function startWatch(recs) {
  stopWatch();
  if (!recs || !recs.length) return;
  const paired = recs.filter((r) => r && r.host_id && r.device_id && r.secret);
  if (!paired.length) return;
  const ac = new AbortController();
  watchAbort = ac;
  for (const rec of paired) {
    watchOne(rec, ac);
  }
}

async function watchOne(rec, ac) {
  while (!ac.signal.aborted) {
    try {
      const res = await fetch("/v1/watch?" + watchQuery(rec), {
        signal: ac.signal,
        headers: { Accept: "application/json" },
        cache: "no-store",
      });
      if (ac.signal.aborted) return;
      if (!res.ok) {
        await sleep(1500, ac.signal);
        continue;
      }
      const ev = await res.json();
      if (ev && ev.kind === "ask") {
        await handleLiveAsk(ev);
        if (!ac.signal.aborted) await sleep(1500, ac.signal);
      }
    } catch (err) {
      if (ac.signal.aborted) return;
      try {
        await sleep(1500, ac.signal);
      } catch (e) {
        return;
      }
    }
  }
}

function ridFromAskURL(url) {
  if (!url) return "";
  try {
    const u = new URL(url, location.origin);
    const path = u.pathname.replace(/\/+$/, "");
    if (path.startsWith("/a/")) return path.slice("/a/".length);
    return "";
  } catch (e) {
    return "";
  }
}

async function ridFromWatchEvent(ev) {
  if (!ev) return "";
  if (ev.rid) return ev.rid;
  const direct = ridFromAskURL(ev.url);
  if (direct) return direct;
  if (!ev.url) return "";
  try {
    const u = new URL(ev.url, location.origin);
    const path = u.pathname.replace(/\/+$/, "");
    if (!path.startsWith("/p/")) return "";
    const token = path.slice("/p/".length);
    if (!token) return "";
    const meta = await fetch("/p/" + token + "/meta", { headers: { Accept: "application/json" } });
    if (!meta.ok) return "";
    const m = await meta.json();
    return m.rid || "";
  } catch (e) {
    return "";
  }
}

function canInterruptForAsk() {
  const open = openSection();
  if (!open) return true;
  if (open.id === "pair" || open.id === "pair-wait" || open.id === "a2hs" || open.id === "unsupported") {
    return false;
  }
  return true;
}

async function handleLiveAsk(ev) {
  const rid = await ridFromWatchEvent(ev);
  if (!rid || rid === lastAskRid) return;
  if (!canInterruptForAsk()) return;
  lastAskRid = rid;
  history.replaceState({}, "", "/a/" + rid);
  await bootApprove(rid);
}

function listenLiveAsk() {
  if (!("serviceWorker" in navigator) || listenLiveAsk.wired) return;
  listenLiveAsk.wired = true;
  navigator.serviceWorker.addEventListener("message", (e) => {
    const data = (e && e.data) || {};
    if (data.type === "ask" || data.kind === "ask") {
      handleLiveAsk({ kind: "ask", url: data.url, rid: data.rid });
    }
  });
}

async function bootApprove(rid) {
  clearIdleTimer();
  if (approveTimer) {
    clearInterval(approveTimer);
    approveTimer = 0;
  }
  lastAskRid = rid;
  const recs = await hydrateRecords().catch(() => []);
  if (recs && recs.length) startWatch(recs);
  show("approve");
  $("approve-btn").disabled = false;
  $("deny-btn").disabled = false;
  $("actions").classList.remove("hidden");
  $("unpaired").classList.add("hidden");
  $("approve-err").textContent = "";
  $("approve-err").className = "";
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
      if (approveTimer) clearInterval(approveTimer);
      approveTimer = 0;
      showGone();
      return true;
    }
    return false;
  };
  if (tick()) return;
  approveTimer = setInterval(tick, 250);

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
      if (approveTimer) clearInterval(approveTimer);
      approveTimer = 0;
      showDecision(decision);
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
window.addEventListener("pageshow", (e) => {
  if (e.persisted) boot();
});
window.addEventListener("focus", maybeResumeIdle);
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") return;
  maybeResumeIdle();
  hydrateRecords()
    .then((recs) => {
      if (recs && recs.length) startWatch(recs);
    })
    .catch(() => {});
});
