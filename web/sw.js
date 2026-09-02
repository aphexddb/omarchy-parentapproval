self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.mode === "navigate" || url.pathname === "/" || url.pathname === "/index.html" || url.pathname === "/app.js" || url.pathname === "/app.css" || url.pathname === "/sw.js") {
    event.respondWith(fetch(event.request, { cache: "no-store" }));
  }
});

self.addEventListener("push", (event) => {
  let data = { title: "Parent Approval", body: "A kid needs sudo", url: "/" };
  if (event.data) {
    try {
      data = Object.assign(data, event.data.json());
    } catch (e) {
      const text = event.data.text();
      if (text) data.body = text;
    }
  }
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      let visible = false;
      const payload = { type: "ask", url: data.url || "/", title: data.title, body: data.body };
      for (const client of windows) {
        try {
          client.postMessage(payload);
        } catch (e) {
          /* ignore */
        }
        if (client.visibilityState === "visible" || client.focused) visible = true;
      }
      if (visible) return;
      return self.registration.showNotification(data.title || "Parent Approval", {
        body: data.body || "A kid needs sudo",
        data: { url: data.url || "/" },
      });
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => {
      for (const client of windows) {
        if (client.url && "focus" in client) {
          client.focus();
          if ("navigate" in client) return client.navigate(url);
          return;
        }
      }
      return self.clients.openWindow(url);
    })
  );
});
