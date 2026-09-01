self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
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
    self.registration.showNotification(data.title || "Parent Approval", {
      body: data.body || "A kid needs sudo",
      data: { url: data.url || "/" },
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
