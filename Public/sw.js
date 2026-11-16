// DC SH!FTZ service worker: shows push notifications and opens the app on the right screen when tapped.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

self.addEventListener("push", (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (x) { d = { body: e.data ? e.data.text() : "" }; }
  e.waitUntil(self.registration.showNotification(d.title || "DC SH!FTZ", {
    body: d.body || "", icon: "/icon-192.png", badge: "/icon-192.png",
    tag: d.tag || undefined, renotify: !!d.tag, data: { view: d.view || "open" }
  }));
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const view = (e.notification.data && e.notification.data.view) || "open";
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) {
      if ("focus" in w) { w.postMessage({ type: "open-view", view }); await w.focus(); return; }
    }
    if (self.clients.openWindow) await self.clients.openWindow("/?v=" + encodeURIComponent(view));
  })());
});
