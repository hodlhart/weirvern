/* Network-only service worker: it exists so an installed Weirvern has an app shell and a
 * fetch handler, not so it can serve a stale dashboard. Nothing is cached: a console that
 * shows yesterday's "all healthy" after a pod died is worse than one showing an error.
 */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;
  event.respondWith(fetch(event.request));
});
