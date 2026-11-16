/* Network-only service worker: it exists so an installed Weirvern has a stable PWA shell,
 * not so it can serve a stale dashboard. Nothing is cached.
 *
 * NO FETCH HANDLER, DELIBERATELY. Safari turns a rejected `respondWith(fetch(...))` into a
 * page-load failure ("FetchEvent.respondWith received an error: TypeError: Load failed") instead
 * of letting the navigation reach the network. A network-only worker has nothing useful to do
 * with a fetch event, so it must not intercept one.
 */
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
