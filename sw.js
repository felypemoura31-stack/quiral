const CACHE_NAME = 'quiral-shell-v1';
const SHELL_FILES = [
  './index.html',
  './manifest.json',
  './icon.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Nunca cachear dados do Firebase — isso precisa ser sempre em tempo real.
  if (url.hostname.includes('firebaseio.com')) return;

  // Só cuida de arquivos do próprio site (mesma origem). CDNs externos (Tailwind,
  // Google Fonts) seguem direto pra rede normalmente.
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const fetchPromise = fetch(event.request).then((resposta) => {
        if (resposta && resposta.ok) {
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, resposta.clone()));
        }
        return resposta;
      }).catch(() => cached);
      return cached || fetchPromise;
    })
  );
});
