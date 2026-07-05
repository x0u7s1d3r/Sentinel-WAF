// Appels vers l'API de contrôle du WAF. En prod, nginx relaie /_sentinel vers
// la passerelle (même origine). En dev, Vite fait le proxy (voir vite.config).
const BASE = '/_sentinel'

async function get(path) {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`)
  return r.json()
}

export const api = {
  health: () => get('/health'),
  stats: () => get('/stats'),
  events: () => get('/events'),
  analytics: () => get('/analytics'),
  apps: () => get('/apps'),
  addApp: (app) =>
    fetch(BASE + '/apps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(app),
    }).then((r) => {
      if (!r.ok) return r.text().then((t) => Promise.reject(new Error(t)))
      return r.json()
    }),
  deleteApp: (id) =>
    fetch(`${BASE}/apps?id=${id}`, { method: 'DELETE' }).then((r) => {
      if (!r.ok) throw new Error(`suppression -> HTTP ${r.status}`)
      return r.json()
    }),
}

// Libellés des catégories de détection (ordre d'affichage).
export const CATEGORIES = [
  ['sqli', 'Injection SQL', 'Requêtes piégées vers la base'],
  ['xss', 'Cross-Site Scripting', 'Scripts injectés dans les pages'],
  ['path_traversal', 'Traversée de fichiers', 'Accès aux fichiers du serveur'],
  ['cmd_injection', 'Injection de commande', 'Commandes système détournées'],
  ['ssrf', 'SSRF', 'Requêtes internes forgées'],
  ['nosql', 'Injection NoSQL', 'Requêtes NoSQL piégées'],
  ['scanner', 'Scanners', 'Outils d’attaque automatisés'],
]
