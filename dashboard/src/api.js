// Appels vers l'API de contrôle du WAF. En prod, nginx relaie /_sentinel vers
// la passerelle (même origine). En dev, Vite fait le proxy (voir vite.config).
const BASE = '/_sentinel'

async function get(path) {
  const r = await fetch(BASE + path)
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`)
  return r.json()
}

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!r.ok) return r.text().then((t) => Promise.reject(new Error(t)))
  return r.json()
}

export const api = {
  health: () => get('/health'),
  stats: (app) => get('/stats' + (app ? `?app=${encodeURIComponent(app)}` : '')),
  events: (app) => get('/events' + (app ? `?app=${encodeURIComponent(app)}` : '')),
  analytics: (app) => get('/analytics' + (app ? `?app=${encodeURIComponent(app)}` : '')),
  apps: () => get('/apps'),
  settings: () => get('/settings'),
  setSettings: (body) => post('/settings', body),
  slackTest: () => post('/slack/test', {}),
  blocklist: (ip, action) => post('/blocklist', { ip, action }),
  addApp: (app) => post('/apps', app),
  updateApp: (id, mode, threshold) =>
    fetch(BASE + '/apps', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, mode, threshold }),
    }).then((r) => {
      if (!r.ok) return r.text().then((t) => Promise.reject(new Error(t)))
      return r.json()
    }),
  updateApp: (id, mode, threshold) =>
    fetch(`${BASE}/apps`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, mode, threshold }),
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

// Libellés + descriptions des catégories de détection (ordre d'affichage).
export const CATEGORIES = [
  ['sqli', 'Injection SQL', 'Requêtes piégées vers la base de données'],
  ['xss', 'Cross-Site Scripting', 'Scripts malveillants injectés dans les pages'],
  ['path_traversal', 'Traversée de fichiers', 'Accès non autorisé aux fichiers du serveur'],
  ['cmd_injection', 'Injection de commande', 'Commandes système détournées'],
  ['ssrf', 'SSRF', 'Requêtes internes forgées par l’attaquant'],
  ['nosql', 'Injection NoSQL', 'Requêtes NoSQL piégées'],
  ['scanner', 'Scanners', 'Outils d’attaque automatisés (sqlmap, nikto…)'],
  ['sensitive_path', 'Chemins sensibles', 'Accès à /.env, /admin, /.git, sauvegardes…'],
  ['brute_force', 'Force brute', 'Tentatives d’authentification répétées'],
]
