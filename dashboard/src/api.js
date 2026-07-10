// Client de l'API de contrôle du WAF. Gère l'authentification : le jeton est
// conservé dans le navigateur et envoyé dans l'en-tête Authorization. Une
// réponse 401 lève une erreur marquée (status: 401) pour déclencher l'écran
// de connexion côté application.
const BASE = '/_sentinel'
const TOKEN_KEY = 'sentinel_token'

function getToken() { try { return localStorage.getItem(TOKEN_KEY) || '' } catch { return '' } }
function setToken(t) { try { t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ } }

function headers(extra) {
  const h = { ...(extra || {}) }
  const t = getToken()
  if (t) h['Authorization'] = 'Bearer ' + t
  return h
}

function unauthorized() { const e = new Error('non autorisé'); e.status = 401; return e }

async function get(path) {
  const r = await fetch(BASE + path, { headers: headers() })
  if (r.status === 401) throw unauthorized()
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`)
  return r.json()
}

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST', headers: headers({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  })
  if (r.status === 401) throw unauthorized()
  if (!r.ok) return r.text().then((t) => Promise.reject(new Error(t)))
  return r.json()
}

export const api = {
  health: () => get('/health'),
  stats: () => get('/stats'),
  events: () => get('/events'),
  analytics: (range) => get('/analytics' + (range ? `?range=${encodeURIComponent(range)}` : '')),
  incidents: () => get('/incidents'),
  timeline: (ip) => get('/timeline?ip=' + encodeURIComponent(ip)),
  apps: () => get('/apps'),
  settings: () => get('/settings'),
  setSettings: (body) => post('/settings', body),
  slackTest: () => post('/slack/test', {}),
  discordTest: () => post('/discord/test', {}),
  llmTest: () => post('/llm/test', {}),
  blocklist: (ip, action) => post('/blocklist', { ip, action }),
  addApp: (app) => post('/apps', app),
  updateApp: (id, fields) =>
    fetch(BASE + '/apps', {
      method: 'PUT', headers: headers({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ id, ...fields }),
    }).then((r) => {
      if (r.status === 401) throw unauthorized()
      if (!r.ok) return r.text().then((t) => Promise.reject(new Error(t)))
      return r.json()
    }),
  deleteApp: (id) =>
    fetch(`${BASE}/apps?id=${id}`, { method: 'DELETE', headers: headers() }).then((r) => {
      if (r.status === 401) throw unauthorized()
      if (!r.ok) throw new Error(`suppression -> HTTP ${r.status}`)
      return r.json()
    }),

  // --- Authentification ---
  setup: async (password) => {
    const r = await fetch(BASE + '/setup', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    const data = await r.json().catch(() => ({}))
    if (!r.ok) { const e = new Error(data.error || 'échec de création'); e.status = r.status; throw e }
    if (data.token) setToken(data.token)
    return data
  },
  login: async (password) => {
    const r = await fetch(BASE + '/login', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    })
    const data = await r.json().catch(() => ({}))
    if (!r.ok) { const e = new Error(data.error || 'échec de connexion'); e.status = r.status; throw e }
    if (data.token) setToken(data.token)
    return data
  },
  changePassword: (oldPw, newPw) => post('/password', { old: oldPw, new: newPw }),
  logout: () => setToken(''),
  hasToken: () => !!getToken(),
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
