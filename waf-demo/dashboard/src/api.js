// Base de l'API de contrôle du WAF. Modifiable si le WAF tourne ailleurs.
export const WAF_API = 'http://127.0.0.1:8080/_waf'

async function j(path, opts) {
  const r = await fetch(WAF_API + path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!r.ok) throw new Error(`${path} -> HTTP ${r.status}`)
  return r.json()
}

export const api = {
  config: () => j('/config'),
  setConfig: (body) => j('/config', { method: 'POST', body: JSON.stringify(body) }),
  stats: () => j('/stats'),
  events: (sinceId = 0, limit = 60) => j(`/events?since_id=${sinceId}&limit=${limit}`),
  attacks: () => j('/attacks'),
  simulate: (attack) => j('/simulate', { method: 'POST', body: JSON.stringify({ attack }) }),
  reset: () => j('/reset', { method: 'POST' }),
  blocklist: (ip, action) =>
    j('/blocklist', { method: 'POST', body: JSON.stringify({ ip, action }) }),
}
