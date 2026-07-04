import { useEffect, useMemo, useRef, useState } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, ResponsiveContainer, Cell, Tooltip,
} from 'recharts'
import { api } from './api.js'

const CAT_COLORS = {
  sqli: '#ff8a8a',
  xss: '#ffcf6e',
  path_traversal: '#a99bff',
  cmd_injection: '#ff5d5d',
  scanner: '#5fe6d3',
}

const VERDICT_LABEL = { blocked: 'BLOQUÉE', detected: 'DÉTECTÉE', allowed: 'AUTORISÉE' }

function fmtTime(ts) {
  const d = new Date(ts * 1000)
  return d.toLocaleTimeString('fr-FR', { hour12: false })
}

export default function App() {
  const [connected, setConnected] = useState(false)
  const [config, setConfig] = useState(null)
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [attacks, setAttacks] = useState([])
  const [sim, setSim] = useState(null)
  const [firing, setFiring] = useState(null)
  const [ipInput, setIpInput] = useState('')
  const lastId = useRef(0)

  // Chargement initial
  useEffect(() => {
    ;(async () => {
      try {
        const [c, a] = await Promise.all([api.config(), api.attacks()])
        setConfig(c)
        setAttacks(a.attacks)
        setConnected(true)
      } catch {
        setConnected(false)
      }
    })()
  }, [])

  // Polling temps réel (stats + nouveaux événements)
  useEffect(() => {
    let alive = true
    async function tick() {
      try {
        const s = await api.stats()
        if (!alive) return
        setStats(s)
        setConnected(true)
        const { events: fresh } = await api.events(lastId.current, 60)
        if (!alive) return
        if (fresh.length) {
          lastId.current = Math.max(...fresh.map((e) => e.id))
          setEvents((prev) => [...fresh, ...prev].slice(0, 120))
        }
      } catch {
        if (alive) setConnected(false)
      }
    }
    tick()
    const id = setInterval(tick, 1500)
    return () => { alive = false; clearInterval(id) }
  }, [])

  async function updateMode(mode) {
    const c = await api.setConfig({ mode })
    setConfig(c)
  }
  async function updateThreshold(v) {
    const c = await api.setConfig({ threshold: v })
    setConfig(c)
  }
  async function toggleCategory(cat) {
    const set = new Set(config.enabled_categories)
    set.has(cat) ? set.delete(cat) : set.add(cat)
    const c = await api.setConfig({ enabled_categories: [...set] })
    setConfig(c)
  }
  async function fire(id) {
    setFiring(id)
    try {
      const res = await api.simulate(id)
      setSim(res)
    } finally {
      setFiring(null)
    }
  }
  async function addIp() {
    if (!ipInput.trim()) return
    const { blocklist } = await api.blocklist(ipInput.trim(), 'add')
    setConfig((c) => ({ ...c, blocklist }))
    setIpInput('')
  }
  async function removeIp(ip) {
    const { blocklist } = await api.blocklist(ip, 'remove')
    setConfig((c) => ({ ...c, blocklist }))
  }
  async function resetAll() {
    await api.reset()
    setEvents([])
    lastId.current = 0
    setSim(null)
  }

  const chartData = useMemo(() => {
    if (!stats) return []
    return Object.entries(stats.by_category).map(([k, v]) => ({
      name: config?.all_categories?.[k] || k,
      key: k,
      value: v,
    }))
  }, [stats, config])

  if (!config) {
    return (
      <div className="app">
        <div className="empty" style={{ marginTop: 80 }}>
          {connected === false
            ? "Connexion au WAF impossible. Vérifiez qu'il tourne sur http://127.0.0.1:8080"
            : 'Connexion à la console…'}
        </div>
      </div>
    )
  }

  return (
    <div className="app">
      {/* -------------------------------------------------- Barre supérieure */}
      <div className="topbar">
        <div className="brand">
          <div className="logo">WAF<b>·</b>Console</div>
          <div className="sub">Supervision temps réel</div>
        </div>
        <div className="spacer" />
        <div className="threshold">
          seuil de menace
          <input
            type="number" min="1" value={config.threshold}
            onChange={(e) => updateThreshold(Number(e.target.value))}
          />
        </div>
        <div className="mode-switch">
          <span className="mode-label">mode</span>
          <div className="seg">
            <button
              className={`block ${config.mode === 'block' ? 'active' : ''}`}
              onClick={() => updateMode('block')}
            >Blocage</button>
            <button
              className={`detect ${config.mode === 'detect' ? 'active' : ''}`}
              onClick={() => updateMode('detect')}
            >Détection</button>
          </div>
        </div>
        <div className="conn">
          <span className={`dot ${connected ? 'live' : ''}`} />
          {connected ? 'en ligne' : 'hors ligne'}
        </div>
      </div>

      {/* -------------------------------------------------- Cartes de stats */}
      <div className="stats">
        <Stat cls="total" k="Requêtes totales" v={stats?.total ?? 0} />
        <Stat cls="blocked" k="Bloquées" v={stats?.blocked ?? 0} />
        <Stat cls="detected" k="Détectées" v={stats?.detected ?? 0} />
        <Stat cls="allowed" k="Autorisées" v={stats?.allowed ?? 0} />
      </div>

      <div className="grid">
        {/* ------------------------------------------- Colonne gauche */}
        <div>
          <div className="card">
            <div className="card-h">
              <h3>Console d'attaque</h3>
              <span className="hint">un clic = une attaque</span>
            </div>
            <div className="card-b">
              <div className="atk-grid">
                {attacks.map((a) => (
                  <button
                    key={a.id}
                    className={`atk ${a.id === 'legit' ? 'legit' : ''}`}
                    disabled={firing === a.id}
                    onClick={() => fire(a.id)}
                  >
                    <div className="cat">{a.category || 'trafic normal'}</div>
                    <div className="lbl">{a.label}</div>
                  </button>
                ))}
              </div>

              {sim && (
                <div className={`sim-result ${sim.verdict}`}>
                  <div className="verdict">
                    {sim.verdict === 'blocked' && '⛔'}
                    {sim.verdict === 'detected' && '⚠️'}
                    {sim.verdict === 'allowed' && '✅'}
                    {VERDICT_LABEL[sim.verdict]} · score {sim.score}
                  </div>
                  <div className="explain">{sim.attack.explain}</div>
                  {sim.matched.length > 0 && (
                    <div className="rules">
                      {sim.matched.map((m) => (
                        <span key={m.id} className={`tag ${m.category}`}>{m.id}</span>
                      ))}
                    </div>
                  )}
                  {sim.backend_response && (
                    <div className="backend">
                      backend HTTP {sim.backend_response.status} —{' '}
                      {sim.verdict === 'allowed'
                        ? 'requête normale servie'
                        : "L'ATTAQUE A ATTEINT LE BACKEND :"}
                      {'\n'}
                      {sim.backend_response.snippet}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          <div className="card">
            <div className="card-h"><h3>Règles actives</h3>
              <span className="hint">{config.enabled_categories.length}/{Object.keys(config.all_categories).length}</span>
            </div>
            <div className="card-b" style={{ paddingTop: 4, paddingBottom: 4 }}>
              {Object.entries(config.all_categories).map(([cat, label]) => (
                <div className="rule-row" key={cat}>
                  <div className="name">{label}<small>{cat}</small></div>
                  <button
                    className={`toggle ${config.enabled_categories.includes(cat) ? 'on' : ''}`}
                    onClick={() => toggleCategory(cat)}
                    aria-label={`Basculer ${label}`}
                  />
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-h"><h3>Blocklist IP</h3></div>
            <div className="card-b">
              <div className="bl-input">
                <input
                  placeholder="192.0.2.10"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && addIp()}
                />
                <button className="btn accent" onClick={addIp}>Bloquer</button>
              </div>
              <div className="bl-list">
                {config.blocklist.length === 0 && <span className="hint">aucune IP bloquée</span>}
                {config.blocklist.map((ip) => (
                  <span className="chip" key={ip}>{ip}
                    <button onClick={() => removeIp(ip)} aria-label={`Débloquer ${ip}`}>×</button>
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ------------------------------------------- Colonne droite */}
        <div>
          <div className="card feed">
            <div className="card-h">
              <h3>Flux d'événements en direct</h3>
              <div className="row-actions">
                <span className="hint" style={{ alignSelf: 'center' }}>
                  {config.mode === 'block' ? 'blocage actif' : 'observation seule'}
                </span>
                <button className="btn ghost" onClick={resetAll}>Réinitialiser</button>
              </div>
            </div>
            <div className="feed-list">
              {events.length === 0 && (
                <div className="empty">
                  En attente de trafic. Lancez une attaque depuis la console à gauche.
                </div>
              )}
              {events.map((e) => (
                <div className={`ev ${e.verdict}`} key={e.id}>
                  <span className="t">{fmtTime(e.ts)}</span>
                  <span className="verdict-pill">{VERDICT_LABEL[e.verdict]}</span>
                  <span className="path"><span className="m">{e.method}</span>{e.path}</span>
                  <span className="score">
                    {e.categories.filter((c) => c !== 'blocklist').join(', ') || '—'}
                    {e.score ? ` · ${e.score}` : ''}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <div className="card-h"><h3>Menaces par catégorie</h3>
              <span className="hint">bloquées + détectées</span>
            </div>
            <div className="card-b">
              {chartData.length === 0 ? (
                <div className="empty" style={{ padding: '30px 0' }}>Aucune menace enregistrée</div>
              ) : (
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} margin={{ top: 6, right: 8, left: -14, bottom: 0 }}>
                      <XAxis dataKey="name" tick={{ fill: '#8B97A8', fontSize: 11 }}
                        axisLine={{ stroke: '#1F2733' }} tickLine={false} interval={0} />
                      <YAxis allowDecimals={false} tick={{ fill: '#8B97A8', fontSize: 11 }}
                        axisLine={false} tickLine={false} />
                      <Tooltip
                        cursor={{ fill: '#ffffff08' }}
                        contentStyle={{ background: '#131824', border: '1px solid #2C3644',
                          borderRadius: 8, color: '#E4E9F2', fontSize: 12 }}
                      />
                      <Bar dataKey="value" radius={[5, 5, 0, 0]}>
                        {chartData.map((d) => (
                          <Cell key={d.key} fill={CAT_COLORS[d.key] || '#7C6BFF'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function Stat({ cls, k, v }) {
  return (
    <div className={`stat ${cls}`}>
      <span className="bar" />
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  )
}
