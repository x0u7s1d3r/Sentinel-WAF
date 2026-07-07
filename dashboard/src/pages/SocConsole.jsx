import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'
import { api, CATEGORIES } from '../api.js'

// Plages de temps proposées et leur pas d'agrégation (ms) côté affichage.
const RANGES = [
  ['1h', "1 h", 60000],
  ['24h', '24 h', 900000],
  ['72h', '72 h', 3600000],
  ['7d', '7 j', 10800000],
  ['30d', '30 j', 86400000],
  ['all', 'Tout', 86400000],
]
const RANGE_LABEL = Object.fromEntries(RANGES.map(([k, l]) => [k, l]))

const CAT_COLOR = {
  sqli: '#E23D43', xss: '#D9820A', path_traversal: '#9B8CFF',
  cmd_injection: '#F97316', ssrf: '#2F6FED', nosql: '#0EA5A3', scanner: '#17A34A',
  sensitive_path: '#EC4899', brute_force: '#8B5CF6', blocklist: '#64748B',
}
const CAT_LABEL = {
  sqli: 'SQLi', xss: 'XSS', path_traversal: 'Traversée',
  cmd_injection: 'Commande', ssrf: 'SSRF', nosql: 'NoSQL', scanner: 'Scanner',
  sensitive_path: 'Chemin sensible', brute_force: 'Force brute', blocklist: 'IP bannie',
}
const VERDICT = { blocked: 'BLOQUÉE', detected: 'SURVEIL.', allowed: 'PASSÉE' }

const hhmm = (t) => (t || '').slice(11, 16)
const ddmm = (t) => { const d = new Date(t); return `${String(d.getDate()).padStart(2, '0')}/${String(d.getMonth() + 1).padStart(2, '0')}` }
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('fr-FR', { hour12: false })

// Étiquette d'axe selon la plage : heure pour les courtes, date pour les longues.
function tickFmt(range) {
  return (range === '7d' || range === '30d' || range === 'all') ? ddmm : hhmm
}
// Étiquette du tooltip : date + heure sur les longues plages.
function labelFmt(range) {
  if (range === '7d' || range === '30d' || range === 'all') {
    return (t) => { const d = new Date(t); return `${ddmm(t)} ${String(d.getHours()).padStart(2, '0')}:00` }
  }
  return hhmm
}

// Comble les tranches vides pour une courbe continue, selon le pas de la plage.
function fillSeries(series, stepMs) {
  if (!series || series.length === 0) return []
  const byT = new Map(series.map((p) => [p.t, p]))
  const bucket = (ms) => new Date(Math.floor(ms / stepMs) * stepMs).toISOString().slice(0, 19) + 'Z'
  const first = new Date(series[0].t).getTime()
  const last = new Date(series[series.length - 1].t).getTime()
  const out = []
  for (let m = first; m <= last; m += stepMs) {
    const key = bucket(m)
    out.push(byT.get(key) || { t: key, total: 0, blocked: 0, detected: 0, allowed: 0 })
  }
  return out.slice(-400) // borne de sécurité
}

export default function SocConsole() {
  const { stats, events, analytics, settings, refresh } = useOutletContext()
  const [range, setRange] = useState('1h')
  const [local, setLocal] = useState(null)

  // Charge l'analytique pour la plage choisie (et rafraîchit en direct).
  useEffect(() => {
    let alive = true
    const load = () => api.analytics(range).then((d) => { if (alive) setLocal(d) }).catch(() => {})
    load()
    const id = setInterval(load, 2500)
    return () => { alive = false; clearInterval(id) }
  }, [range])

  const a = local || analytics || {}
  const stepMs = (RANGES.find((r) => r[0] === range) || RANGES[0])[2]
  const series = fillSeries(a.timeseries, stepMs)
  const cats = a.by_category || []
  const topIps = a.top_ips || []
  const topPaths = a.top_paths || []

  const st = settings || {}
  const enabled = new Set(st.enabled_categories || [])
  const blocked = new Set(st.blocklist || [])

  async function setMode(mode) { await api.setSettings({ mode }); refresh() }
  async function setThreshold(threshold) { await api.setSettings({ threshold }); refresh() }
  async function toggleCat(cat) {
    const next = new Set(enabled)
    next.has(cat) ? next.delete(cat) : next.add(cat)
    await api.setSettings({ enabled_categories: [...next] }); refresh()
  }
  async function ban(ip) { await api.blocklist(ip, 'add'); refresh() }
  async function unban(ip) { await api.blocklist(ip, 'remove'); refresh() }

  const total = stats?.total ?? 0
  const blockedCount = stats?.blocked ?? 0
  const detected = stats?.detected ?? 0
  const allowed = stats?.allowed ?? 0
  const rate = total ? Math.round((blockedCount / total) * 100) : 0

  const maxIp = Math.max(1, ...topIps.map((x) => x.attacks || x.total))
  const maxPath = Math.max(1, ...topPaths.map((x) => x.count))
  const catTotal = cats.reduce((s, c) => s + c.count, 0)

  return (
    <div className="soc">
      <div className="live-strip">
        <span className="live"><i />EN DIRECT</span>
        <span className="sep">·</span>
        <span className="live" style={{ color: 'var(--faint)' }}>
          actualisation automatique toutes les 2 s
        </span>
      </div>

      {/* Barre de contrôles rapides */}
      {settings && (
        <div className="ctrlbar">
          <div className="ctrl">
            <span className="ctrl-l">Mode</span>
            <div className="seg">
              <button className={st.mode === 'block' ? 'active block' : ''} onClick={() => setMode('block')}>Blocage</button>
              <button className={st.mode === 'detect' ? 'active detect' : ''} onClick={() => setMode('detect')}>Surveillance</button>
            </div>
          </div>
          <div className="ctrl">
            <span className="ctrl-l">Seuil {st.threshold}</span>
            <input type="range" min="1" max="12" value={st.threshold}
              onChange={(e) => setThreshold(Number(e.target.value))} className="slider sm" />
          </div>
          <div className="ctrl chips">
            <span className="ctrl-l">Protections</span>
            {CATEGORIES.map(([key, name]) => (
              <button key={key} className={`chip-toggle ${enabled.has(key) ? 'on' : ''}`}
                onClick={() => toggleCat(key)} title={name}>
                {name.replace('Injection ', '').replace('Cross-Site Scripting', 'XSS').replace('Server-Side Request Forgery', 'SSRF')}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="kpis">
        <Kpi cls="" k="Requêtes" v={total} d="analysées" />
        <Kpi cls="blocked" k="Bloquées" v={blockedCount} d="attaques stoppées" />
        <Kpi cls="detected" k="Surveillance" v={detected} d="détectées, laissées passer" />
        <Kpi cls="allowed" k="Autorisées" v={allowed} d="trafic légitime" />
        <Kpi cls="rate" k="Taux de blocage" v={rate + '%'} d="des requêtes" />
      </div>

      <div className="soc-hero">
        <div className="range-head">
          <h3 style={{ margin: 0, fontFamily: 'var(--display)', fontSize: 13 }}>
            Trafic — {RANGE_LABEL[range] === 'Tout' ? 'tout l’historique' : `derniers ${RANGE_LABEL[range]}`}
          </h3>
          <div className="range-picker">
            {RANGES.map(([key, label]) => (
              <button key={key}
                className={`range-btn ${range === key ? 'active' : ''}`}
                onClick={() => setRange(key)}>{label}</button>
            ))}
          </div>
        </div>
        <div style={{ height: 220 }}>
          {series.length === 0 ? (
            <Empty msg="En attente de trafic pour tracer la courbe." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#17A34A" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#17A34A" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#E23D43" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#E23D43" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gDetected" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#D9820A" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#D9820A" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tickFormatter={tickFmt(range)} tick={{ fill: '#7A8AA0', fontSize: 11 }}
                  axisLine={{ stroke: '#E4EBF4' }} tickLine={false} minTickGap={40} />
                <YAxis allowDecimals={false} tick={{ fill: '#7A8AA0', fontSize: 11 }}
                  axisLine={false} tickLine={false} width={38} />
                <Tooltip
                  labelFormatter={labelFmt(range)}
                  contentStyle={{ background: '#FFFFFF', border: '1px solid #CFDCEC', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#5C6B80' }} />
                <Area type="monotone" dataKey="allowed" stackId="1" stroke="#17A34A" fill="url(#gAllowed)" strokeWidth={1.5} name="Autorisées" />
                <Area type="monotone" dataKey="detected" stackId="1" stroke="#D9820A" fill="url(#gDetected)" strokeWidth={1.5} name="Surveillance" />
                <Area type="monotone" dataKey="blocked" stackId="1" stroke="#E23D43" fill="url(#gBlocked)" strokeWidth={1.5} name="Bloquées" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="soc-cols">
        {/* Répartition par catégorie */}
        <div className="panelbox">
          <h3>Répartition des attaques <span className="hint">par catégorie</span></h3>
          {cats.length === 0 ? <Empty msg="Aucune attaque enregistrée." /> : (
            <>
              <div style={{ height: 150 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={cats} dataKey="count" nameKey="category"
                      innerRadius={44} outerRadius={64} paddingAngle={2} stroke="none">
                      {cats.map((c) => (
                        <Cell key={c.category} fill={CAT_COLOR[c.category] || '#5C6B80'} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#FFFFFF', border: '1px solid #CFDCEC', borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="donut-legend">
                {cats.map((c) => (
                  <div className="li" key={c.category}>
                    <i style={{ background: CAT_COLOR[c.category] || '#5C6B80' }} />
                    {CAT_LABEL[c.category] || c.category}
                    <span className="c">{c.count} · {Math.round((c.count / catTotal) * 100)}%</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>

        {/* Top attaquants */}
        <div className="panelbox">
          <h3>Top attaquants <span className="hint">par IP</span></h3>
          {topIps.length === 0 ? <Empty msg="Aucune source détectée." /> : (
            <div className="toplist">
              {topIps.map((x) => (
                <div className="toprow threat ban" key={x.ip}>
                  <span className="lbl">{x.ip}</span>
                  <span className="val">
                    {x.attacks || x.total} att.
                    {blocked.has(x.ip)
                      ? <button className="banbtn banned" onClick={() => unban(x.ip)} title="Débannir">banni ✕</button>
                      : <button className="banbtn" onClick={() => ban(x.ip)} title="Bannir cette IP">bannir</button>}
                  </span>
                  <span className="track"><span className="fill" style={{ width: `${((x.attacks || x.total) / maxIp) * 100}%` }} /></span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top cibles */}
        <div className="panelbox">
          <h3>Cibles visées <span className="hint">URLs attaquées</span></h3>
          {topPaths.length === 0 ? <Empty msg="Aucune cible enregistrée." /> : (
            <div className="toplist">
              {topPaths.map((x) => (
                <div className="toprow" key={x.path}>
                  <span className="lbl">{x.path}</span>
                  <span className="val">{x.count}</span>
                  <span className="track"><span className="fill" style={{ width: `${(x.count / maxPath) * 100}%` }} /></span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Flux d'événements en direct */}
      <div className="stream">
        <div className="sh"><h3>Flux d'événements</h3><span className="hint" style={{ fontSize: 11, color: 'var(--faint)' }}>{(events || []).length} récents</span></div>
        <div className="rows">
          {(events || []).length === 0 && <div className="empty">Aucun événement pour l'instant.</div>}
          {(events || []).map((e) => (
            <div className={`srow ${e.verdict}`} key={e.id}>
              <span className="t">{fmtTime(e.ts)}</span>
              <span className="pill">{VERDICT[e.verdict] || e.verdict}</span>
              <span className="m">{e.method}</span>
              <span className="p">{e.path}</span>
              <span className="ip">{(e.categories || []).join(',') || e.client_ip}</span>
              <span className="sc">{e.score || ''}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function Kpi({ cls, k, v, d }) {
  return (
    <div className={`kpi ${cls}`}>
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      <div className="d">{d}</div>
    </div>
  )
}

function Empty({ msg }) {
  return <div className="empty" style={{ margin: 'auto' }}>{msg}</div>
}
