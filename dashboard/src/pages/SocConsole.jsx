import { useOutletContext } from 'react-router-dom'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell,
} from 'recharts'

const CAT_COLOR = {
  sqli: '#FF5D6C', xss: '#F5B544', path_traversal: '#9B8CFF',
  cmd_injection: '#FF8A63', ssrf: '#4C8DFF', nosql: '#3DD6C0', scanner: '#4ADE80',
}
const CAT_LABEL = {
  sqli: 'SQLi', xss: 'XSS', path_traversal: 'Traversée',
  cmd_injection: 'Commande', ssrf: 'SSRF', nosql: 'NoSQL', scanner: 'Scanner',
}
const VERDICT = { blocked: 'BLOQUÉE', detected: 'SURVEIL.', allowed: 'PASSÉE' }

const hhmm = (t) => (t || '').slice(11, 16)
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('fr-FR', { hour12: false })

// Comble les minutes sans trafic pour une courbe continue (dernière heure).
function fillSeries(series) {
  if (!series || series.length === 0) return []
  const byT = new Map(series.map((p) => [p.t, p]))
  const bucket = (ms) => new Date(ms).toISOString().slice(0, 16) + ':00Z'
  const first = new Date(series[0].t).getTime()
  const last = new Date(series[series.length - 1].t).getTime()
  const out = []
  for (let m = first; m <= last; m += 60000) {
    const key = bucket(m)
    out.push(byT.get(key) || { t: key, total: 0, blocked: 0, detected: 0, allowed: 0 })
  }
  return out.slice(-60)
}

export default function SocConsole() {
  const { stats, events, analytics } = useOutletContext()
  const a = analytics || {}
  const series = fillSeries(a.timeseries)
  const cats = a.by_category || []
  const topIps = a.top_ips || []
  const topPaths = a.top_paths || []

  const total = stats?.total ?? 0
  const blocked = stats?.blocked ?? 0
  const detected = stats?.detected ?? 0
  const allowed = stats?.allowed ?? 0
  const rate = total ? Math.round((blocked / total) * 100) : 0

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

      <div className="kpis">
        <Kpi cls="" k="Requêtes" v={total} d="analysées" />
        <Kpi cls="blocked" k="Bloquées" v={blocked} d="attaques stoppées" />
        <Kpi cls="detected" k="Surveillance" v={detected} d="détectées, laissées passer" />
        <Kpi cls="allowed" k="Autorisées" v={allowed} d="trafic légitime" />
        <Kpi cls="rate" k="Taux de blocage" v={rate + '%'} d="des requêtes" />
      </div>

      <div className="soc-hero">
        <h3 style={{ margin: '0 0 10px', fontFamily: 'var(--display)', fontSize: 13 }}>
          Trafic — dernière heure
        </h3>
        <div style={{ height: 220 }}>
          {series.length === 0 ? (
            <Empty msg="En attente de trafic pour tracer la courbe." />
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="gAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#4ADE80" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#4ADE80" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#FF5D6C" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#FF5D6C" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="gDetected" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#F5B544" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#F5B544" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tickFormatter={hhmm} tick={{ fill: '#566072', fontSize: 11 }}
                  axisLine={{ stroke: '#1C2531' }} tickLine={false} minTickGap={40} />
                <YAxis allowDecimals={false} tick={{ fill: '#566072', fontSize: 11 }}
                  axisLine={false} tickLine={false} width={38} />
                <Tooltip
                  labelFormatter={hhmm}
                  contentStyle={{ background: '#0D131C', border: '1px solid #2A3646', borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: '#8695AB' }} />
                <Area type="monotone" dataKey="allowed" stackId="1" stroke="#4ADE80" fill="url(#gAllowed)" strokeWidth={1.5} name="Autorisées" />
                <Area type="monotone" dataKey="detected" stackId="1" stroke="#F5B544" fill="url(#gDetected)" strokeWidth={1.5} name="Surveillance" />
                <Area type="monotone" dataKey="blocked" stackId="1" stroke="#FF5D6C" fill="url(#gBlocked)" strokeWidth={1.5} name="Bloquées" />
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
                        <Cell key={c.category} fill={CAT_COLOR[c.category] || '#8695AB'} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#0D131C', border: '1px solid #2A3646', borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="donut-legend">
                {cats.map((c) => (
                  <div className="li" key={c.category}>
                    <i style={{ background: CAT_COLOR[c.category] || '#8695AB' }} />
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
                <div className="toprow threat" key={x.ip}>
                  <span className="lbl">{x.ip}</span>
                  <span className="val">{x.attacks || x.total} att.</span>
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
