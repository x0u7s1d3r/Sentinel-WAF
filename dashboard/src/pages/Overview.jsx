import { useEffect, useState } from 'react'
import { useOutletContext, Link } from 'react-router-dom'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts'
import { api } from '../api.js'

const hhmm = (t) => (t || '').slice(11, 16)

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

export default function Overview() {
  const { stats, analytics, apps, events, settings } = useOutletContext()
  const [siteStats, setSiteStats] = useState({})

  // Liste des sites : applications enregistrées + le trafic « par défaut »
  // (requêtes sans domaine routé) s'il y en a.
  const registered = apps || []
  const hasDefault = (events || []).some((e) => e.app === 'default') || registered.length === 0
  const sites = [...registered]
  if (hasDefault) {
    sites.unshift({ id: 0, name: 'default', domain: '', mode: settings?.mode || 'block', _default: true })
  }

  const siteKey = sites.map((s) => s.name).join(',')
  useEffect(() => {
    let alive = true
    async function load() {
      const entries = await Promise.all(
        sites.map((s) => api.stats(s.name).then((st) => [s.name, st]).catch(() => [s.name, null])),
      )
      if (alive) setSiteStats(Object.fromEntries(entries))
    }
    load()
    const id = setInterval(load, 3000)
    return () => { alive = false; clearInterval(id) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [siteKey])

  const series = fillSeries(analytics?.timeseries)
  const total = stats?.total ?? 0
  const blocked = stats?.blocked ?? 0
  const detected = stats?.detected ?? 0
  const allowed = stats?.allowed ?? 0

  // Une attaque « récente » (< 5 min) marque un site comme attaqué.
  const now = Date.now()
  function recentAttacks(name) {
    return (events || []).filter(
      (e) => e.app === name && e.verdict !== 'allowed' && now - new Date(e.ts).getTime() < 5 * 60000,
    ).length
  }

  return (
    <div className="soc">
      <div className="cmd-hero">
        <div className="shield-wrap">
          <div className="ring" />
          <svg viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="hs" x1="0" y1="0" x2="40" y2="40">
                <stop offset="0" stopColor="#3FE0A8" /><stop offset="1" stopColor="#2C5CE0" />
              </linearGradient>
            </defs>
            <path d="M20 3 L34 8.5 V20 C34 29 27.5 35 20 37.5 C12.5 35 6 29 6 20 V8.5 Z" fill="url(#hs)" />
            <path d="M13.5 20 l4.5 4.5 l9 -10" stroke="#0C1524" strokeWidth="2.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <div className="hero-txt">
          <div className="lbl">État de la protection</div>
          <div className="st">
            <span className={blocked > 0 ? 'attacked' : 'ok'}>
              {blocked > 0 ? 'Attaques repoussées' : 'Système protégé'}
            </span>
            <span className="badge-live"><i />EN DIRECT</span>
          </div>
          <div className="sub">
            Sentinel inspecte le trafic en temps réel. <b>{blocked} attaque{blocked > 1 ? 's' : ''}</b> bloquée{blocked > 1 ? 's' : ''} sur la dernière heure,
            {detected > 0 ? ` ${detected} sous surveillance.` : ' aucune menace n\u2019a atteint vos applications.'}
          </div>
        </div>
        <div className="mini">
          <div className="mi"><span className="mv coral">{blocked}</span><span className="mk">Bloquées</span></div>
          <div className="mi"><span className="mv amber">{detected}</span><span className="mk">Surveillance</span></div>
          <div className="mi"><span className="mv">{sites.length}</span><span className="mk">Applications</span></div>
        </div>
      </div>

      <div className="tiles">
        <Tile cls="" k="Requêtes analysées" v={total} />
        <Tile cls="blocked" k="Attaques bloquées" v={blocked} />
        <Tile cls="detected" k="En surveillance" v={detected} />
        <Tile cls="allowed" k="Trafic autorisé" v={allowed} />
      </div>

      <div className="soc-hero">
        <h3 style={{ margin: '0 0 10px', fontFamily: 'var(--display)', fontSize: 13 }}>
          Trafic global — dernière heure
        </h3>
        <div style={{ height: 200 }}>
          {series.length === 0 ? (
            <div className="empty" style={{ margin: 'auto' }}>En attente de trafic pour tracer la courbe.</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={series} margin={{ top: 6, right: 8, left: -18, bottom: 0 }}>
                <defs>
                  <linearGradient id="oAllowed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#0FA678" stopOpacity={0.32} />
                    <stop offset="100%" stopColor="#0FA678" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="oBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#E5484D" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="#E5484D" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="oDetected" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#E0920A" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#E0920A" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="t" tickFormatter={hhmm} tick={{ fill: '#93A1B4', fontSize: 11 }}
                  axisLine={{ stroke: '#E6ECF5' }} tickLine={false} minTickGap={40} />
                <YAxis allowDecimals={false} tick={{ fill: '#93A1B4', fontSize: 11 }}
                  axisLine={false} tickLine={false} width={38} />
                <Tooltip labelFormatter={hhmm}
                  contentStyle={{ background: '#FFFFFF', border: '1px solid #D6E0EE', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="allowed" stackId="1" stroke="#0FA678" fill="url(#oAllowed)" strokeWidth={1.5} name="Autorisées" />
                <Area type="monotone" dataKey="detected" stackId="1" stroke="#E0920A" fill="url(#oDetected)" strokeWidth={1.5} name="Surveillance" />
                <Area type="monotone" dataKey="blocked" stackId="1" stroke="#E5484D" fill="url(#oBlocked)" strokeWidth={1.5} name="Bloquées" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="section-h">Vos sites protégés</div>
      <div className="sites-grid">
        {sites.map((s) => {
          const st = siteStats[s.name] || {}
          const atk = recentAttacks(s.name)
          const attacked = atk > 0
          return (
            <Link to={`/site/${encodeURIComponent(s.name)}`} className="site-card" key={s.name}>
              <div className="site-top">
                <div className={`site-dot ${attacked ? 'attacked' : 'calm'}`} />
                <div className="site-id">
                  <div className="site-name">{s._default ? 'Application principale' : s.name}</div>
                  <div className="site-dom">{s._default ? 'trafic direct (sans domaine)' : s.domain}</div>
                </div>
                <span className={`badge ${s.mode}`}>{s.mode === 'block' ? 'Blocage' : 'Surveillance'}</span>
              </div>
              <div className={`site-status ${attacked ? 'attacked' : 'calm'}`}>
                {attacked ? `Sous attaque — ${atk} récente${atk > 1 ? 's' : ''}` : 'Serein'}
              </div>
              <div className="site-metrics">
                <div><span className="m-v">{st.total ?? 0}</span><span className="m-k">requêtes</span></div>
                <div><span className="m-v threat">{st.blocked ?? 0}</span><span className="m-k">bloquées</span></div>
                <div><span className="m-v warn">{st.detected ?? 0}</span><span className="m-k">surveillées</span></div>
              </div>
              <div className="site-go">Voir le détail →</div>
            </Link>
          )
        })}
      </div>
    </div>
  )
}

function Tile({ cls, k, v }) {
  return (
    <div className={`tile ${cls}`}>
      <span className="bar" />
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  )
}
