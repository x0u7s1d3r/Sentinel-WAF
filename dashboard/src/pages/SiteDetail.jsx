import { useEffect, useState } from 'react'
import { useParams, useOutletContext, Link } from 'react-router-dom'
import { api } from '../api.js'

const VERDICT = { blocked: 'BLOQUÉE', detected: 'SURVEIL.', allowed: 'PASSÉE' }
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('fr-FR', { hour12: false })

export default function SiteDetail() {
  const { name } = useParams()
  const { apps, settings, refresh } = useOutletContext()
  const [data, setData] = useState({ stats: null, events: [], analytics: null })

  const app = (apps || []).find((a) => a.name === name)
  const isDefault = name === 'default'

  useEffect(() => {
    let alive = true
    async function load() {
      const [stats, ev, analytics] = await Promise.all([
        api.stats(name).catch(() => null),
        api.events(name).catch(() => ({ events: [] })),
        api.analytics(name).catch(() => null),
      ])
      if (alive) setData({ stats, events: ev.events || [], analytics })
    }
    load()
    const id = setInterval(load, 2000)
    return () => { alive = false; clearInterval(id) }
  }, [name])

  const { stats, events, analytics } = data
  const total = stats?.total ?? 0
  const blocked = stats?.blocked ?? 0
  const detected = stats?.detected ?? 0
  const allowed = stats?.allowed ?? 0
  const topPaths = analytics?.top_paths || []

  const now = Date.now()
  const recent = (events || []).filter(
    (e) => e.verdict !== 'allowed' && now - new Date(e.ts).getTime() < 5 * 60000,
  )
  const attacked = recent.length > 0
  const mode = isDefault ? (settings?.mode || 'block') : (app?.mode || 'block')

  async function setMode(m) {
    if (isDefault) {
      await api.setSettings({ mode: m })
    } else if (app) {
      await api.updateApp(app.id, m, app.threshold || 4)
    }
    refresh()
  }

  return (
    <div className="soc">
      <Link to="/" className="back">← Tous les sites</Link>

      {/* Hero scoped au site */}
      <section className="hero">
        <div className="shield">
          <span className="ring" style={attacked ? { animation: 'none' } : {}} />
          <svg viewBox="0 0 100 100" fill="none">
            <path d="M50 6 L86 20 V48 C86 72 70 88 50 96 C30 88 14 72 14 48 V20 Z"
              fill={attacked ? '#E23D4310' : '#2F6FED10'}
              stroke={attacked ? 'var(--threat)' : 'var(--accent)'} strokeWidth="2.5" />
            {attacked ? (
              <path d="M50 30 V54 M50 66 v.5" stroke="var(--threat)" strokeWidth="5"
                fill="none" strokeLinecap="round" />
            ) : (
              <path d="M36 50 l10 10 l20 -22" stroke="var(--accent)" strokeWidth="4"
                fill="none" strokeLinecap="round" strokeLinejoin="round" />
            )}
          </svg>
        </div>
        <div>
          <div className="status-label">{isDefault ? 'Application principale' : name}</div>
          <div className={`status ${attacked ? 'warn' : 'ok'}`}>
            {attacked ? 'Sous attaque' : 'Protégé'}
          </div>
          <div className="sub">
            {isDefault ? 'Trafic direct (sans domaine routé). ' : <>Domaine <b>{app?.domain || '—'}</b>. </>}
            {attacked
              ? <><b>{recent.length}</b> attaque{recent.length > 1 ? 's' : ''} dans les 5 dernières minutes.</>
              : <>Aucune attaque récente sur ce site.</>}
          </div>
        </div>
        <div className="hero-ctrl">
          <span className="ctrl-l">Mode de ce site</span>
          <div className="seg">
            <button className={mode === 'block' ? 'active block' : ''} onClick={() => setMode('block')}>Blocage</button>
            <button className={mode === 'detect' ? 'active detect' : ''} onClick={() => setMode('detect')}>Surveillance</button>
          </div>
        </div>
      </section>

      <div className="tiles">
        <Tile cls="" k="Requêtes" v={total} />
        <Tile cls="blocked" k="Bloquées" v={blocked} />
        <Tile cls="detected" k="Surveillance" v={detected} />
        <Tile cls="allowed" k="Autorisées" v={allowed} />
      </div>

      <div className="soc-cols" style={{ gridTemplateColumns: '1fr 1.3fr' }}>
        {/* Cibles visées sur ce site */}
        <div className="panelbox">
          <h3>Cibles visées <span className="hint">sur ce site</span></h3>
          {topPaths.length === 0 ? (
            <div className="empty" style={{ margin: 'auto' }}>Aucune cible attaquée.</div>
          ) : (
            <div className="toplist">
              {topPaths.map((x) => {
                const max = Math.max(1, ...topPaths.map((p) => p.count))
                return (
                  <div className="toprow" key={x.path}>
                    <span className="lbl">{x.path}</span>
                    <span className="val">{x.count}</span>
                    <span className="track"><span className="fill" style={{ width: `${(x.count / max) * 100}%` }} /></span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Dernières attaques de ce site */}
        <div className="panelbox" style={{ padding: 0 }}>
          <h3 style={{ padding: '14px 16px 10px' }}>Dernières attaques <span className="hint">de ce site</span></h3>
          <div className="rows" style={{ maxHeight: 300 }}>
            {(events || []).filter((e) => e.verdict !== 'allowed').length === 0 && (
              <div className="empty">Aucune attaque enregistrée.</div>
            )}
            {(events || []).filter((e) => e.verdict !== 'allowed').map((e) => (
              <div className={`srow ${e.verdict}`} key={e.id} style={{ gridTemplateColumns: '66px 70px 1fr 120px' }}>
                <span className="t">{fmtTime(e.ts)}</span>
                <span className="pill">{VERDICT[e.verdict] || e.verdict}</span>
                <span className="p">{e.path}</span>
                <span className="ip">{(e.categories || []).join(',') || e.client_ip}</span>
              </div>
            ))}
          </div>
        </div>
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
