import { useOutletContext } from 'react-router-dom'
import { CATEGORIES } from '../api.js'

function timeAgo(ts) {
  const s = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000))
  if (s < 60) return `il y a ${s} s`
  if (s < 3600) return `il y a ${Math.floor(s / 60)} min`
  if (s < 86400) return `il y a ${Math.floor(s / 3600)} h`
  return `il y a ${Math.floor(s / 86400)} j`
}

export default function SiteStatus() {
  const { health, stats, events, apps } = useOutletContext()

  const blocked = stats?.blocked ?? 0
  const detected = stats?.detected ?? 0
  const allowed = stats?.allowed ?? 0
  const total = stats?.total ?? 0
  const appCount = apps?.length ?? 0

  // Comptage des attaques par catégorie (à partir des événements récents)
  const counts = {}
  let lastThreat = null
  for (const e of events || []) {
    if (e.verdict !== 'allowed') {
      for (const c of e.categories || []) counts[c] = (counts[c] || 0) + 1
      if (!lastThreat) lastThreat = e
    }
  }

  // Le site est « sous surveillance renforcée » si des menaces passent (mode detect)
  const anyThreat = blocked + detected > 0
  const statusOk = health?.mode === 'block' || detected === 0

  return (
    <>
      <section className="hero">
        <div className="shield">
          <span className="ring" />
          <svg viewBox="0 0 100 100" fill="none">
            <path d="M50 6 L86 20 V48 C86 72 70 88 50 96 C30 88 14 72 14 48 V20 Z"
              fill="#6fcf9714" stroke="var(--safe)" strokeWidth="2.5" />
            <path d="M36 50 l10 10 l20 -22" stroke="var(--safe)" strokeWidth="4"
              fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <div>
          <div className="status-label">État de la protection</div>
          <div className={`status ${statusOk ? 'ok' : 'warn'}`}>
            {statusOk ? 'Protégé' : 'Surveillance'}
          </div>
          <div className="sub">
            {appCount > 0
              ? <><b>{appCount}</b> application{appCount > 1 ? 's' : ''} sous protection. </>
              : <>Protection active sur le trafic entrant. </>}
            {anyThreat
              ? <><b>{blocked}</b> attaque{blocked > 1 ? 's' : ''} bloquée{blocked > 1 ? 's' : ''} à ce jour.</>
              : <>Aucune attaque détectée pour l'instant.</>}
          </div>
        </div>
      </section>

      <div className="tiles">
        <Tile cls="" k="Requêtes analysées" v={total} />
        <Tile cls="blocked" k="Attaques bloquées" v={blocked} />
        <Tile cls="detected" k="En surveillance" v={detected} />
        <Tile cls="allowed" k="Trafic autorisé" v={allowed} />
      </div>

      <div className="section-h">Protections actives</div>
      <div className="protect-grid">
        {CATEGORIES.map(([key, name, desc]) => (
          <div className="protect" key={key}>
            <div className="check">✓</div>
            <div className="txt">
              <div className="n">{name}</div>
              <div className="s">{desc}</div>
            </div>
            {counts[key] ? <div className="count">{counts[key]} bloquée{counts[key] > 1 ? 's' : ''}</div> : null}
          </div>
        ))}
      </div>

      <div className="section-h">Dernière menace</div>
      <div className={`last ${lastThreat ? '' : 'calm'}`}>
        <span className="pulse" />
        {lastThreat ? (
          <div className="info">
            <b>{(lastThreat.categories || []).join(', ') || 'Menace'} </b>
            {lastThreat.verdict === 'blocked' ? 'bloquée' : 'détectée (surveillance)'}
            <div className="meta">
              {timeAgo(lastThreat.ts)} · IP {lastThreat.client_ip} · {lastThreat.path}
            </div>
          </div>
        ) : (
          <div className="info">
            Rien à signaler.
            <div className="meta">Aucune attaque n'a été détectée récemment.</div>
          </div>
        )}
      </div>
    </>
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
