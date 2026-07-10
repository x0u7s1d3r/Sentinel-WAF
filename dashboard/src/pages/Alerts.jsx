import { useState, useEffect } from 'react'
import { api } from '../api.js'

// Découpe l'analyse IA en deux sections (diagnostic + mesures) si les marqueurs
// sont présents ; sinon renvoie le texte brut comme diagnostic.
function splitAnalysis(text) {
  if (!text) return null
  const up = text.toUpperCase()
  const iM = up.indexOf('MESURES')
  if (iM === -1) return { diag: text.trim(), measures: [] }
  let diag = text.slice(0, iM)
  diag = diag.replace(/ANALYSE\s*:/i, '').trim()
  const rest = text.slice(iM).replace(/MESURES[^:]*:/i, '').trim()
  const measures = rest.split(/\n|(?:^|\s)[-•*]\s|\d+[.)]\s/).map((s) => s.trim()).filter(Boolean)
  return { diag, measures }
}

const SEV = {
  'ÉLEVÉE': { cls: 'high', ico: '🔴' },
  'MODÉRÉE': { cls: 'mid', ico: '🟠' },
  'SURVEILLANCE': { cls: 'low', ico: '🟡' },
}

function fmtTime(ts) {
  if (!ts) return ''
  const d = new Date(ts)
  return d.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
}

export default function Alerts() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(null)

  useEffect(() => {
    let alive = true
    const load = () => api.incidents()
      .then((d) => { if (alive) { setIncidents(d.incidents || []); setLoading(false) } })
      .catch(() => { if (alive) setLoading(false) })
    load()
    const t = setInterval(load, 5000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  return (
    <div className="card">
      <div className="card-h">
        <h3>Centre d'alertes</h3>
        <span className="hint">{incidents.length} incident{incidents.length > 1 ? 's' : ''}</span>
      </div>
      <div className="alerts-list">
        {loading && <div className="empty">Chargement…</div>}
        {!loading && incidents.length === 0 && (
          <div className="empty">Aucun incident pour le moment. Les attaques détectées apparaîtront ici, regroupées en incidents.</div>
        )}
        {incidents.map((inc) => {
          const sev = SEV[inc.severity] || { cls: 'low', ico: '⚪' }
          const isOpen = open === inc.id
          const ana = splitAnalysis(inc.analysis)
          return (
            <div className={`alert-card ${sev.cls} ${isOpen ? 'open' : ''}`} key={inc.id}>
              <button className="alert-head" onClick={() => setOpen(isOpen ? null : inc.id)}>
                <span className={`sev-badge ${sev.cls}`}>{sev.ico} {inc.severity}</span>
                <span className="alert-title">
                  {inc.count} attaque{inc.count > 1 ? 's' : ''} · {inc.blocked} bloquée{inc.blocked > 1 ? 's' : ''}
                  {inc.detected > 0 ? ` · ${inc.detected} surveillance` : ''}
                </span>
                <span className="alert-apps">{inc.apps || '—'}</span>
                <span className="alert-time">{fmtTime(inc.ts)}</span>
                <span className="alert-chevron">{isOpen ? '▾' : '▸'}</span>
              </button>
              {isOpen && (
                <div className="alert-body">
                  <div className="alert-grid">
                    <div className="ab-field"><span className="ab-k">Fenêtre</span><span className="ab-v">{inc.window}</span></div>
                    <div className="ab-field"><span className="ab-k">Applications visées</span><span className="ab-v">{inc.apps || '—'}</span></div>
                    <div className="ab-field"><span className="ab-k">Catégories</span><span className="ab-v">{inc.categories || '—'}</span></div>
                    <div className="ab-field"><span className="ab-k">IP sources</span><span className="ab-v mono">{inc.top_ips || '—'}</span></div>
                    <div className="ab-field"><span className="ab-k">Cibles</span><span className="ab-v mono">{inc.top_paths || '—'}</span></div>
                    <div className="ab-field"><span className="ab-k">Verdict</span><span className="ab-v">{inc.blocked} bloquée(s) · {inc.detected} surveillance</span></div>
                  </div>
                  {ana ? (
                    <div className="ai-block">
                      <div className="ai-title">🧠 Analyse IA</div>
                      <p className="ai-diag">{ana.diag}</p>
                      {ana.measures.length > 0 && (
                        <>
                          <div className="ai-sub">✅ Mesures immédiates</div>
                          <ul className="ai-measures">
                            {ana.measures.map((m, i) => <li key={i}>{m}</li>)}
                          </ul>
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="ai-block empty-ai">Aucune analyse IA pour cet incident (enrichissement désactivé ou indisponible au moment de l'alerte).</div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
