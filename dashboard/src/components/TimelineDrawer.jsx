import { useState, useEffect } from 'react'
import { api } from '../api.js'

const CAT_LABEL = {
  sqli: 'Injection SQL', xss: 'XSS', path_traversal: 'Traversée de répertoire',
  cmd_injection: 'Injection de commande', ssrf: 'SSRF', nosql: 'Injection NoSQL',
  scanner: 'Scanner', sensitive_path: 'Chemin sensible', brute_force: 'Force brute',
}
const VERDICT = { blocked: 'Bloquée', detected: 'Surveillance', allowed: 'Autorisée' }

function fmtTime(ts) {
  if (!ts) return ''
  return new Date(ts).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
function fmtDur(a, b) {
  if (!a || !b) return '—'
  const s = Math.max(0, Math.round((new Date(b) - new Date(a)) / 1000))
  if (s < 60) return `${s} s`
  if (s < 3600) return `${Math.floor(s / 60)} min ${s % 60} s`
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
}

export default function TimelineDrawer({ ip, onClose }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!ip) return
    setLoading(true)
    api.timeline(ip)
      .then((d) => { setData(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [ip])

  if (!ip) return null
  const s = data?.summary || {}
  const events = data?.events || []
  const cats = Object.entries(s.categories || {}).sort((a, b) => b[1] - a[1])

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} />
      <aside className="drawer">
        <div className="drawer-head">
          <div>
            <div className="drawer-kicker">Chronologie de l'attaquant</div>
            <div className="drawer-ip">{ip}</div>
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Fermer">✕</button>
        </div>

        {loading && <div className="empty">Reconstitution de la session…</div>}

        {!loading && (
          <>
            <div className="drawer-summary">
              <div className="ds-tile"><span className="ds-v">{s.total || 0}</span><span className="ds-k">Requêtes</span></div>
              <div className="ds-tile"><span className="ds-v threat">{s.blocked || 0}</span><span className="ds-k">Bloquées</span></div>
              <div className="ds-tile"><span className="ds-v warn">{s.detected || 0}</span><span className="ds-k">Surveillance</span></div>
              <div className="ds-tile"><span className="ds-v">{s.max_score || 0}</span><span className="ds-k">Score max</span></div>
            </div>

            <div className="drawer-meta">
              <div><span className="dm-k">Première vue</span><span className="dm-v">{fmtTime(s.first_seen)}</span></div>
              <div><span className="dm-k">Dernière vue</span><span className="dm-v">{fmtTime(s.last_seen)}</span></div>
              <div><span className="dm-k">Durée de la session</span><span className="dm-v">{fmtDur(s.first_seen, s.last_seen)}</span></div>
            </div>

            {cats.length > 0 && (
              <div className="drawer-cats">
                {cats.map(([c, n]) => (
                  <span className="dcat" key={c}>{CAT_LABEL[c] || c} <b>{n}</b></span>
                ))}
              </div>
            )}

            <div className="drawer-tl-title">Séquence des requêtes</div>
            <div className="drawer-timeline">
              {events.map((e, i) => (
                <div className={`tl-item ${e.verdict}`} key={e.id}>
                  <div className="tl-marker">
                    <span className="tl-dot" />
                    {i < events.length - 1 && <span className="tl-line" />}
                  </div>
                  <div className="tl-content">
                    <div className="tl-row1">
                      <span className="tl-time">{fmtTime(e.ts)}</span>
                      <span className={`tl-verdict ${e.verdict}`}>{VERDICT[e.verdict] || e.verdict}</span>
                      {e.score > 0 && <span className="tl-score">score {e.score}</span>}
                    </div>
                    <div className="tl-row2">
                      <span className="tl-method">{e.method}</span>
                      <span className="tl-path">{e.path}</span>
                    </div>
                    {(e.categories || []).length > 0 && (
                      <div className="tl-cats">
                        {e.categories.map((c) => <span className="tl-cat" key={c}>{CAT_LABEL[c] || c}</span>)}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {events.length === 0 && <div className="empty">Aucune requête enregistrée pour cette IP.</div>}
            </div>
          </>
        )}
      </aside>
    </>
  )
}
