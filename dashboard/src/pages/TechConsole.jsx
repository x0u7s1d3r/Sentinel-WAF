import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

const VERDICT = { blocked: 'BLOQUÉE', detected: 'SURVEIL.', allowed: 'PASSÉE' }

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString('fr-FR', { hour12: false })
}

export default function TechConsole() {
  const { stats, events, apps, refresh } = useOutletContext()

  return (
    <>
      <div className="tiles">
        <Tile cls="" k="Total" v={stats?.total ?? 0} />
        <Tile cls="blocked" k="Bloquées" v={stats?.blocked ?? 0} />
        <Tile cls="detected" k="Surveillance" v={stats?.detected ?? 0} />
        <Tile cls="allowed" k="Autorisées" v={stats?.allowed ?? 0} />
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-h">
            <h3>Flux d'événements</h3>
            <span className="hint">temps réel</span>
          </div>
          <div className="feed-list">
            {(events || []).length === 0 && (
              <div className="empty">Aucun événement pour l'instant.</div>
            )}
            {(events || []).map((e) => (
              <div className={`ev ${e.verdict}`} key={e.id}>
                <span className="t">{fmtTime(e.ts)}</span>
                <span className="pill">{VERDICT[e.verdict] || e.verdict}</span>
                <span className="path"><span className="m">{e.method}</span>{e.path}</span>
                <span className="cats">{(e.categories || []).join(', ') || '—'}</span>
              </div>
            ))}
          </div>
        </div>

        <AppsManager apps={apps} refresh={refresh} />
      </div>
    </>
  )
}

function AppsManager({ apps, refresh }) {
  const empty = { name: '', domain: '', upstream_url: '', mode: 'block', threshold: 4 }
  const [form, setForm] = useState(empty)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })

  async function add() {
    setErr('')
    if (!form.name || !form.domain || !form.upstream_url) {
      setErr('Nom, domaine et backend sont requis.')
      return
    }
    setBusy(true)
    try {
      await api.addApp({ ...form, threshold: Number(form.threshold) || 4 })
      setForm(empty)
      refresh()
    } catch (e) {
      setErr(String(e.message || e).slice(0, 160))
    } finally {
      setBusy(false)
    }
  }

  async function remove(id) {
    await api.deleteApp(id)
    refresh()
  }

  return (
    <div className="card">
      <div className="card-h">
        <h3>Applications surveillées</h3>
        <span className="hint">{apps?.length || 0} enregistrée{(apps?.length || 0) > 1 ? 's' : ''}</span>
      </div>

      <div className="app-row head">
        <span>Nom</span><span>Domaine</span><span>Backend</span><span>Mode</span><span></span>
      </div>
      {(apps || []).length === 0 && (
        <div className="empty">Aucune application. Ajoutez-en une ci-dessous.</div>
      )}
      {(apps || []).map((a) => (
        <div className="app-row" key={a.id}>
          <span>{a.name}</span>
          <span className="dom">{a.domain}</span>
          <span className="up">{a.upstream_url}</span>
          <span><span className={`badge ${a.mode}`}>{a.mode === 'block' ? 'Blocage' : 'Surveillance'}</span></span>
          <button className="btn danger mini" onClick={() => remove(a.id)}>Retirer</button>
        </div>
      ))}

      <div className="card-b">
        <div className="section-h" style={{ marginTop: 0 }}>Ajouter une application</div>
        <div className="form">
          <div>
            <label>Nom</label>
            <input value={form.name} onChange={set('name')} placeholder="Ma boutique" />
          </div>
          <div>
            <label>Domaine (en-tête Host)</label>
            <input value={form.domain} onChange={set('domain')} placeholder="boutique.exemple.tg" />
          </div>
          <div className="full">
            <label>Backend à protéger (URL)</label>
            <input value={form.upstream_url} onChange={set('upstream_url')} placeholder="http://127.0.0.1:9001" />
          </div>
          <div>
            <label>Mode</label>
            <select value={form.mode} onChange={set('mode')}>
              <option value="block">Blocage</option>
              <option value="detect">Surveillance</option>
            </select>
          </div>
          <div>
            <label>Seuil de blocage</label>
            <input type="number" min="1" value={form.threshold} onChange={set('threshold')} />
          </div>
          {err && <div className="full" style={{ color: 'var(--threat)', fontSize: 12 }}>{err}</div>}
          <div className="full">
            <button className="btn accent" onClick={add} disabled={busy}>
              {busy ? 'Ajout…' : 'Ajouter l’application'}
            </button>
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
