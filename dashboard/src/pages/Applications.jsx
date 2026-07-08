import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../api.js'

export default function Applications() {
  const { apps, refresh } = useOutletContext()
  const empty = { name: '', domain: '', upstream_url: '', mode: 'block', threshold: 4 }
  const [form, setForm] = useState(empty)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [editId, setEditId] = useState(null)
  const [edit, setEdit] = useState(empty)

  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value })
  const setE = (k) => (e) => setEdit({ ...edit, [k]: e.target.value })

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
      setErr(String(e.message || e).slice(0, 180))
    } finally {
      setBusy(false)
    }
  }

  async function remove(id) {
    if (!confirm('Retirer cette application de la protection ?')) return
    await api.deleteApp(id)
    refresh()
  }

  async function toggleMode(a) {
    const next = a.mode === 'block' ? 'detect' : 'block'
    await api.updateApp(a.id, { mode: next, threshold: a.threshold || 4 })
    refresh()
  }

  function startEdit(a) {
    setEditId(a.id)
    setEdit({
      name: a.name, domain: a.domain, upstream_url: a.upstream_url,
      mode: a.mode, threshold: a.threshold || 4,
    })
  }

  async function saveEdit(id) {
    await api.updateApp(id, {
      name: edit.name, domain: edit.domain, upstream_url: edit.upstream_url,
      mode: edit.mode, threshold: Number(edit.threshold) || 4,
    })
    setEditId(null)
    refresh()
  }

  return (
    <div className="grid-2" style={{ gridTemplateColumns: '1.4fr 1fr' }}>
      <div className="card">
        <div className="card-h">
          <h3>Applications surveillées</h3>
          <span className="hint">{apps?.length || 0} enregistrée{(apps?.length || 0) > 1 ? 's' : ''}</span>
        </div>
        <div className="app-list">
          {(apps || []).length === 0 && (
            <div className="empty">Aucune application. Ajoutez-en une pour la placer sous protection.</div>
          )}
          {(apps || []).map((a) => (
            editId === a.id ? (
              <div className="app-card editing" key={a.id}>
                <div className="form">
                  <div className="full">
                    <label>Nom</label>
                    <input value={edit.name} onChange={setE('name')} />
                  </div>
                  <div className="full">
                    <label>Domaine (en-tête Host)</label>
                    <input value={edit.domain} onChange={setE('domain')} />
                  </div>
                  <div className="full">
                    <label>Backend à protéger (URL)</label>
                    <input value={edit.upstream_url} onChange={setE('upstream_url')} />
                  </div>
                  <div>
                    <label>Mode</label>
                    <select value={edit.mode} onChange={setE('mode')}>
                      <option value="block">Blocage</option>
                      <option value="detect">Surveillance</option>
                    </select>
                  </div>
                  <div>
                    <label>Seuil de blocage</label>
                    <input type="number" min="1" value={edit.threshold} onChange={setE('threshold')} />
                  </div>
                  <div className="full app-edit-actions">
                    <button className="btn accent" onClick={() => saveEdit(a.id)}>Enregistrer</button>
                    <button className="btn ghost" onClick={() => setEditId(null)}>Annuler</button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="app-card" key={a.id}>
                <div className="app-card-main">
                  <div className="app-id">
                    <span className="app-name">{a.name}</span>
                    <span className="app-domain">{a.domain}</span>
                  </div>
                  <div className="app-backend">
                    <span className="app-lbl">Backend</span>
                    <span className="app-up">{a.upstream_url}</span>
                  </div>
                </div>
                <div className="app-card-side">
                  <button
                    className={`mode-toggle ${a.mode}`}
                    onClick={() => toggleMode(a)}
                    title="Basculer entre Blocage et Surveillance"
                  >
                    <span className="mode-ico">{a.mode === 'block' ? '🛡️' : '👁️'}</span>
                    <span className="mode-txt">{a.mode === 'block' ? 'Blocage' : 'Surveillance'}</span>
                  </button>
                  <div className="app-acts">
                    <button className="icon-btn" onClick={() => startEdit(a)} title="Modifier">✎</button>
                    <button className="icon-btn danger" onClick={() => remove(a.id)} title="Retirer">🗑</button>
                  </div>
                </div>
              </div>
            )
          ))}
        </div>
      </div>

      <div className="card">
        <div className="card-h"><h3>Ajouter une application</h3></div>
        <div className="card-b">
          <div className="form">
            <div className="full">
              <label>Nom</label>
              <input value={form.name} onChange={set('name')} placeholder="Ma boutique en ligne" />
            </div>
            <div className="full">
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
    </div>
  )
}
