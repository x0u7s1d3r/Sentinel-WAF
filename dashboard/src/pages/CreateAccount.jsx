import { useState } from 'react'
import { api } from '../api.js'

export default function CreateAccount({ onSuccess }) {
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    setErr('')
    if (pw.length < 6) { setErr('6 caractères minimum.'); return }
    if (pw !== confirm) { setErr('Les deux mots de passe ne correspondent pas.'); return }
    setBusy(true)
    try {
      await api.setup(pw)
      onSuccess()
    } catch (e) {
      setErr(String(e.message || e))
    } finally { setBusy(false) }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <svg className="login-logo" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="lgc" x1="0" y1="0" x2="40" y2="40">
              <stop offset="0" stopColor="#3B82F6" /><stop offset="1" stopColor="#2456C8" />
            </linearGradient>
          </defs>
          <path d="M20 3 L34 8.5 V20 C34 29 27.5 35 20 37.5 C12.5 35 6 29 6 20 V8.5 Z" fill="url(#lgc)" />
          <path d="M13.5 20 l4.5 4.5 l9 -10" stroke="#fff" strokeWidth="2.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div className="login-title">Sentinel <span>WAF</span></div>
        <div className="login-sub">Créez le compte administrateur</div>

        <input type="password" value={pw} autoFocus onChange={(e) => setPw(e.target.value)}
          placeholder="Choisir un mot de passe" className="login-input" />
        <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="Confirmer le mot de passe" className="login-input" />
        {err && <div className="login-err">{err}</div>}
        <button className="btn accent login-btn" onClick={submit} disabled={busy}>
          {busy ? 'Création…' : 'Créer le compte'}
        </button>
        <div className="login-note">Ce mot de passe protège l'accès à la console. Il est haché, jamais stocké en clair.</div>
      </div>
    </div>
  )
}
