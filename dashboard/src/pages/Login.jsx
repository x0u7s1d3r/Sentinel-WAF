import { useState } from 'react'
import { api } from '../api.js'

export default function Login({ onSuccess }) {
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit() {
    if (!password) return
    setBusy(true); setErr('')
    try {
      await api.login(password)
      onSuccess()
    } catch (e) {
      setErr(e.status === 401 ? 'Mot de passe incorrect.' : String(e.message || e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login-wrap">
      <div className="login-card">
        <svg className="login-logo" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <linearGradient id="lgl" x1="0" y1="0" x2="40" y2="40">
              <stop offset="0" stopColor="#2C5CE0" /><stop offset="1" stopColor="#0FA678" />
            </linearGradient>
          </defs>
          <path d="M20 3 L34 8.5 V20 C34 29 27.5 35 20 37.5 C12.5 35 6 29 6 20 V8.5 Z" fill="url(#lgl)" />
          <path d="M13.5 20 l4.5 4.5 l9 -10" stroke="#fff" strokeWidth="2.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <div className="login-title">Sentinel <span>WAF</span></div>
        <div className="login-sub">Console d'administration</div>

        <input
          type="password" value={password} autoFocus
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="Mot de passe administrateur" className="login-input" />
        {err && <div className="login-err">{err}</div>}
        <button className="btn accent login-btn" onClick={submit} disabled={busy}>
          {busy ? 'Connexion…' : 'Se connecter'}
        </button>
      </div>
    </div>
  )
}
