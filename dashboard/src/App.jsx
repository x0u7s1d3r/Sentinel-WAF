import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { api } from './api.js'
import Login from './pages/Login.jsx'
import CreateAccount from './pages/CreateAccount.jsx'

export default function App() {
  const [data, setData] = useState({
    health: null, stats: null, events: [], apps: [], analytics: null,
    settings: null, connected: null,
  })
  // screen: 'ready' | 'login' | 'setup'
  const [screen, setScreen] = useState('ready')

  async function refresh() {
    let health
    try {
      health = await api.health() // ouvert : indique si un compte existe
    } catch {
      setData((d) => ({ ...d, connected: false }))
      return
    }
    // Aucun compte -> écran de création (sécurisé par défaut).
    if (!health.account_exists) {
      setScreen('setup')
      setData((d) => ({ ...d, health, connected: true }))
      return
    }
    try {
      const [stats, eventsRes, appsRes, analytics, settings] = await Promise.all([
        api.stats(), api.events(),
        api.apps().catch(() => ({ apps: [] })),
        api.analytics('24h').catch(() => null),
        api.settings().catch(() => null),
      ])
      setData({
        health, stats,
        events: eventsRes.events || [],
        apps: appsRes.apps || [],
        analytics, settings, connected: true,
      })
      setScreen('ready')
    } catch (e) {
      if (e && e.status === 401) setScreen('login')
      else setData((d) => ({ ...d, connected: false }))
    }
  }

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 2000)
    return () => clearInterval(id)
  }, [])

  if (screen === 'setup') return <CreateAccount onSuccess={() => { setScreen('ready'); refresh() }} />
  if (screen === 'login') return <Login onSuccess={() => { setScreen('ready'); refresh() }} />

  const mode = data.settings?.mode || data.health?.mode || 'block'
  function logout() { api.logout(); setScreen('login') }

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <svg className="logo" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
            <defs>
              <linearGradient id="lg" x1="0" y1="0" x2="40" y2="40">
                <stop offset="0" stopColor="#2C5CE0" />
                <stop offset="1" stopColor="#0FA678" />
              </linearGradient>
            </defs>
            <path d="M20 3 L34 8.5 V20 C34 29 27.5 35 20 37.5 C12.5 35 6 29 6 20 V8.5 Z" fill="url(#lg)" />
            <path d="M13.5 20 l4.5 4.5 l9 -10" stroke="#fff" strokeWidth="2.8" fill="none" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div className="name">Sentinel <span>WAF</span></div>
        </div>
        <nav className="nav">
          <NavLink to="/" end>Vue d'ensemble</NavLink>
          <NavLink to="/supervision">Supervision</NavLink>
          <NavLink to="/applications">Applications</NavLink>
          <NavLink to="/parametres">Paramètres</NavLink>
        </nav>
        <div className="spacer" />
        <div className={`mode-badge ${mode === 'detect' ? 'detect' : ''}`}>
          <span className="dot" />
          {mode === 'block' ? 'Mode blocage' : 'Mode surveillance'}
        </div>
        {api.hasToken() && (
          <button className="btn mini logout-btn" onClick={logout} title="Se déconnecter">Déconnexion</button>
        )}
      </header>

      {data.connected === false ? (
        <div className="offline">
          Connexion à la passerelle impossible. Vérifiez qu'elle tourne et que le
          dashboard peut l'atteindre via <code>/_sentinel</code>.
        </div>
      ) : (
        <Outlet context={{ ...data, refresh }} />
      )}
    </div>
  )
}
