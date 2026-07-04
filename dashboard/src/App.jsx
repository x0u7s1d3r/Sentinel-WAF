import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { api } from './api.js'

// Le layout récupère les données une fois pour toutes et les partage aux pages
// via le contexte du routeur (Outlet), en les rafraîchissant toutes les 2 s.
export default function App() {
  const [data, setData] = useState({
    health: null, stats: null, events: [], apps: [], connected: null,
  })

  async function refresh() {
    try {
      const [health, stats, eventsRes, appsRes] = await Promise.all([
        api.health(), api.stats(), api.events(), api.apps().catch(() => ({ apps: [] })),
      ])
      setData({
        health, stats,
        events: eventsRes.events || [],
        apps: appsRes.apps || [],
        connected: true,
      })
    } catch {
      setData((d) => ({ ...d, connected: false }))
    }
  }

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 2000)
    return () => clearInterval(id)
  }, [])

  const mode = data.health?.mode || 'block'

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <div className="mark">S</div>
          <div className="name">Sentinel <span>WAF</span></div>
        </div>
        <nav className="nav">
          <NavLink to="/" end>État du site</NavLink>
          <NavLink to="/technique">Console technique</NavLink>
        </nav>
        <div className="spacer" />
        <div className={`mode-badge ${mode === 'detect' ? 'detect' : ''}`}>
          <span className="dot" />
          {mode === 'block' ? 'Mode blocage' : 'Mode surveillance'}
        </div>
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
