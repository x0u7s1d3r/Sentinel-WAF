import { useEffect, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { api } from './api.js'

// Le layout récupère les données et les partage aux pages via l'Outlet,
// en rafraîchissant toutes les 2 s pour un rendu « temps réel ».
export default function App() {
  const [data, setData] = useState({
    health: null, stats: null, events: [], apps: [], analytics: null, connected: null,
  })

  async function refresh() {
    try {
      const [health, stats, eventsRes, appsRes, analytics] = await Promise.all([
        api.health(), api.stats(), api.events(),
        api.apps().catch(() => ({ apps: [] })),
        api.analytics().catch(() => null),
      ])
      setData({
        health, stats,
        events: eventsRes.events || [],
        apps: appsRes.apps || [],
        analytics,
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
          <NavLink to="/" end>Vue d'ensemble</NavLink>
          <NavLink to="/supervision">Supervision</NavLink>
          <NavLink to="/applications">Applications</NavLink>
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
