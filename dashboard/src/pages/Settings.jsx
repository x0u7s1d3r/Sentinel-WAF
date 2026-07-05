import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api, CATEGORIES } from '../api.js'

export default function Settings() {
  const { settings, refresh } = useOutletContext()
  const [ipInput, setIpInput] = useState('')
  const s = settings || {}
  const enabled = new Set(s.enabled_categories || [])
  const blocklist = s.blocklist || []

  if (!settings) {
    return <div className="offline">Chargement des paramètres… (la persistance doit être active)</div>
  }

  async function setMode(mode) { await api.setSettings({ mode }); refresh() }
  async function setThreshold(threshold) { await api.setSettings({ threshold }); refresh() }
  async function toggleCat(cat) {
    const next = new Set(enabled)
    next.has(cat) ? next.delete(cat) : next.add(cat)
    await api.setSettings({ enabled_categories: [...next] })
    refresh()
  }
  async function addIp() {
    if (!ipInput.trim()) return
    await api.blocklist(ipInput.trim(), 'add'); setIpInput(''); refresh()
  }
  async function removeIp(ip) { await api.blocklist(ip, 'remove'); refresh() }

  return (
    <div className="settings">
      <div className="grid-2">
        {/* Mode + seuil */}
        <div className="card">
          <div className="card-h"><h3>Politique globale</h3></div>
          <div className="card-b">
            <div className="field">
              <div className="field-l">Mode de fonctionnement</div>
              <div className="seg big">
                <button className={`${s.mode === 'block' ? 'active block' : ''}`} onClick={() => setMode('block')}>Blocage</button>
                <button className={`${s.mode === 'detect' ? 'active detect' : ''}`} onClick={() => setMode('detect')}>Surveillance</button>
              </div>
              <div className="field-h">
                {s.mode === 'block'
                  ? 'Les attaques sont bloquées (403). Recommandé en production.'
                  : 'Les attaques sont détectées et journalisées, mais laissées passer.'}
              </div>
            </div>

            <div className="field">
              <div className="field-l">Seuil de blocage <b>{s.threshold}</b></div>
              <input type="range" min="1" max="12" value={s.threshold}
                onChange={(e) => setThreshold(Number(e.target.value))} className="slider" />
              <div className="field-h">
                Plus le seuil est bas, plus le WAF est strict (risque de faux positifs).
                Plus il est haut, plus il est permissif. Défaut : 4.
              </div>
            </div>
          </div>
        </div>

        {/* Blocklist */}
        <div className="card">
          <div className="card-h"><h3>Blocklist d'IP</h3><span className="hint">{blocklist.length} bannie{blocklist.length > 1 ? 's' : ''}</span></div>
          <div className="card-b">
            <div className="bl-input">
              <input value={ipInput} onChange={(e) => setIpInput(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addIp()} placeholder="203.0.113.9" />
              <button className="btn accent" onClick={addIp}>Bannir</button>
            </div>
            <div className="bl-list">
              {blocklist.length === 0 && <div className="hint">Aucune IP bannie.</div>}
              {blocklist.map((ip) => (
                <span className="chip" key={ip}>{ip}
                  <button onClick={() => removeIp(ip)} title="Débannir">×</button>
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Catégories */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h">
          <h3>Protections actives</h3>
          <span className="hint">{enabled.size}/{CATEGORIES.length} activées</span>
        </div>
        <div className="cat-grid">
          {CATEGORIES.map(([key, name, desc]) => (
            <div className={`cat-item ${enabled.has(key) ? 'on' : 'off'}`} key={key}>
              <div className="cat-txt">
                <div className="cat-n">{name}</div>
                <div className="cat-d">{desc}</div>
              </div>
              <button className={`sw ${enabled.has(key) ? 'on' : ''}`} onClick={() => toggleCat(key)}
                aria-label={`Activer ${name}`} />
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
