import { useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api, CATEGORIES } from '../api.js'

export default function Settings() {
  const { settings, refresh } = useOutletContext()
  const [ipInput, setIpInput] = useState('')
  const [webhook, setWebhook] = useState('')
  const [slackMsg, setSlackMsg] = useState(null)
  const [slackBusy, setSlackBusy] = useState(false)
  const [discordHook, setDiscordHook] = useState('')
  const [discordMsg, setDiscordMsg] = useState(null)
  const [discordBusy, setDiscordBusy] = useState(false)
  const [llmUrl, setLlmUrl] = useState('')
  const [llmModel, setLlmModel] = useState('')
  const [llmKey, setLlmKey] = useState('')
  const [llmMsg, setLlmMsg] = useState(null)
  const [llmBusy, setLlmBusy] = useState(false)
  const [pwOld, setPwOld] = useState('')
  const [pwNew, setPwNew] = useState('')
  const [pwConfirm, setPwConfirm] = useState('')
  const [pwMsg, setPwMsg] = useState(null)
  const [pwBusy, setPwBusy] = useState(false)
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

  async function saveWebhook() {
    setSlackBusy(true); setSlackMsg(null)
    try {
      await api.setSettings({ slack_webhook: webhook.trim() })
      setWebhook('')
      setSlackMsg({ ok: true, text: webhook.trim() ? 'Webhook enregistré.' : 'Webhook retiré.' })
      refresh()
    } catch (e) {
      setSlackMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setSlackBusy(false) }
  }
  async function testSlack() {
    setSlackBusy(true); setSlackMsg(null)
    try {
      const r = await api.slackTest()
      setSlackMsg(r.ok
        ? { ok: true, text: 'Message de test envoyé ✅ Vérifiez votre canal Slack.' }
        : { ok: false, text: r.error || 'Échec de l’envoi.' })
    } catch (e) {
      setSlackMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setSlackBusy(false) }
  }

  async function saveDiscord() {
    setDiscordBusy(true); setDiscordMsg(null)
    try {
      await api.setSettings({ discord_webhook: discordHook.trim() })
      setDiscordHook('')
      setDiscordMsg({ ok: true, text: discordHook.trim() ? 'Webhook enregistré.' : 'Webhook retiré.' })
      refresh()
    } catch (e) {
      setDiscordMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setDiscordBusy(false) }
  }
  async function testDiscord() {
    setDiscordBusy(true); setDiscordMsg(null)
    try {
      const r = await api.discordTest()
      setDiscordMsg(r.ok
        ? { ok: true, text: 'Message de test envoyé ✅ Vérifiez votre salon Discord.' }
        : { ok: false, text: r.error || 'Échec de l’envoi.' })
    } catch (e) {
      setDiscordMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setDiscordBusy(false) }
  }

  async function saveLlm(enabled) {
    setLlmBusy(true); setLlmMsg(null)
    try {
      const body = { llm_enabled: enabled }
      if (llmUrl.trim()) body.llm_base_url = llmUrl.trim()
      if (llmModel.trim()) body.llm_model = llmModel.trim()
      if (llmKey.trim()) body.llm_api_key = llmKey.trim()
      await api.setSettings(body)
      setLlmKey('')
      setLlmMsg({ ok: true, text: enabled ? 'Configuration enregistrée.' : 'Enrichissement désactivé.' })
      refresh()
    } catch (e) {
      setLlmMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setLlmBusy(false) }
  }
  async function testLlm() {
    setLlmBusy(true); setLlmMsg(null)
    try {
      const r = await api.llmTest()
      setLlmMsg(r.ok
        ? { ok: true, text: 'Analyse de test réussie ✅ L’IA répond correctement.' }
        : { ok: false, text: 'Échec : ' + (r.error || 'vérifiez la clé, l’URL et le crédit.') })
    } catch (e) {
      setLlmMsg({ ok: false, text: String(e.message || e).slice(0, 140) })
    } finally { setLlmBusy(false) }
  }

  async function changePassword() {
    setPwMsg(null)
    if (pwNew.length < 6) { setPwMsg({ ok: false, text: '6 caractères minimum.' }); return }
    if (pwNew !== pwConfirm) { setPwMsg({ ok: false, text: 'La confirmation ne correspond pas.' }); return }
    setPwBusy(true)
    try {
      await api.changePassword(pwOld, pwNew)
      setPwOld(''); setPwNew(''); setPwConfirm('')
      setPwMsg({ ok: true, text: 'Mot de passe modifié.' })
    } catch (e) {
      setPwMsg({ ok: false, text: e.status === 401 ? 'Mot de passe actuel incorrect.' : String(e.message || e).slice(0, 140) })
    } finally { setPwBusy(false) }
  }

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
      {/* Alertes Slack */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h">
          <h3>Alertes Slack</h3>
          <span className={`hint ${s.slack_webhook_set ? 'ok-hint' : ''}`}>
            {s.slack_webhook_set ? '● Configuré' : '○ Non configuré'}
          </span>
        </div>
        <div className="card-b">
          <div className="field-h" style={{ marginTop: 0, marginBottom: 12 }}>
            Recevez un résumé des attaques dans votre canal Slack. Créez un
            « Incoming Webhook » sur api.slack.com/apps, puis collez son URL ici.
            {s.slack_webhook_set && ' Un webhook est déjà enregistré ; saisissez-en un nouveau pour le remplacer, ou laissez vide et enregistrez pour le retirer.'}
          </div>
          <div className="bl-input">
            <input type="password" value={webhook} onChange={(e) => setWebhook(e.target.value)}
              placeholder={s.slack_webhook_set ? '•••••••• (webhook enregistré)' : 'https://hooks.slack.com/services/…'} />
            <button className="btn accent" onClick={saveWebhook} disabled={slackBusy}>Enregistrer</button>
            <button className="btn" onClick={testSlack} disabled={slackBusy || !s.slack_webhook_set}>Tester</button>
          </div>
          {slackMsg && (
            <div style={{ fontSize: 12, marginTop: 10, color: slackMsg.ok ? 'var(--safe)' : 'var(--threat)' }}>
              {slackMsg.text}
            </div>
          )}
        </div>
      </div>

      {/* Alertes Discord */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h">
          <h3>Alertes Discord</h3>
          <span className={`hint ${s.discord_webhook_set ? 'ok-hint' : ''}`}>
            {s.discord_webhook_set ? '● Configuré' : '○ Non configuré'}
          </span>
        </div>
        <div className="card-b">
          <div className="field-h" style={{ marginTop: 0, marginBottom: 12 }}>
            Recevez le même résumé d'attaques dans un salon Discord. Dans votre
            salon : Paramètres → Intégrations → Webhooks → « Nouveau webhook »,
            puis copiez l'URL ici. Slack et Discord peuvent être actifs ensemble.
            {s.discord_webhook_set && ' Un webhook est déjà enregistré ; saisissez-en un nouveau pour le remplacer, ou laissez vide et enregistrez pour le retirer.'}
          </div>
          <div className="bl-input">
            <input type="password" value={discordHook} onChange={(e) => setDiscordHook(e.target.value)}
              placeholder={s.discord_webhook_set ? '•••••••• (webhook enregistré)' : 'https://discord.com/api/webhooks/…'} />
            <button className="btn accent" onClick={saveDiscord} disabled={discordBusy}>Enregistrer</button>
            <button className="btn" onClick={testDiscord} disabled={discordBusy || !s.discord_webhook_set}>Tester</button>
          </div>
          {discordMsg && (
            <div style={{ fontSize: 12, marginTop: 10, color: discordMsg.ok ? 'var(--safe)' : 'var(--threat)' }}>
              {discordMsg.text}
            </div>
          )}
        </div>
      </div>

      {/* Enrichissement IA */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h">
          <h3>Enrichissement IA</h3>
          <span className={`hint ${s.llm_enabled && s.llm_key_set ? 'ok-hint' : ''}`}>
            {s.llm_enabled && s.llm_key_set ? '● Actif' : (s.llm_key_set ? '○ Configuré (désactivé)' : '○ Non configuré')}
          </span>
        </div>
        <div className="card-b">
          <div className="field-h" style={{ marginTop: 0, marginBottom: 12 }}>
            Ajoute à chaque alerte une analyse en langage naturel rédigée par une IA
            (nature de l'attaque, risque, recommandation). Compatible avec toute API
            de type OpenAI : Groq (gratuit), RodiumAI, OpenAI, Ollama… La clé reste
            secrète (jamais réaffichée).
          </div>
          <div className="form">
            <div className="full">
              <label>URL de base de l'API</label>
              <input type="text" value={llmUrl} onChange={(e) => setLlmUrl(e.target.value)}
                placeholder={s.llm_base_url || 'https://api.groq.com/openai/v1'} />
            </div>
            <div className="full">
              <label>Modèle</label>
              <input type="text" value={llmModel} onChange={(e) => setLlmModel(e.target.value)}
                placeholder={s.llm_model || 'llama-3.3-70b-versatile'} />
            </div>
            <div className="full">
              <label>Clé API {s.llm_key_set && <span className="hint ok-hint">(enregistrée)</span>}</label>
              <input type="password" value={llmKey} onChange={(e) => setLlmKey(e.target.value)}
                placeholder={s.llm_key_set ? '•••••••• (clé enregistrée)' : 'gsk_… / sk-… / rd_sk_…'} />
            </div>
            {llmMsg && (
              <div className="full" style={{ fontSize: 12, color: llmMsg.ok ? 'var(--safe)' : 'var(--threat)' }}>{llmMsg.text}</div>
            )}
            <div className="full" style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button className="btn accent" onClick={() => saveLlm(true)} disabled={llmBusy}>Enregistrer &amp; activer</button>
              <button className="btn" onClick={testLlm} disabled={llmBusy || !s.llm_key_set}>Tester</button>
              {s.llm_enabled && (
                <button className="btn" onClick={() => saveLlm(false)} disabled={llmBusy}>Désactiver</button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Compte administrateur */}
      <div className="card" style={{ marginTop: 18 }}>
        <div className="card-h"><h3>Compte administrateur</h3></div>
        <div className="card-b">
          <div className="field-h" style={{ marginTop: 0, marginBottom: 12 }}>
            Changez le mot de passe de la console. L'ancien mot de passe est requis.
          </div>
          <div className="form">
            <div className="full">
              <label>Mot de passe actuel</label>
              <input type="password" value={pwOld} onChange={(e) => setPwOld(e.target.value)} placeholder="••••••••" />
            </div>
            <div>
              <label>Nouveau mot de passe</label>
              <input type="password" value={pwNew} onChange={(e) => setPwNew(e.target.value)} placeholder="6 caractères min." />
            </div>
            <div>
              <label>Confirmer</label>
              <input type="password" value={pwConfirm} onChange={(e) => setPwConfirm(e.target.value)} placeholder="Répéter" />
            </div>
            {pwMsg && (
              <div className="full" style={{ fontSize: 12, color: pwMsg.ok ? 'var(--safe)' : 'var(--threat)' }}>{pwMsg.text}</div>
            )}
            <div className="full">
              <button className="btn accent" onClick={changePassword} disabled={pwBusy}>
                {pwBusy ? 'Modification…' : 'Changer le mot de passe'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
