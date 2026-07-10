// report.js — génération d'un rapport de sécurité PDF (côté navigateur).
import { jsPDF } from 'jspdf'
import autoTable from 'jspdf-autotable'
import { api } from './api.js'

const INK = [12, 21, 36]
const ACCENT = [44, 92, 224]
const TEAL = [15, 166, 120]
const CORAL = [229, 72, 77]
const MUTED = [90, 107, 130]

const CAT_LABEL = {
  sqli: 'Injection SQL', xss: 'XSS', path_traversal: 'Traversée de répertoire',
  cmd_injection: 'Injection de commande', ssrf: 'SSRF', nosql: 'Injection NoSQL',
  scanner: 'Scanner', sensitive_path: 'Chemin sensible', brute_force: 'Force brute',
}

function fmtDate(d) {
  return new Date(d).toLocaleString('fr-FR', { day: '2-digit', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

// Génère et télécharge le rapport. `range` = plage analytique (ex. '24h','7d').
export async function generateReport(range = '24h') {
  const [analytics, incidentsResp] = await Promise.all([
    api.analytics(range).catch(() => ({})),
    api.incidents().catch(() => ({ incidents: [] })),
  ])
  const incidents = incidentsResp.incidents || []

  const doc = new jsPDF({ unit: 'pt', format: 'a4' })
  const W = doc.internal.pageSize.getWidth()
  const M = 48
  let y = 0

  // ── Bandeau d'en-tête ──
  doc.setFillColor(...INK)
  doc.rect(0, 0, W, 96, 'F')
  doc.setFillColor(...ACCENT)
  doc.rect(0, 96, W, 4, 'F')
  doc.setTextColor(255, 255, 255)
  doc.setFont('helvetica', 'bold'); doc.setFontSize(22)
  doc.text('SENTINEL WAF', M, 46)
  doc.setFont('helvetica', 'normal'); doc.setFontSize(12)
  doc.setTextColor(180, 200, 240)
  doc.text('Rapport de sécurité', M, 68)
  doc.setFontSize(9); doc.setTextColor(150, 170, 210)
  const RANGE_LABEL = { '1h': 'dernière heure', '24h': 'dernières 24 heures', '72h': '3 derniers jours', '7d': '7 derniers jours', '30d': '30 derniers jours', 'all': 'historique complet' }
  doc.text('Période : ' + (RANGE_LABEL[range] || range), W - M, 46, { align: 'right' })
  doc.text('Généré le ' + fmtDate(Date.now()), W - M, 62, { align: 'right' })
  y = 128

  // ── Synthèse (KPIs) ──
  const verdicts = analytics.verdicts || {}
  const total = verdicts.total || 0
  const threat = analytics.threat_score || {}
  doc.setTextColor(...INK); doc.setFont('helvetica', 'bold'); doc.setFontSize(14)
  doc.text('Synthèse', M, y); y += 8

  const kpis = [
    ['Requêtes analysées', String(total), MUTED],
    ['Attaques bloquées', String(verdicts.blocked || 0), CORAL],
    ['En surveillance', String(verdicts.detected || 0), [224, 146, 10]],
    ['Trafic autorisé', String(verdicts.allowed || 0), TEAL],
  ]
  const cardW = (W - 2 * M - 3 * 12) / 4
  y += 10
  kpis.forEach((k, i) => {
    const x = M + i * (cardW + 12)
    doc.setFillColor(245, 248, 252); doc.roundedRect(x, y, cardW, 60, 6, 6, 'F')
    doc.setFontSize(20); doc.setTextColor(...k[2]); doc.setFont('helvetica', 'bold')
    doc.text(k[1], x + 12, y + 30)
    doc.setFontSize(8); doc.setTextColor(...MUTED); doc.setFont('helvetica', 'normal')
    doc.text(k[0], x + 12, y + 46)
  })
  y += 84

  // ── Niveau de menace ──
  if (threat.level) {
    doc.setFillColor(245, 248, 252); doc.roundedRect(M, y, W - 2 * M, 44, 6, 6, 'F')
    doc.setFont('helvetica', 'bold'); doc.setFontSize(11); doc.setTextColor(...INK)
    doc.text('Niveau de menace global', M + 14, y + 20)
    const lvl = threat.level.toUpperCase()
    const col = threat.gauge >= 70 ? CORAL : threat.gauge >= 40 ? [224, 146, 10] : TEAL
    doc.setFontSize(16); doc.setTextColor(...col)
    doc.text(`${lvl}  (${threat.gauge}/100)`, M + 14, y + 38)
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(...MUTED)
    doc.text(`Score moyen ${threat.avg} · maximum ${threat.max} · ${threat.attacks} attaque(s)`, W - M - 14, y + 30, { align: 'right' })
    y += 64
  }

  // ── Répartition par catégorie ──
  const byCat = analytics.by_category || []
  const catRows = byCat.map((x) => [CAT_LABEL[x.category] || x.category, String(x.count)])
  if (catRows.length) {
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(...INK)
    doc.text('Répartition des attaques par catégorie', M, y); y += 6
    autoTable(doc, {
      startY: y + 6, margin: { left: M, right: M },
      head: [['Catégorie', 'Occurrences']],
      body: catRows,
      headStyles: { fillColor: ACCENT, textColor: 255, fontStyle: 'bold', fontSize: 9 },
      bodyStyles: { fontSize: 9, textColor: INK },
      alternateRowStyles: { fillColor: [241, 245, 251] },
      styles: { cellPadding: 6, lineColor: [230, 236, 245], lineWidth: 0.5 },
    })
    y = doc.lastAutoTable.finalY + 24
  }

  // ── Top attaquants ──
  const topIps = analytics.top_ips || []
  if (topIps.length) {
    if (y > 640) { doc.addPage(); y = 60 }
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(...INK)
    doc.text('Principales sources d\'attaque', M, y); y += 6
    autoTable(doc, {
      startY: y + 6, margin: { left: M, right: M },
      head: [['Adresse IP', 'Attaques']],
      body: topIps.slice(0, 10).map((x) => [x.ip, String(x.attacks || x.total)]),
      headStyles: { fillColor: ACCENT, textColor: 255, fontStyle: 'bold', fontSize: 9 },
      bodyStyles: { fontSize: 9, textColor: INK, font: 'courier' },
      alternateRowStyles: { fillColor: [241, 245, 251] },
      styles: { cellPadding: 6, lineColor: [230, 236, 245], lineWidth: 0.5 },
    })
    y = doc.lastAutoTable.finalY + 24
  }

  // ── Incidents récents ──
  if (incidents.length) {
    if (y > 600) { doc.addPage(); y = 60 }
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(...INK)
    doc.text('Incidents récents', M, y); y += 6
    autoTable(doc, {
      startY: y + 6, margin: { left: M, right: M },
      head: [['Date', 'Criticité', 'Attaques', 'Applications', 'Catégories']],
      body: incidents.slice(0, 15).map((i) => [
        new Date(i.ts).toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }),
        i.severity, String(i.count), (i.apps || '—').slice(0, 30), (i.categories || '—').slice(0, 40),
      ]),
      headStyles: { fillColor: ACCENT, textColor: 255, fontStyle: 'bold', fontSize: 8 },
      bodyStyles: { fontSize: 8, textColor: INK },
      alternateRowStyles: { fillColor: [241, 245, 251] },
      styles: { cellPadding: 5, lineColor: [230, 236, 245], lineWidth: 0.5 },
      columnStyles: { 0: { cellWidth: 70 }, 1: { cellWidth: 62 }, 2: { cellWidth: 48 } },
    })
    y = doc.lastAutoTable.finalY + 24
  }

  // ── Analyse IA globale (dernière analyse disponible) ──
  const ai = analytics.ai_analysis
  if (ai && ai.text) {
    if (y > 620) { doc.addPage(); y = 60 }
    doc.setFont('helvetica', 'bold'); doc.setFontSize(12); doc.setTextColor(...ACCENT)
    doc.text('Analyse IA la plus récente', M, y); y += 16
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9); doc.setTextColor(...INK)
    const lines = doc.splitTextToSize(ai.text, W - 2 * M)
    doc.text(lines, M, y)
    y += lines.length * 12 + 10
  }

  // ── Pied de page sur chaque page ──
  const pages = doc.internal.getNumberOfPages()
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p)
    doc.setDrawColor(230, 236, 245); doc.line(M, 812, W - M, 812)
    doc.setFontSize(8); doc.setTextColor(...MUTED); doc.setFont('helvetica', 'normal')
    doc.text('Sentinel WAF — Rapport de sécurité confidentiel', M, 826)
    doc.text(`Page ${p} / ${pages}`, W - M, 826, { align: 'right' })
  }

  const stamp = new Date().toISOString().slice(0, 10)
  doc.save(`Rapport_Securite_Sentinel_${stamp}.pdf`)
}
