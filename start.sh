#!/usr/bin/env bash
#
# start.sh — Démarrage clé en main de Sentinel WAF.
#
# Usage :  ./start.sh
#
# Ce script vérifie les prérequis, prépare la configuration, construit les
# images et démarre l'ensemble. Il est idempotent : on peut le relancer.

set -euo pipefail

# ── Couleurs (dégradation propre si le terminal ne les gère pas) ──
if [ -t 1 ]; then
  B="\033[1m"; G="\033[32m"; Y="\033[33m"; R="\033[31m"; C="\033[36m"; N="\033[0m"
else
  B=""; G=""; Y=""; R=""; C=""; N=""
fi
say()  { printf "%b\n" "$1"; }
ok()   { printf "%b\n" "${G}✓${N} $1"; }
warn() { printf "%b\n" "${Y}!${N} $1"; }
err()  { printf "%b\n" "${R}✗${N} $1" >&2; }

cd "$(dirname "$0")"

say "${B}${C}"
say "  ╔══════════════════════════════════════╗"
say "  ║        Sentinel WAF — Démarrage       ║"
say "  ╚══════════════════════════════════════╝"
say "${N}"

# ── 1. Docker présent ? ──
if ! command -v docker >/dev/null 2>&1; then
  err "Docker n'est pas installé."
  say "  Installez-le : ${C}https://docs.docker.com/engine/install/${N}"
  exit 1
fi
ok "Docker détecté"

# ── 2. Choisir la commande compose (plugin v2 ou binaire v1) ──
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  err "Docker Compose introuvable (ni « docker compose », ni « docker-compose »)."
  say "  Voir : ${C}https://docs.docker.com/compose/install/${N}"
  exit 1
fi
ok "Docker Compose détecté ($DC)"

# ── 3. Le démon Docker répond-il ? (droits/permission) ──
if ! docker info >/dev/null 2>&1; then
  err "Impossible de contacter le démon Docker."
  say "  • Démarrez Docker, ou"
  say "  • Ajoutez votre utilisateur au groupe docker :"
  say "      ${C}sudo usermod -aG docker \$USER${N}  puis reconnectez-vous,"
  say "  • ou relancez ce script avec ${C}sudo ./start.sh${N}"
  exit 1
fi
ok "Démon Docker opérationnel"

# ── 4. Préparer le fichier .env ──
if [ ! -f .env ]; then
  cp .env.example .env
  ok "Fichier .env créé depuis .env.example"
  warn "Pensez à définir un mot de passe admin (SENTINEL_ADMIN_PASSWORD) dans .env,"
  warn "ou vous le ferez au premier lancement depuis la console web."
else
  ok "Fichier .env présent (conservé)"
fi

# ── 5. Avertissement AppArmor sur machine virtuelle ──
# Sur certaines VM (Docker installé via snap), AppArmor peut empêcher Docker
# d'arrêter/redémarrer des conteneurs. On se contente d'avertir, sans modifier
# le système sans consentement.
if command -v systemd-detect-virt >/dev/null 2>&1 && [ "$(systemd-detect-virt 2>/dev/null || echo none)" != "none" ]; then
  if docker info 2>/dev/null | grep -qi apparmor; then
    warn "Machine virtuelle + AppArmor détectés."
    warn "Si des conteneurs refusent de s'arrêter (« permission denied »), voir la"
    warn "section « Dépannage » du README (override AppArmor de Docker)."
  fi
fi

# ── 6. Construire et démarrer ──
say ""
say "${B}Construction des images et démarrage…${N} (peut prendre 1-2 min la 1re fois)"
$DC up -d --build

# ── 7. Attendre que la passerelle soit saine ──
PORT="$(grep -E '^SENTINEL_HTTP_PORT=' .env 2>/dev/null | cut -d= -f2)"
PORT="${PORT:-8000}"
say ""
printf "Attente de la passerelle "
for i in $(seq 1 30); do
  if curl -fsS "http://localhost:${PORT}/_sentinel/health" >/dev/null 2>&1; then
    printf "\n"; ok "Passerelle opérationnelle"
    break
  fi
  printf "."; sleep 2
  if [ "$i" -eq 30 ]; then
    printf "\n"; warn "La passerelle met du temps à répondre. Vérifiez : ${C}$DC logs gateway${N}"
  fi
done

DASH="$(grep -E '^SENTINEL_DASHBOARD_PORT=' .env 2>/dev/null | cut -d= -f2)"
DASH="${DASH:-3000}"

# ── 8. Récapitulatif ──
say ""
say "${G}${B}Sentinel WAF est démarré.${N}"
say ""
say "  ${B}Console d'administration${N} : ${C}http://localhost:${DASH}${N}"
say "  ${B}Passerelle WAF (proxy)${N}   : ${C}http://localhost:${PORT}${N}"
say ""
say "  Première visite : créez votre compte administrateur dans la console."
say "  Ajoutez vos applications à protéger depuis l'onglet « Applications »."
say ""
say "  Commandes utiles :"
say "    • Voir les logs   : ${C}$DC logs -f gateway${N}"
say "    • Arrêter         : ${C}$DC down${N}"
say "    • Redémarrer      : ${C}./start.sh${N}"
say ""
