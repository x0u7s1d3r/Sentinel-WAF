#!/usr/bin/env bash
# Lance les trois composants du projet WAF.
# Usage :  ./run.sh
# Arrêt  :  Ctrl+C (arrête tout proprement)

set -e
cd "$(dirname "$0")"

# --- 1. Environnement Python ---
if [ ! -d ".venv" ]; then
  echo "==> Création de l'environnement Python…"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements.txt

# --- 2. Dépendances du dashboard ---
if [ ! -d "dashboard/node_modules" ]; then
  echo "==> Installation des dépendances du dashboard…"
  (cd dashboard && npm install --no-audit --no-fund)
fi

echo
echo "==================================================================="
echo "  Backend cible   : http://127.0.0.1:8000"
echo "  WAF (proxy)      : http://127.0.0.1:8080"
echo "  Dashboard        : http://127.0.0.1:5173   <-- OUVRIR ICI"
echo "==================================================================="
echo

# --- 3. Démarrage ---
pids=()
cleanup() { echo; echo "Arrêt…"; kill "${pids[@]}" 2>/dev/null || true; exit 0; }
trap cleanup INT TERM

( cd backend && uvicorn vulnerable_app:app --port 8000 ) & pids+=($!)
( cd waf     && uvicorn main:app --port 8080 )          & pids+=($!)
( cd dashboard && npm run dev )                          & pids+=($!)

wait
