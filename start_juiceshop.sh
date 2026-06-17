#!/bin/bash
# start_juiceshop.sh — Arranca o OWASP Juice Shop (Linux / macOS)
# Requisito: setup_juiceshop.bat (ou equivalente) ja ter sido executado.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JUICE_DIR="$SCRIPT_DIR/../juice-shop"

if [ ! -f "$JUICE_DIR/app.ts" ]; then
    echo "ERRO: Juice Shop nao encontrado em $JUICE_DIR"
    echo "Corre primeiro o setup (ver README.md)"
    exit 1
fi

echo "[Start] A arrancar o Juice Shop em background..."
cd "$JUICE_DIR"
npx tsx app.ts &
echo "[Start] PID: $!"
echo "[Start] Disponivel em: http://localhost:3000"
echo "[Start] Para parar: ./stop_services.sh"
