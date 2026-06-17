#!/bin/bash
# stop_services.sh — Para todos os servicos do projeto (Linux / macOS)

echo "[Stop] A procurar processo na porta 3000 (Juice Shop)..."

PID=$(lsof -ti tcp:3000 2>/dev/null)

if [ -n "$PID" ]; then
    echo "[Stop] A terminar PID $PID..."
    kill "$PID"
    echo "[Stop] Juice Shop terminado."
else
    echo "[Stop] Nenhum processo encontrado na porta 3000."
fi
