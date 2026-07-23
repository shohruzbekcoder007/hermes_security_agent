#!/usr/bin/env bash
# Container entrypoint — document RAG service
set -euo pipefail

log() {
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [start] $*"
}

APP_HOME="${APP_HOME:-/app}"
export APP_HOME
export HR_APP_ROOT="${HR_APP_ROOT:-$APP_HOME}"
export LOG_DIR="${LOG_DIR:-$APP_HOME/logs}"
export PYTHONUNBUFFERED=1
export APP_PORT="${APP_PORT:-9000}"

mkdir -p "$LOG_DIR"

RAG_CHROMA_ROOT="${RAG_CHROMA_ROOT:-/home/appuser/.rag/chroma}"
mkdir -p "$RAG_CHROMA_ROOT" || true

# Named volumes often mount as root — fix ownership when we can (root entrypoint)
if [[ "$(id -u)" -eq 0 ]]; then
  chown -R appuser:appuser "$LOG_DIR" "$RAG_CHROMA_ROOT" 2>/dev/null || true
  chown -R appuser:appuser "$APP_HOME/data" 2>/dev/null || true
fi

log "Starting document RAG service"
log "APP_PORT=$APP_PORT RAG_CHROMA_ROOT=$RAG_CHROMA_ROOT LLM_MODEL=${LLM_MODEL:-} RAG_EMBED_PROVIDER=${RAG_EMBED_PROVIDER:-}"

cd "$APP_HOME"
if [[ "$(id -u)" -eq 0 ]]; then
  exec runuser -u appuser -- python -m app.main
fi
exec python -m app.main
