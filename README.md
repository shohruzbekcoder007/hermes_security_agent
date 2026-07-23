# hermes_security_agent — document RAG only

```text
Client → POST /v1/chat  (or /v1/docs/chat)
       → RAG agent → Chroma (PDF / Word / FAQ) + LLM answer
```

SQL, Hermes host, and self-improve stacks have been removed. Only the document RAG agent remains.

## Configure

```env
APP_PORT=9000
OPENAI_API_KEY=...
LLM_MODEL=gpt-4.1

RAG_ENABLED=true
RAG_DOCS_DIR=./data/docs
RAG_CHROMA_ROOT=./data/rag/chroma

# Preferred: remote embedding-service
RAG_EMBED_PROVIDER=remote
RAG_EMBED_URL=http://host.docker.internal:8090

# In-process fallback:
# RAG_EMBED_PROVIDER=openai
# RAG_EMBED_MODEL=text-embedding-3-small
# Local bge-m3: RAG_EMBED_PROVIDER=local + requirements-rag-local.txt
```

## Run

```bash
# local
python -m app.main

# docker
docker compose up -d --build
```

Listens on **port 9000** by default.

## API

| Method | Path | Role |
|--------|------|------|
| POST | `/v1/chat` | Document RAG Q&A (gateway-compatible) |
| POST | `/v1/docs/chat` | Same RAG path |
| POST | `/v1/docs/reindex` | Rebuild Chroma for current embed identity |
| GET | `/ready` | RAG ready |
| GET | `/health` | Liveness |
| GET | `/v1/info` | Service metadata |
| GET | `/v1/docs/ready` | RAG ready |
| GET | `/v1/docs/info` | RAG config + stats |
| GET | `/v1/docs/files` | Files under `RAG_DOCS_DIR` |

## Document workflow

1. Put PDF / DOCX / MD / TXT into `data/docs/` (Docker volume `./data`).
2. `POST /v1/docs/reindex` (bearer required if `API_BEARER_TOKEN` set).
3. Ask via `POST /v1/chat` or `POST /v1/docs/chat`.

## Layout

```text
agents/
  rag_agent.py       # document RAG
  embeddings.py      # remote / openai / local embeddings
  doc_structure.py   # structure detection (bob/modda, etc.)
app/
  api.py             # FastAPI
  main.py            # uvicorn entry (port 9000)
prompts/
  rag_agent_system.md
data/docs/           # source documents
```
