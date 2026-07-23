# hermes_security_agent

Two capabilities on **port 9000**:

1. **Document RAG** — Q&A over PDF/Word/FAQ (Chroma + embeddings)
2. **Nginx Error Log Analyzer** — enterprise incident report from `error.log` files

```text
Client → POST /v1/nginx/analyze   (upload error.log / error.log.1 / …)
       → stream parse → classify → group → prioritize → Markdown report

Client → POST /v1/chat
       → if body looks like nginx error.log → analyzer
       → else → document RAG
```

---

## Nginx Error Log Analyzer

Acts as Senior Linux / Nginx / PHP / DevOps / Security analyst.

### What it does

- Streams large logs (100MB+ friendly; no full load into LLM)
- Parses every line; groups identical/similar events
- Classifies (security scan, ModSecurity, PHP fatal/notice, upstream, SSL, OOM, …)
- Assigns severity: `INFO | LOW | MEDIUM | HIGH | CRITICAL`
- Explains root cause, business impact, recommended actions
- Confidence score 0–100%
- Executive **SERVER HEALTH REPORT** with overall score /100

### Rules of evidence

- No hallucination — only what appears in the logs
- Internet scanners (`/wp-admin`, `/.env`, `/phpmyadmin`, …) → **Security Scan / LOW** (not outages)
- ModSecurity denies → **ModSecurity Block / INFO** (successful blocks, not compromise)
- Attack attempt ≠ successful compromise ≠ app bug ≠ infrastructure fault

### API

| Method | Path | Role |
|--------|------|------|
| POST | `/v1/nginx/analyze` | Multipart upload of one or more log files |
| POST | `/v1/nginx/analyze/text` | JSON `{ "log_text": "..." }` |
| POST | `/v1/nginx/analyze/text/md` | Same → raw Markdown body |
| POST | `/v1/nginx/analyze/path` | JSON `{ "paths": ["/var/log/nginx/error.log"] }` |
| GET | `/v1/nginx/info` | Agent readiness |

### Examples

```bash
# Upload (multiple rotated logs)
curl -s -X POST http://127.0.0.1:9000/v1/nginx/analyze \
  -F "files=@error.log" \
  -F "files=@error.log.1" | jq .overall_health_score

# Local sample
python scripts/demo_nginx_analyze.py
# → logs/nginx_sample_report.md

# Paste logs into chat (Open WebUI / gateway)
curl -s -X POST http://127.0.0.1:9000/v1/chat \
  -H "Content-Type: application/json" \
  -d "{\"message\":\"$(cat data/samples/nginx_error_sample.log | head -c 5000)\"}"
```

### Hybrid: rules + LLM (not per-row)

```text
every log row  →  rules/tools (parse, classify, count)
grouped events →  LLM (optional) deepens root cause / impact / actions + executive narrative
```

| | Rules | LLM |
|--|-------|-----|
| Har bir qator | ✅ | ❌ |
| Guruh (kategoriya + ≤3 misol) | shablon | ✅ chuqur tahlil |
| Health score / counts | ✅ | o‘zgartirmaydi |

```env
OPENAI_API_KEY=...
LLM_MODEL=gpt-4.1
# default: on when API key is set
NGINX_ANALYZER_LLM=true
NGINX_ANALYZER_LLM_MAX_GROUPS=15
```

```bash
# rules only
python scripts/demo_nginx_analyze.py --no-llm

# force LLM enrichment
python scripts/demo_nginx_analyze.py --llm

# API
curl -s -X POST http://127.0.0.1:9000/v1/nginx/analyze/text \
  -H "Content-Type: application/json" \
  -d '{"log_text":"...","use_llm":true}'
```

---

## Document RAG

```env
APP_PORT=9000
OPENAI_API_KEY=...
LLM_MODEL=gpt-4.1

RAG_ENABLED=true
RAG_DOCS_DIR=./data/docs
RAG_CHROMA_ROOT=./data/rag/chroma
RAG_EMBED_PROVIDER=remote
RAG_EMBED_URL=http://host.docker.internal:8090
```

| Method | Path | Role |
|--------|------|------|
| POST | `/v1/chat` | RAG (or nginx if logs detected) |
| POST | `/v1/docs/chat` | Document RAG only |
| POST | `/v1/docs/reindex` | Rebuild Chroma |
| GET | `/ready` | Service ready |
| GET | `/health` | Liveness |

---

## Run

```bash
python -m app.main
# or
docker compose up -d --build
```

OpenAPI: http://127.0.0.1:9000/docs

---

## Layout

```text
agents/
  nginx_analyzer/     # error.log analyzer agent
    patterns.py       # signatures, severity, recommendations
    parser.py         # streaming line parser
    classifier.py     # group + prioritize
    report.py         # Markdown SERVER HEALTH REPORT
    service.py        # public service API
  rag_agent.py
  embeddings.py
  doc_structure.py
app/
  api.py
  main.py
data/samples/
  nginx_error_sample.log
scripts/
  demo_nginx_analyze.py
```
