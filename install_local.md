# Local install — document RAG

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
# set OPENAI_API_KEY and RAG_EMBED_* in .env
python -m app.main
```

Open http://127.0.0.1:9000/docs

Only the document RAG agent is registered. Port **9000**.
