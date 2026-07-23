# Install — document RAG

1. `cp .env.example .env` and set `OPENAI_API_KEY`, `LLM_MODEL=gpt-4.1`
2. Configure embeddings (`RAG_EMBED_PROVIDER`, `RAG_EMBED_URL` or openai/local)
3. `pip install -r requirements.txt` **or** `docker compose build && docker compose up -d`
4. Put documents in `data/docs/`
5. `curl http://127.0.0.1:9000/ready`
6. `POST /v1/docs/reindex` then `POST /v1/chat` with `{"message":"..."}`

Prompt file: `prompts/rag_agent_system.md`. Default port: **9000**.
