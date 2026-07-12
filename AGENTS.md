# Home Mesh Agent Notes

## Knowledge Base

Use `$maintain-llm-wiki` for tasks that ingest, query, lint, or restructure the
project knowledge base.

- Keep `.documentation/currentState` private and ignored; it contains local
  runtime evidence and must not be committed or copied into public docs without
  sanitization.
- Treat source code, tests, and reproducible runtime evidence as higher
  authority than older prose.
- Never place credentials, tokens, private keys, `.env` values, databases, or
  machine-specific secrets in tracked knowledge pages.
- When durable project behavior changes, update the relevant sanitized wiki
  page, its source references, index, and append-only log in the same change
  when that tracked wiki exists; otherwise record the missing structure rather
  than inventing a parallel document set.
