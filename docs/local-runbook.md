# Local Runbook

This runbook starts SecureShare locally with PostgreSQL, OpenFGA, Swagger UI, seed data, and smoke tests.

## Prerequisites

- Docker and Docker Compose
- UV

Install UV if needed:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 1. Install Python Dependencies

```bash
uv sync --extra dev
```

## 2. Start PostgreSQL And OpenFGA

```bash
docker compose up -d postgres openfga
```

Check containers:

```bash
docker compose ps
```

## 3. Bootstrap OpenFGA

The demo OpenFGA server starts without a store. Create a store and authorization model:

```bash
docker compose run --rm api python scripts/bootstrap_openfga.py
```

Copy the printed values into `.env`:

```env
SECURESHARE_OPENFGA_STORE_ID=<printed-store-id>
SECURESHARE_OPENFGA_AUTHORIZATION_MODEL_ID=<printed-authorization-model-id>
SECURESHARE_JWT_SECRET=dev-only-change-me-minimum-32-characters
SECURESHARE_MACAROON_ROOT_KEY=dev-macaroon-root-key-change-me
```

## 4. Start The API

```bash
docker compose up -d api
```

## 5. Run Migrations And Seed Data

```bash
docker compose exec api alembic upgrade head
docker compose exec api python scripts/seed.py
```

## 6. Open Swagger

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Raw OpenAPI JSON: `http://localhost:8000/openapi.json`
- Committed OpenAPI artifact: `docs/openapi.json`

## 7. Test Health Endpoints

Liveness:

```bash
curl http://localhost:8000/healthz
```

Expected:

```json
{
  "status": "ok",
  "service": "SecureShare",
  "version": "0.1.0"
}
```

Readiness:

```bash
curl -i http://localhost:8000/readyz
```

Expected HTTP `200` when PostgreSQL and OpenFGA are reachable. If either dependency is unavailable, the endpoint returns HTTP `503` with per-component details.

## 8. Login And Exercise Authorization

Login as Alice:

```bash
ALICE_TOKEN=$(curl -s http://localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"password123"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

Read Alice's seeded document:

```bash
curl http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $ALICE_TOKEN"
```

Login as Bob:

```bash
BOB_TOKEN=$(curl -s http://localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"bob@example.com","password":"password123"}' \
  | python -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
```

Bob can read but cannot edit:

```bash
curl -i http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $BOB_TOKEN"

curl -i -X PATCH http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $BOB_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"title":"Unauthorized edit"}'
```

Revoke Bob's viewer relationship:

```bash
curl -i -X DELETE http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/shares \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"subject_type":"user","subject_id":"00000000-0000-0000-0000-000000000002","role":"viewer"}'
```

Bob's existing JWT should now fail on the same read:

```bash
curl -i http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $BOB_TOKEN"
```

## 9. Run Tests

```bash
uv run pytest
```

## 10. Export OpenAPI JSON

After changing routes or schemas:

```bash
PYTHONPATH=apps/api uv run python scripts/export_openapi.py
```

