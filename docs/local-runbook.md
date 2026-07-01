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

## 2. Create Local Secrets

Create a `.env` file before starting the stack:

```env
SECURESHARE_ENVIRONMENT=dev
SECURESHARE_OPENFGA_PRESHARED_KEY=<random-32-plus-character-value>
SECURESHARE_JWT_SECRET=<random-32-plus-character-value>
SECURESHARE_MACAROON_ROOT_KEY=<random-32-plus-character-value>
```

The API no longer accepts the published demo defaults. In `dev`, omitted secrets are generated ephemerally for in-process runs, but Docker Compose requires explicit values so restarts stay predictable and OpenFGA auth stays aligned.

## 3. Start PostgreSQL And OpenFGA

```bash
docker compose up -d postgres openfga
```

On first boot, PostgreSQL creates a dedicated `openfga` database and the `openfga-migrate` service prepares the OpenFGA schema before the API starts talking to the PDP.

Check containers:

```bash
docker compose ps
```

## 4. Bootstrap OpenFGA

The demo OpenFGA server starts without a store. Create a store and authorization model:

```bash
docker compose run --rm api python scripts/bootstrap_openfga.py
```

Copy the printed values into `.env`:

```env
SECURESHARE_OPENFGA_STORE_ID=<printed-store-id>
SECURESHARE_OPENFGA_AUTHORIZATION_MODEL_ID=<printed-authorization-model-id>
```

## 5. Start The API

```bash
docker compose up -d api
```

## 6. Run Migrations And Seed Data

```bash
docker compose exec api alembic upgrade head
docker compose exec api python scripts/seed.py
```

## 7. Open Swagger

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Raw OpenAPI JSON: `http://localhost:8000/openapi.json`
- Committed OpenAPI artifact: `docs/openapi.json`

## 8. Test Health Endpoints

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

## 9. Login And Exercise Authorization

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

Cross-tenant shares are rejected, and `owner` is no longer a generic share role in v1.

Bob's existing JWT should now fail on the same read:

```bash
curl -i http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $BOB_TOKEN"
```

Delegated links are always bound to the issuing caller IP. If you provide `ip_address`, it must match the observed caller IP.

Revoke the current JWT family:

```bash
curl -i -X POST http://localhost:8000/auth/logout \
  -H "authorization: Bearer $ALICE_TOKEN"
```

Inspect audit logs as tenant admin:

```bash
curl http://localhost:8000/audit \
  -H "authorization: Bearer $ALICE_TOKEN"
```

Bob should receive `403 Tenant admin access required` on the same endpoint.

## 10. Run Tests

```bash
uv run pytest
```

## 11. Export OpenAPI JSON

After changing routes or schemas:

```bash
PYTHONPATH=apps/api uv run python scripts/export_openapi.py
```

## 12. Process Authorization Repair Jobs

If OpenFGA cleanup fails during a rolled-back write, SecureShare queues a repair job in PostgreSQL:

```bash
PYTHONPATH=apps/api uv run python scripts/process_authz_repair_jobs.py
```
