# SecureShare

SecureShare is a small production-style reference app for secure multi-tenant document sharing. It keeps identity, authorization, and delegation deliberately separate:

- JWTs contain identity claims only.
- FastAPI dependencies act as policy enforcement points.
- OpenFGA is the primary policy decision point for relationship checks.
- Macaroon-style tokens provide attenuated temporary read access.
- PostgreSQL stores application data and authorization audit logs.

## What Is Included

- FastAPI backend under `apps/api`
- SQLAlchemy models and Alembic migration
- OpenFGA model and seed tuples under `infra/openfga`
- Docker Compose for PostgreSQL, OpenFGA, and the API
- Pytest suite for critical authorization failures
- Threat model, architecture notes, developer guide, and sample API collection

## Developer Docs

- [Architecture](docs/architecture.md)
- [Developer guide](docs/developer-guide.md)
- [Local runbook](docs/local-runbook.md)
- [Threat model](docs/threat-model.md)
- [Database-layer authorization](docs/database-authorization.md)
- [API contracts](docs/api-contracts.md)
- [Attack scenarios](docs/attack-scenarios.md)

## Local Run

1. Create a local `.env` with unique development secrets:

   ```env
   SECURESHARE_ENVIRONMENT=dev
   SECURESHARE_OPENFGA_PRESHARED_KEY=replace-with-a-random-32-plus-character-value
   SECURESHARE_JWT_SECRET=replace-with-a-random-32-plus-character-value
   SECURESHARE_MACAROON_ROOT_KEY=replace-with-a-random-32-plus-character-value
   ```

2. Start infrastructure:

   ```bash
   docker compose up -d postgres openfga
   ```

3. Bootstrap OpenFGA and copy the printed values into `.env`:

   ```bash
   docker compose run --rm api python scripts/bootstrap_openfga.py
   ```

   Example `.env`:

   ```env
   SECURESHARE_OPENFGA_STORE_ID=replace-with-printed-store-id
   SECURESHARE_OPENFGA_AUTHORIZATION_MODEL_ID=replace-with-printed-model-id
   ```

4. Start the API with the populated environment:

   ```bash
   docker compose up -d api
   ```

5. Run migrations and seed demo data:

   ```bash
   docker compose exec api alembic upgrade head
   docker compose exec api python scripts/seed.py
   ```

6. Open the API:

   - Health: `http://localhost:8000/healthz`
   - Readiness: `http://localhost:8000/readyz`
   - OpenAPI docs: `http://localhost:8000/docs`
   - ReDoc: `http://localhost:8000/redoc`
   - Raw OpenAPI JSON: `http://localhost:8000/openapi.json`

## Demo Accounts

All demo users use password `password123`.

| User | Tenant | Demo role |
| --- | --- | --- |
| `alice@example.com` | Acme | Owner of Acme document |
| `bob@example.com` | Acme | Viewer of Acme document |
| `eve@example.net` | Globex | Owner of Globex document |

Seed documents:

- Acme document: `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
- Globex document: `bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb`

## Demo Scenarios

Login as Alice:

```bash
curl -s http://localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"password123"}'
```

Read Alice's document with the returned bearer token:

```bash
curl http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $ALICE_TOKEN"
```

Try Bob editing Alice's document. It should fail because Bob is only a viewer:

```bash
curl -X PATCH http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "authorization: Bearer $BOB_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"title":"Unauthorized edit"}'
```

Revoke Bob's viewer relationship. Bob's existing JWT will immediately stop working for the document because authorization is not embedded in the JWT:

```bash
curl -X DELETE http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/shares \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"subject_type":"user","subject_id":"00000000-0000-0000-0000-000000000002","role":"viewer"}'
```

Create a delegated read token:

```bash
curl -X POST http://localhost:8000/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/shares/delegated-link \
  -H "authorization: Bearer $ALICE_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"expires_in_seconds":300}'
```

Delegated links are automatically bound to the caller IP unless an explicit `ip_address` caveat is provided.

Read through delegated access:

```bash
curl http://localhost:8000/delegated/documents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa \
  -H "x-delegation-token: $DELEGATION_TOKEN"
```

Inspect audit logs as tenant admin:

```bash
curl http://localhost:8000/audit -H "authorization: Bearer $ALICE_TOKEN"
```

## Tests

From the repository root:

```bash
uv sync --extra dev
uv run pytest
```

The tests use SQLite and a fake relationship client to verify application enforcement quickly. Docker Compose is used for the full PostgreSQL and OpenFGA runtime.

## Dependency And CI Automation

SecureShare includes both Dependabot and Renovate configuration:

- Dependabot updates Python dependencies, Docker images, Docker Compose images, and GitHub Actions.
- Dependabot applies dependency cooldowns to version updates: 14 days for major, 7 days for minor, and 3 days for patch updates. GitHub Actions patch updates use a 2-day cooldown.
- Renovate provides grouped dependency PRs and a dependency dashboard.
- Renovate uses `minimumReleaseAge` with strict internal checks, so branches and PRs wait until releases are old enough. Major updates wait 14 days, minor updates wait 7 days, patch updates wait 3 days, and Docker image updates wait 7 days.

GitHub Actions CI uses UV, validates Docker Compose, runs tests, uploads JUnit/source artifacts, and signs source artifacts on non-PR events with Sigstore keyless signing through Cosign.
It also generates a CycloneDX SBOM, runs Trivy vulnerability checks against both the source tree and the built API container image, uploads SARIF reports to GitHub code scanning on push events, and includes the SBOM plus scan reports in the CI artifact bundle. High and critical source or image findings fail the workflow unless they are unfixed upstream findings ignored by the scanner configuration.

## Known Gaps

- Local JWT issuing is for development only. Replace it with a real IdP for production.
- The local stack now uses a durable Postgres-backed OpenFGA datastore, but production still needs backup, retention, and operational monitoring around the relationship store.
- Delegated tokens are read-only in v1 and are constrained by live issuer authorization at read time.
- Authorization repair jobs are queued when compensating OpenFGA cleanup fails; production should run `scripts/process_authz_repair_jobs.py` on a schedule or worker.
- Local Docker Compose requires explicit unique secrets and an OpenFGA preshared key in `.env`. Bare `docker compose up` no longer falls back to public demo credentials.
