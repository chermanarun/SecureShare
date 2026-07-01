import logging

from fastapi import FastAPI

from app.middleware.pep import RequestContextMiddleware
from app.routers import audit, auth, delegated, documents, health, shares

DESCRIPTION = """
SecureShare is a production-style reference API for secure multi-tenant document sharing.

Core security properties:

* JWTs carry identity only, never document permissions.
* FastAPI routers and dependencies act as policy enforcement points.
* OpenFGA is the relationship-based policy decision point for document access.
* Macaroon-style delegated links provide temporary, attenuated read access.
* Every allow and deny authorization decision is written to the audit log.

Demo users all use password `password123`:

* `alice@example.com` owns the Acme document.
* `bob@example.com` can view the Acme document.
* `eve@example.net` owns the Globex document in another tenant.
"""

TAGS_METADATA = [
    {
        "name": "health",
        "description": "Liveness and readiness endpoints for smoke tests, local checks, and deployment probes.",
    },
    {
        "name": "auth",
        "description": "Development-only local JWT issuer. Tokens contain identity claims only.",
    },
    {
        "name": "documents",
        "description": "Document create, read, edit, and relationship inspection endpoints protected by OpenFGA checks.",
    },
    {
        "name": "shares",
        "description": "Relationship grant, revoke, and delegated-link issuance endpoints. Sharing requires `can_share`.",
    },
    {
        "name": "delegated",
        "description": "Macaroon-style delegated read endpoint. Caveats and live issuer authorization are enforced.",
    },
    {
        "name": "audit",
        "description": "Tenant-scoped authorization decision logs.",
    },
]


def create_app() -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    app = FastAPI(
        title="SecureShare Authorization Reference API",
        summary="Multi-tenant document sharing with JWT, OpenFGA, Macaroons, PostgreSQL, and audit logging.",
        description=DESCRIPTION,
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        openapi_tags=TAGS_METADATA,
        contact={"name": "SecureShare maintainers"},
        license_info={"name": "Reference implementation"},
    )
    app.add_middleware(RequestContextMiddleware)
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(documents.router)
    app.include_router(shares.router)
    app.include_router(delegated.router)
    app.include_router(audit.router)

    return app


app = create_app()
