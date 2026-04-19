# SecureShare Architecture

## Goals

SecureShare demonstrates a clean authorization architecture for a multi-tenant document sharing system. The central design rule is that business services do not decide authorization. They create and mutate application data only after a shared authorization service has produced an auditable decision.

For day-to-day code changes, read the developer guide in `docs/developer-guide.md`.

## Components

### Identity

The development identity provider is a local login endpoint that issues JWT access tokens. Tokens contain only identity claims:

- `sub`
- `tenant_id`
- `email`
- issuer, audience, issued-at, not-before, expiration

JWTs do not contain document permissions, roles, group memberships, or cached authorization state.

### PEP

FastAPI route dependencies and request middleware act as policy enforcement points:

- `RequestContextMiddleware` assigns a request ID for traceability.
- `get_current_principal` authenticates and validates JWT identity.
- Routers construct `AuthorizationRequest` objects before accessing protected resources.

### PDP

`AuthorizationService` is the single application authorization boundary. It checks:

- The resource exists.
- The resource belongs to the authenticated tenant.
- OpenFGA allows the requested relationship-derived action.

Every allow and deny is written through `AuditService`.

### OpenFGA

OpenFGA models users, tenants, groups, and documents. Document permissions are relationship-derived:

- `owner` grants read, comment, edit, and share.
- `editor` grants read, comment, and edit.
- `commenter` grants read and comment.
- `viewer` grants read.

Group grants are represented through `group:<id>#member`, so group membership affects effective permissions without copying permissions to every user.

### Delegation

Delegated read links are Macaroon-style tokens with caveats:

- action is `can_read`
- document ID
- tenant ID
- issuing user ID
- expiry timestamp
- optional IP address

Delegated access is not a separate authority. After caveat verification, SecureShare performs a live OpenFGA read check for the issuing user. Revoking the issuer's access immediately invalidates delegated reads.

### Persistence

PostgreSQL stores tenants, users, groups, documents, group membership, and audit logs. OpenFGA stores relationship tuples.

## Request Flow

1. Client sends a JWT-protected document request.
2. FastAPI validates the bearer token and loads the principal.
3. Router builds an `AuthorizationRequest`.
4. `AuthorizationService` verifies tenant boundary and calls OpenFGA.
5. The decision is recorded in `audit_logs`.
6. The route proceeds only on allow.

## Why Revocation Is Immediate

JWTs are identity-only. Removing a viewer tuple from OpenFGA changes the next authorization decision immediately, even if the user's JWT has not expired.
