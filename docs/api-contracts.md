# SecureShare API Contracts

## Authentication

`POST /auth/login`

```json
{
  "email": "alice@example.com",
  "password": "password123"
}
```

Returns:

```json
{
  "access_token": "jwt",
  "token_type": "bearer",
  "expires_in": 3600
}
```

`POST /auth/logout`

Requires a bearer token. Increments the stored token version for the caller so previously issued JWTs are rejected on the next request.

## Documents

`POST /documents`

Creates a document owned by the caller only if the caller still has a live tenant-membership relationship in OpenFGA, then writes the owner and tenant-parent tuples.

`GET /documents/{document_id}`

Requires `can_read`.

`PATCH /documents/{document_id}`

Requires `can_edit`.

## Shares

`POST /documents/{document_id}/shares`

Requires `can_share`.

```json
{
  "subject_type": "user",
  "subject_id": "00000000-0000-0000-0000-000000000002",
  "role": "viewer"
}
```

`DELETE /documents/{document_id}/shares`

Requires `can_share`.

## Delegation

`POST /documents/{document_id}/shares/delegated-link`

Requires issuer `can_read`.
Delegated tokens are always bound to the server-observed caller IP. If `ip_address` is provided, it must match the observed client IP or the request is rejected.

```json
{
  "expires_in_seconds": 300,
  "ip_address": "203.0.113.10"
}
```

`GET /delegated/documents/{document_id}`

Requires header:

```text
x-delegation-token: <macaroon>
```

## Audit

`GET /audit`

Returns recent tenant-scoped authorization decisions.

## Relationship Inspection

`GET /documents/{document_id}/relationships`

Requires tenant-admin access and only returns relationships for documents inside the caller's tenant.
