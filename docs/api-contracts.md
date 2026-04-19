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

## Documents

`POST /documents`

Creates a document owned by the caller and writes an OpenFGA owner tuple.

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

