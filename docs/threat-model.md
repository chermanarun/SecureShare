# SecureShare Threat Model

## Assets

- Tenant-isolated documents
- User identity claims
- OpenFGA relationship tuples
- Delegated Macaroon tokens
- Authorization audit logs

## Trust Boundaries

- Browser or API client to FastAPI
- FastAPI to PostgreSQL
- FastAPI to OpenFGA
- Macaroon token holder to delegated read endpoint

## Key Threats And Controls

### Broken Access Control

Risk: a user changes an object ID and reads another tenant's document.

Controls:

- All protected document routes call `AuthorizationService`.
- `AuthorizationService` checks tenant ownership before asking OpenFGA.
- Tests cover direct object reference tampering and cross-tenant denial.

### Stale JWT Authorization

Risk: a JWT minted before revocation continues to grant access.

Controls:

- JWT contains identity only.
- OpenFGA is checked on every protected resource request.
- Tests revoke Bob's viewer relationship and reuse his existing JWT.

### Weak Or Malformed JWT

Risk: unsigned, weak-algorithm, malformed, or wrong-issuer tokens are accepted.

Controls:

- JWT decoding pins `HS256`.
- Required claims are enforced.
- Issuer and audience are verified.
- Stored `token_version` enables immediate family-wide bearer-token revocation through logout or future account-recovery flows.
- Tests cover malformed and `alg=none` tokens.

### Delegated Token Abuse

Risk: temporary share links are replayed, used after expiry, used from the wrong IP, or outlive issuer access.

Controls:

- Macaroon caveats bind action, document, tenant, issuer, expiry, and caller IP.
- Delegated endpoint supports read only.
- Delegated reads perform live OpenFGA checks for the issuing user.
- Delegated-link issuance rejects mismatched client-supplied IP overrides.
- Tests cover expiry, wrong IP, and revocation.

### Audit Gaps

Risk: denied requests or delegated access cannot be reconstructed.

Controls:

- `AuthorizationService` records every allow and deny.
- Audit rows include request ID, user, tenant, resource, action, decision, reason, and decision source.
- Audit log reads require a tenant-admin relationship in OpenFGA.
- Login-attempt audit resources use hashed identifiers instead of raw email addresses.

## Residual Risks

- The local JWT issuer is not suitable for production identity federation.
- Audit retention, tamper resistance, and export to a SIEM are left as production extensions.
- Authorization repair jobs need a production scheduler or worker so queued cleanup tasks are drained promptly after an OpenFGA outage.
- Production should still add backup, restore, and monitoring controls around the OpenFGA datastore.
