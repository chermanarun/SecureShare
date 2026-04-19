# SecureShare Coding Skill

## Objective
Build a secure reference app for modern authorization.

## Principles
- Keep identity and authorization separate
- JWT is for identity, not full permissions
- Every resource access goes through a single authorization path
- Relationship-based permissions come from OpenFGA
- Temporary delegated access uses Macaroon caveats
- All decisions are auditable

## Code expectations
- Python 3.12
- FastAPI
- SQLAlchemy 2.x
- clear package boundaries
- typed code
- pytest coverage for positive and negative authz paths
- no authz logic spread across routers and services

## Required modules
- auth/jwt.py
- auth/current_user.py
- authz/client.py
- authz/service.py
- authz/models.py
- middleware/pep.py
- audit/service.py
- routers/documents.py
- routers/shares.py
- services/document_service.py

## Authorization rules
- A user can read a document only if OpenFGA returns can_read
- A user can edit a document only if OpenFGA returns can_edit
- Ownership revocation must take effect immediately
- Group membership must affect effective permissions
- Cross-tenant reads are denied unless explicitly modeled

## Delegation rules
- Delegated tokens are read-only in v1
- Tokens must include expiry caveat
- Tokens should support optional IP caveat
- Tokens must not grant broader permissions than the issuing user already has

## Logging rules
For every decision, record:
- timestamp
- request id
- user id
- tenant id
- resource
- action
- allow or deny
- reason
- source of decision: jwt, openfga, macaroon, policy

## Test cases
- owner can read and edit
- viewer can read but not edit
- non-member cannot read
- revoked viewer loses access immediately
- expired Macaroon denied
- Macaroon with wrong IP denied
- cross-tenant request denied
- stale JWT does not bypass revoked relationship
- direct object id tampering denied

## Documentation
Write simple docs for:
- architecture
- local setup
- threat model
- demo scenarios
- known gaps and next steps