# Database-Layer Authorization

PostgreSQL can and should help with authorization, but it should not replace SecureShare's shared application authorization path.

## Short Answer

Yes, RBAC and ABAC can be enforced in PostgreSQL, especially with:

- database roles
- grants
- views
- row-level security policies
- tenant-scoped session settings
- constraints and triggers

For SecureShare, the recommended production posture is:

- OpenFGA remains the primary object-permission decision engine.
- FastAPI remains the policy enforcement point for user-facing actions.
- PostgreSQL row-level security acts as defense in depth for tenant isolation.

## Why Not Put Everything In PostgreSQL?

Document sharing is relationship-based:

- users can have direct roles on documents
- groups can have roles on documents
- group membership changes effective access
- revocation must be immediate
- delegated tokens must be attenuated by caveats

OpenFGA is better suited to answer those relationship questions consistently. PostgreSQL is excellent at enforcing data-plane guardrails such as "this query may only see rows for the current tenant."

## Recommended DB-Layer Controls

### Tenant Isolation With RLS

Use PostgreSQL row-level security on tenant-owned tables:

```sql
alter table documents enable row level security;

create policy tenant_documents_isolation
on documents
using (tenant_id = current_setting('app.current_tenant_id', true));
```

The API would set the tenant for each transaction:

```sql
select set_config('app.current_tenant_id', :tenant_id, true);
```

The third argument `true` makes the setting local to the transaction, which is important with connection pooling.

### Separate Application Roles

Use a least-privilege database role for the API:

```sql
grant select, insert, update, delete on documents to secureshare_api;
grant select, insert on audit_logs to secureshare_api;
```

Avoid using a database superuser from the application.

### Append-Oriented Audit Logs

Use grants or triggers to make audit logs append-oriented:

```sql
revoke update, delete on audit_logs from secureshare_api;
```

For production, ship audit logs to an external immutable store or SIEM.

## ABAC In The DB Layer

ABAC rules based on stable row attributes can live in PostgreSQL RLS. Examples:

- tenant ID
- document classification
- soft-delete state
- retention state
- regional partition

Rules that depend on relationship graphs or delegated token caveats should stay in the application and OpenFGA path.

## What SecureShare Does Today

The first version keeps DB-layer authorization simple:

- tenant IDs are modeled on tenant-owned rows
- the shared `AuthorizationService` checks tenant boundary and OpenFGA
- tests cover cross-tenant IDOR attempts

Recommended next hardening step:

1. Add PostgreSQL RLS policies for tenant-owned tables.
2. Add a SQLAlchemy transaction hook or dependency that sets `app.current_tenant_id`.
3. Add tests proving accidental queries cannot cross tenant boundaries even if a developer forgets a `where tenant_id = ...` clause.

That would give SecureShare both centralized relationship authorization and database-level tenant isolation.

