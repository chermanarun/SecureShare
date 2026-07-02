# Security Policy

## Scope

SecureShare is a reference application for multi-tenant authorization patterns. Security-sensitive areas include:

- `apps/api/app/auth/`
- `apps/api/app/authz/`
- `apps/api/app/routers/`
- `apps/api/app/services/`
- `migrations/`
- `infra/`
- `.github/workflows/`

## Reporting A Vulnerability

Please report suspected vulnerabilities privately to the maintainers before opening a public issue.

Include:

- affected version, branch, or commit
- reproduction steps
- expected impact
- any proof-of-concept artifacts or logs

The maintainers will acknowledge receipt, validate the report, and coordinate remediation before public disclosure.

## Triage Priorities

Highest priority:

- broken tenant isolation
- authentication bypass
- authorization bypass
- delegated-token abuse
- audit-log tampering or suppression
- CI/release integrity compromise

Medium priority:

- denial of service
- information disclosure without direct privilege escalation
- local-dev misconfiguration that could become production guidance drift

## Supported Security Posture

This repository aims to keep:

- JWTs identity-only and revocable
- OpenFGA as the primary object-authorization engine
- delegated tokens attenuated and caveat-bound
- authorization decisions auditable
- CI artifacts signed and reproducible

Local Docker Compose is for development only and must not be treated as a production deployment profile.
