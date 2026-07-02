# Release Criteria

SecureShare releases should meet the following minimum bar before promotion beyond local development.

## Required Automated Checks

- `uv run pytest` passes
- `uv run python -m compileall -q apps/api/app scripts` passes
- `docker compose config --quiet` passes
- CI source vulnerability policy passes
- CI image vulnerability policy passes
- SBOM generation succeeds
- artifact signing succeeds on non-PR release paths

## Required Security Review

- auth, authz, delegated-token, migration, and workflow changes reviewed by code owners
- threat-model updates included for materially new trust boundaries or residual risks
- OpenAPI contract regenerated when externally visible behavior changes

## Release Integrity

- signed source bundle produced
- SHA256 sums produced
- SBOM attached to the release artifact set
- CI workflow references pinned to immutable action SHAs

## Operational Readiness

- required secrets documented and provisioned
- OpenFGA store and PostgreSQL backup expectations documented
- authorization repair job processing path available
- rollback plan identified for schema or auth-contract changes

## Blockers

Do not release when any of the following are true:

- known tenant-isolation bypass remains open
- known authentication bypass remains open
- CI artifact signing path is broken or bypassed
- unsigned mutable workflow changes are the only release path
- high or critical vulnerabilities violate the documented scanner policy
