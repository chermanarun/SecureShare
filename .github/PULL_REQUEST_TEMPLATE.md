## Summary

- change:
- risk:

## Security Checklist

- [ ] auth/authz changes include regression tests
- [ ] tenant-boundary behavior was reviewed
- [ ] delegated-token behavior was reviewed if touched
- [ ] CI/workflow changes were reviewed for supply-chain impact
- [ ] docs/openapi artifacts were refreshed if contract changed
- [ ] threat model or release criteria were updated if risk changed

## Validation

- [ ] `uv run pytest`
- [ ] `uv run python -m compileall -q apps/api/app scripts`
- [ ] `docker compose config --quiet`
