<!-- Thanks for contributing. Keep changes 100% local / no-cloud. -->

## What & why
Briefly: what this changes and the motivation.

## Type
- [ ] New / updated detection rule(s)
- [ ] Framework change (scripts, hooks, Docker, dashboard)
- [ ] Docs only

## Validation (required for rule changes)
- [ ] `.\scripts\Invoke-Validation.ps1 -Full` passes locally
- [ ] Functional expectation added/updated in `tests/expected/expected.json` (if a new rule)
- [ ] Rule metadata complete per [docs/METADATA-SCHEMA.md](../docs/METADATA-SCHEMA.md)
- [ ] Reviewed against [docs/EDGE-CASES.md](../docs/EDGE-CASES.md) (HOME_NET scope, ports, flow state, perf)
- [ ] `metadata/rules-index.csv` regenerated (the pre-commit hook does this)

## Constraints
- [ ] No cloud / SaaS dependency introduced
- [ ] No personal, host-specific, or organisation-identifying data added

## Notes for reviewers
