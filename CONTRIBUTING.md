# Contributing rules

## The lifecycle

```
        author rule                 syntax+functional green              reviewed
 (1) rules/<engine>/staging/  ──▶  (2) Test-Functional.ps1 passes  ──▶  (3) git mv to production/
```

1. **Author** the rule in `rules/<engine>/staging/`. Follow
   [docs/METADATA-SCHEMA.md](docs/METADATA-SCHEMA.md) (SID range, `metadata:`/`meta:`).
2. **Validate locally** before committing:
   ```powershell
   .\scripts\Validate-Syntax.ps1 -Files rules\suricata\staging\my-rule.rules
   .\scripts\Test-Functional.ps1 -Engine suricata
   ```
   If your rule needs new telemetry to prove it fires, extend
   `tests/generators/gen_pcaps.py` (or add a benign YARA sample under
   `tests/samples/yara/`) and add an expectation to `tests/expected/expected.json`.
3. **Commit.** The pre-commit hook re-runs syntax validation on staged rules and
   refreshes `metadata/rules-index.csv`. A failure **blocks the commit** — fix, don't
   bypass. (Emergency override is `git commit --no-verify`; never use it to land a
   broken rule.)
4. **Promote** only after functional tests pass and review against
   [docs/EDGE-CASES.md](docs/EDGE-CASES.md):
   ```powershell
   git mv rules\suricata\staging\my-rule.rules rules\suricata\production\
   ```

## Definition of done

- [ ] Syntax validation passes for the rule's engine.
- [ ] A functional expectation exists and passes (rule fires on a true positive,
      and — for YARA — does NOT fire on the negative-control sample).
- [ ] Metadata complete (`sid`/`rev`/`msg`/`classtype`/`metadata:` or YARA `meta:`).
- [ ] Reviewed against EDGE-CASES.md (HOME_NET scoping, ports, flow state, perf).
- [ ] `metadata/rules-index.csv` updated (automatic via hook).
