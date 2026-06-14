# Security Policy

## Reporting a vulnerability

**Please do not open public issues for security problems.**

Use GitHub's private vulnerability reporting: the repository **Security** tab →
**Report a vulnerability**. Include reproduction steps, impact, and the affected
files. Acknowledgement is best-effort (this is a community project).

## Scope

**In scope**
- The orchestration scripts (`scripts/`), Git hooks (`.githooks/`), and the
  dashboard generator.
- The Docker build definitions (`docker/`).

**Out of scope**
- The upstream engines (Snort 3, Suricata, YARA) and their base images — report
  those to their respective projects.
- False positives / false negatives in detection rules — those are functional
  bugs, file a normal issue.

## Security model

This project is designed to be run safely against **untrusted rule content**:

- All validation executes in **ephemeral containers launched with
  `--network none`** — there is no network path out of the sandbox.
- Rule parsing/compilation happens **only inside the container**, never directly
  on the host.
- **Do not place live malware in `tests/samples/`** on a host with real-time AV —
  use the provided neutral markers (see [docs/EDGE-CASES.md](docs/EDGE-CASES.md)).
- Generated artifacts (`reports/`, `dashboard/index.html`, PCAPs) may embed rule
  metadata; they are git-ignored by default.
- The pre-commit hook is a **local** control and is not a substitute for
  server-side review (see [docs/BRANCH-PROTECTION.md](docs/BRANCH-PROTECTION.md)).

## Supported versions

| Version        | Supported    |
|----------------|--------------|
| latest `main`  | yes          |
| older commits  | best-effort  |
