# BRANCH-PROTECTION.md — Recommended `main` protection

Branch protection is configured on GitHub (UI or API), not in repo files. These are
sensible defaults for this project. Apply them after the first push.

## Recommended ruleset for `main`

| Setting | Value | Why |
|---|---|---|
| Require a pull request before merging | on | no direct pushes to `main` |
| Required approvals | 1 (or more) | a second set of eyes on every rule change |
| Dismiss stale approvals on new commits | on | re-review after changes |
| Require linear history | on | clean, bisectable history |
| Require conversation resolution | on | nothing merges with open threads |
| Block force pushes | on | history can't be rewritten |
| Restrict deletions | on | `main` can't be deleted |
| Require status checks to pass | optional | see note below |

### Note on status checks (local-first project)

The pre-commit hook is a **local** control — GitHub can't see it. To enforce checks
*server-side* you'd add a CI workflow that runs the validators. That requires GitHub
Actions runners with Docker, which is an **optional** trade-off against the strict
"no cloud" stance. If you keep CI off, rely on the required PR review + the local
pre-commit gate. If you add CI, mark its job as a required status check here.

## Apply via the GitHub CLI

Using the modern **rulesets** API (replace `OWNER/REPO`):

```bash
gh api -X POST repos/OWNER/REPO/rulesets \
  -f name='protect-main' -f target='branch' -f enforcement='active' \
  -F 'conditions[ref_name][include][]=refs/heads/main' \
  -F 'rules[][type]=deletion' \
  -F 'rules[][type]=non_fast_forward' \
  -F 'rules[][type]=required_linear_history' \
  -F 'rules[][type]=pull_request'
```

Or the classic branch-protection endpoint:

```bash
gh api -X PUT repos/OWNER/REPO/branches/main/protection \
  -F 'required_pull_request_reviews[required_approving_review_count]=1' \
  -F 'enforce_admins=true' \
  -F 'required_linear_history=true' \
  -F 'allow_force_pushes=false' \
  -F 'allow_deletions=false' \
  -F 'required_status_checks=null' \
  -F 'restrictions=null'
```

Verify in the GitHub UI under **Settings → Branches** (or **Settings → Rules**).
