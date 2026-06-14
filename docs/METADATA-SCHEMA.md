# METADATA-SCHEMA.md — Rule metadata conventions

A consistent metadata convention makes the corpus searchable, auditable, and
auto-cataloguable (`scripts/Update-RuleIndex.ps1` parses these fields into
`metadata/rules-index.csv`).

---

## SID / ID allocation

| Engine        | Identifier | Reserved ranges                                            |
|---------------|------------|-----------------------------------------------------------|
| Snort/Suricata| `sid`      | `9000000–9000999` = framework self-tests. Author rules: `1000000+` (local SID space; ≥1,000,000 avoids collisions with vendor rulesets). |
| YARA          | rule name  | `DRL_<Category>_<Name>` PascalCase, globally unique. |

Always set `rev:` and bump it on every change.

---

## Snort 3 / Suricata required keywords

Every rule MUST include:

- `msg:` — human-readable, prefixed with a stable namespace token, e.g. `"DRL ..."`.
- `sid:` and `rev:`.
- `classtype:` — from the engine's `classification.config`.
- `metadata:` — comma-separated `key value` pairs. **No commas inside a value**
  (use `_`). Recommended keys:

```
metadata:stage staging, author detection-rules-lab, created 2026_06_14, mitre_technique T1071_001
```

| Key               | Example            | Notes                                  |
|-------------------|--------------------|----------------------------------------|
| `stage`           | `staging`          | mirrors the lifecycle directory        |
| `author`          | `detection-rules-lab` | owner / team                        |
| `created`         | `2026_06_14`       | ISO-ish, underscores (commas illegal)  |
| `mitre_technique` | `T1071_001`        | ATT&CK technique (dot → underscore)    |

> Suricata-specific: prefer **sticky buffers** (`http.uri; content:"...";`) over the
> legacy `uricontent`. Add `flow:established,to_server;` for stateful HTTP rules.
> Snort 3 equivalent sticky buffer is `http_uri;` followed by `content:"...";`.

---

## YARA `meta:` block

```yara
rule DRL_Category_Name
{
    meta:
        author          = "detection-rules-lab"
        description     = "what it detects, one line"
        stage           = "staging"
        severity        = "informational|low|medium|high|critical"
        created         = "2026-06-14"
        reference       = "internal://detection-rules-lab/<ticket-or-source>"
        mitre_technique = "T1059.001"   // or "N/A"
    strings:
        $a = "..." ascii wide
    condition:
        $a
}
```

`Update-RuleIndex.ps1` extracts `author`, `description`, and `severity` per rule.
Use `ascii wide` on string atoms unless you have a reason not to, and keep at least
one reasonably long/specific atom so YARA's fast matching stays efficient.

---

## The generated catalog

`metadata/rules-index.csv` columns:

```
engine, scope, file, id, name, classtype, metadata
```

It is regenerated and re-staged automatically by the pre-commit hook, so it never
drifts from the rules. Regenerate manually any time with:

```powershell
.\scripts\Update-RuleIndex.ps1
```
