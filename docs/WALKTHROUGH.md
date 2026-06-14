# WALKTHROUGH.md — "Dummy-proof" demo (no prior knowledge needed)

This proves the whole system works in ~10 minutes. Just copy each command, paste it
into the blue window, and press **Enter**. After every step there's a
**"✅ You should see"** so you know it worked.

You do **not** need to understand Docker, Git, or PowerShell to follow this.

> Even simpler: double-click **`RUN-DEMO.bat`** in the project folder — it runs
> Steps 2 and 5 automatically. The manual steps below are for when you want to see
> exactly what's happening.

---

## STEP 0 — Start Docker (the engine room)

1. Press the **Windows key**, type **`Docker Desktop`**, click it.
2. Wait ~1 minute until the **whale icon** (bottom-right, near the clock) stops
   animating and Docker Desktop shows **"Engine running"** (green dot).

> Why: every check runs inside small throwaway "containers". Docker provides them.
> Nothing here ever talks to the internet/cloud.

---

## STEP 1 — Open the blue command window in the project folder

1. Press the **Windows key**, type **`PowerShell`**, click **Windows PowerShell**.
2. Go into the folder where you cloned/unzipped the project (the folder that contains
   `scripts\` and `rules\`). For example:

```powershell
cd C:\Users\you\detection-rules-lab
```

✅ The prompt should now end with the project folder name, e.g.
`PS C:\Users\you\detection-rules-lab>`.

3. Paste this one line and press **Enter** (it lets scripts run *in this window only*;
   it resets when you close the window):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

✅ No error = good. (It may print nothing. That's fine.)

---

## STEP 2 — Confirm Docker is awake

```powershell
docker ps
```

✅ You should see a header row like `CONTAINER ID   IMAGE   COMMAND ...`.
❌ If you see *"cannot connect to the Docker daemon"* → go back to STEP 0, Docker
isn't running yet.

---

## STEP 3 — Do the "engines" exist yet? (one-time build)

```powershell
docker images drl/*
```

- ✅ If you see **4 lines** (`drl/snort3`, `drl/suricata`, `drl/yara`, `drl/pcapgen`) →
  they're already built. **Skip to STEP 4.**
- If you see **only a header / nothing** → build them now (takes 5–15 min the first
  time; it's downloading the engines):

```powershell
.\scripts\Build-Images.ps1
```

✅ Ends with: `[+] All requested images are ready.`
(Short on time or disk? `.\scripts\Build-Images.ps1 -SkipSnort` builds everything
except the large Snort image.)

---

## STEP 4 — THE PROOF: run every check, all three engines

```powershell
.\scripts\Invoke-Validation.ps1 -Full
```

This checks the rules are **written correctly** (syntax) **and actually detect things**
(functional), for Snort, Suricata, and YARA.

✅ You should see green `[+]` lines and, at the very end:

```
[+]   required SID 9000001 fired
...
[+]   DRL_Benign_TP_Marker matched benign_marker_sample.txt
[+]   DRL_Benign_TP_Marker correctly ignored clean_negative_sample.txt
[+] All validation passed.
```

**That last line — `All validation passed.` — is your proof the system works.**

> Plain English: it built a fake network packet and a fake file, fed them to the three
> detection engines, and confirmed each engine raised the alarm it was supposed to
> (and did *not* raise a false alarm on the clean file).

---

## STEP 5 — THE SAFETY NET: watch a BAD rule get rejected

This proves the system stops broken rules from being saved.

1. Create a deliberately broken rule (copy-paste the whole line):

```powershell
Set-Content -Encoding ascii .\rules\suricata\staging\zz-test-bad.rules 'alert tcp any any -> any any (msg:"BAD TEST"; this_is_not_real:foo; sid:9000900; rev:1;)'
```

2. Try to save ("commit") it:

```powershell
git add .\rules\suricata\staging\zz-test-bad.rules
git commit -m "trying to save a broken rule"
```

✅ You should see it **refuse**, ending with:

```
[x] Suricata FAILED: zz-test-bad.rules
...
[x] Commit BLOCKED: 1 validation failure(s).
```

The broken rule was **not** saved. That's the gate doing its job.

3. Clean up the test file:

```powershell
git restore --staged .\rules\suricata\staging\zz-test-bad.rules
Remove-Item .\rules\suricata\staging\zz-test-bad.rules
```

✅ Confirm nothing is left to save:

```powershell
git status --short
```

✅ You should see **nothing** printed (clean = good).

---

## You're done 🎉

You just proved:
- **STEP 4** — all detection rules are valid and actually fire.
- **STEP 5** — a broken rule is automatically blocked before it can be saved.

### Everyday use (the only commands you'll normally type)
| I want to... | Command |
|---|---|
| Check everything works | `.\scripts\Invoke-Validation.ps1 -Full` |
| Just a quick syntax check | `.\scripts\Invoke-Validation.ps1` |
| Check one engine | `.\scripts\Validate-Syntax.ps1 -Engine yara` |

---

## If something goes wrong

| What you saw | What to do |
|---|---|
| `cannot connect to the Docker daemon` | Docker isn't running. Do STEP 0, wait for the green "Engine running". |
| `running scripts is disabled on this system` | You skipped STEP 1.3. Re-run the `Set-ExecutionPolicy` line. |
| `Required image 'drl/...' is missing` | Run `.\scripts\Build-Images.ps1` (STEP 3). |
| `cd : Cannot find path` | You're not in the project folder. `cd` into the folder that contains `scripts\`. |
| Red text mentioning `NativeCommandError` | Usually harmless noise from a tool's normal output — read the `[+]`/`[x]` lines instead; they're the real result. |
| It asks for a git name/email | Run: `git config user.name "Your Name"` then `git config user.email "you@example.com"`, and retry. |

> Tip: a line starting with **`[+]`** = good. **`[x]`** = a problem. **`[!]`** = a
> heads-up (not fatal). Read those lines; ignore the rest.
