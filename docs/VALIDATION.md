# VALIDATION.md — Explicit per-engine CLI reference

The PowerShell scripts wrap the commands below. This document spells out the raw
`docker run` invocations so you can reproduce, debug, or adapt any step by hand.
Every container is launched `--network none` (offline by construction) and `--rm`
(no residue).

All examples assume you are at the repo root and define `$repo` once:

```powershell
$repo = (Resolve-Path .).Path     # run from the cloned repo root
```

> Windows path note: Docker Desktop accepts native Windows paths in `-v`
> (e.g. `-v "$repo\rules:/rules:ro"`). On Linux/macOS the same commands work with
> `$repo` resolving to a POSIX path.

---

## A. Syntax validation (dry-run / test modes)

### Snort 3 — `-T` config+rule test
`-T` loads the config **and** the `-R` rule file, reports problems, and exits without
touching a NIC. Non-zero exit = failure. `-w` sets the working dir to the shipped Lua
defaults so `include 'snort_defaults.lua'` resolves (the Talos base image does not put
that dir on the include path).

```powershell
docker run --rm --network none `
  -v "$repo\config\snort:/config:ro" `
  -v "$repo\rules\snort\staging:/rules:ro" `
  -w /home/snorty/snort3/etc/snort `
  --entrypoint snort drl/snort3:local `
  -c /config/snort.lua -R /rules/selftest.rules -T
```

### Suricata — `-T` engine test mode
`-T` validates the YAML config and the `-S` (exclusive) rule file, then exits.
Returns non-zero if any rule fails to load.

```powershell
docker run --rm --network none `
  -v "$repo\config\suricata:/config:ro" `
  -v "$repo\rules\suricata\staging:/rules:ro" `
  --entrypoint suricata drl/suricata:local `
  -T -c /config/suricata.yaml -S /rules/selftest.rules -l /tmp
```

### YARA — `yarac` compile check
`yarac` compiles source → bytecode; any syntax/semantic error is non-zero exit.
(Alternative: `yara --fail-on-warnings <rule> <file>` to also fail on warnings.)

```powershell
docker run --rm --network none `
  -v "$repo\rules\yara\staging:/rules:ro" `
  -w /rules --entrypoint yarac drl/yara:local `
  selftest.yar /tmp/out.yarc
```

Python alternative (also fully local, via `yara-python`):
```python
import yara
yara.compile(filepath="rules/yara/staging/selftest.yar")  # raises yara.SyntaxError on failure
```

---

## B. Functional validation (does the rule actually fire?)

### Step 0 — synthesize telemetry offline (Scapy)
```powershell
docker run --rm --network none `
  -v "$repo\tests\generators:/gen:ro" `
  -v "$repo\tests\pcaps:/out" `
  --entrypoint python drl/pcapgen:local /gen/gen_pcaps.py
```

### Suricata — read PCAP, parse alerts
`-r` reads a PCAP; `--runmode single` is deterministic; **`-k none` disables checksum
validation** (crafted/replayed packets often carry placeholder checksums).

```powershell
docker run --rm --network none `
  -v "$repo\config\suricata:/config:ro" `
  -v "$repo\rules\suricata\staging:/rules:ro" `
  -v "$repo\tests\pcaps:/pcaps:ro" `
  -v "$repo\reports\suricata:/out" `
  --entrypoint suricata drl/suricata:local `
  -c /config/suricata.yaml -S /rules/selftest.rules `
  -r /pcaps/http_test.pcap -l /out --runmode single -k none
# Alerts: reports\suricata\fast.log  and  reports\suricata\eve.json
```

### Snort 3 — read PCAP, alert_fast output
`-r` reads a PCAP; `-A alert_fast` writes `alert_fast.txt` into the `-l` log dir.
(Checksum drops are disabled in `snort.lua` via `network.checksum_eval = 'none'`.)

```powershell
docker run --rm --network none `
  -v "$repo\config\snort:/config:ro" `
  -v "$repo\rules\snort\staging:/rules:ro" `
  -v "$repo\tests\pcaps:/pcaps:ro" `
  -v "$repo\reports\snort:/out" `
  -w /home/snorty/snort3/etc/snort `
  --entrypoint snort drl/snort3:local `
  -c /config/snort.lua -R /rules/selftest.rules `
  -r /pcaps/http_test.pcap -A alert_fast -l /out -q
# Alerts: reports\snort\alert_fast.txt
```

> Live alternative (true wire replay instead of `-r`): run the engine on an interface
> and feed it with `tcpreplay -i <iface> http_test.pcap`. The `-r` read mode above is
> preferred locally — deterministic, rootless, no NIC required.

### YARA — scan benign true-positive samples
`-r` recurses the sample directory; each match prints `RULENAME /path`.

```powershell
docker run --rm --network none `
  -v "$repo\rules\yara\staging:/rules:ro" `
  -v "$repo\tests\samples\yara:/samples:ro" `
  --entrypoint yara drl/yara:local `
  -r /rules/selftest.yar /samples
# Expect: DRL_Benign_TP_Marker /samples/benign_marker_sample.txt
# Expect: NO line for clean_negative_sample.txt
```

---

## C. Parsing alerts programmatically

Both Snort `alert_fast.txt` and Suricata `fast.log` carry the GID:SID:REV tuple:

```
... [**] [1:9000001:1] DRL FUNCTIONAL TCP PAYLOAD MARKER [**] ...
```

`Test-Functional.ps1` extracts SIDs with `\[\*\*\]\s*\[\d+:(\d+):\d+\]` and asserts
each `required_sids` entry from `tests/expected/expected.json` is present. Suricata's
`eve.json` additionally gives structured JSON (`event_type:"alert"`, `alert.signature_id`)
if you prefer JSON parsing over the fast-log regex.
