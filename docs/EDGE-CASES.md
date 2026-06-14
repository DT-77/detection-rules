# EDGE-CASES.md — Where local validation diverges from live deployment

Local, container-based validation is necessary but **not sufficient**. These are the
recurring traps where a rule passes locally yet behaves differently in production
(or vice-versa). Treat this as the review checklist before promoting `staging → production`.

---

## 1. Network variables (`HOME_NET` / `EXTERNAL_NET`)

- **Here:** `config/snort/snort.lua` and `config/suricata/suricata.yaml` set
  `HOME_NET = any`, `EXTERNAL_NET = any` so a rule is never silently scoped out
  during validation.
- **Production:** these are tightened to real address space. A rule written
  `$HOME_NET any -> $EXTERNAL_NET any` may match locally but **never fire in prod**
  if the test traffic's addresses fall outside the production `HOME_NET`.
- **Action:** before promotion, mentally (or with a second config) re-test against
  production-like `HOME_NET` values. Don't hard-code directionality you can't satisfy.

## 2. Port variables & `HTTP_PORTS`

The demo rules pin `-> any 80`. Production traffic on 8080/8443/etc. won't match a
port-literal rule. Use `$HTTP_PORTS` and ensure the var covers real ports.

## 3. Checksum handling (the #1 "my rule won't fire on a PCAP")

Crafted (Scapy) and some replayed packets carry placeholder/invalid L3/L4 checksums.
- Suricata drops them unless you pass **`-k none`**.
- Snort drops them unless `network.checksum_eval = 'none'` (set in our `snort.lua`).
On a live NIC the OS computes valid checksums, so this knob is a **local-only** concern.
If you forget it, you get zero alerts and no error — the most confusing failure mode.

## 4. Flow state & stream reassembly across PCAP boundaries

- `flow:established` / `flowbits` / `flowint` need the **handshake and both
  directions** in the PCAP. Our generator emits a full 3-way handshake for exactly
  this reason. A single-packet PCAP will silently fail any `flow:established` rule.
- Rules spanning multiple flows or requiring `flowbits` set by a *prior* rule need a
  PCAP that contains the whole sequence — partial captures give false negatives.
- TCP segmentation: content split across segments only matches if stream reassembly
  is on (it is, in our configs). Live MTU/segmentation may differ from your PCAP.

## 5. App-layer parsing requires a valid protocol exchange

`http.uri`, `http.host`, `tls.sni`, `dns.query` etc. only populate if the engine
successfully parses the app protocol. A raw-content rule (`content:"..."`) is far more
robust on synthetic PCAPs; that's why the framework's *required* SID is a raw match
and the app-layer SID is "bonus". In production, prefer app-layer buffers for
precision — but test them against realistic captures, not hand-crafted single requests.

## 5b. Generic `content` inspects DIFFERENT buffers on Snort vs Suricata

Verified in this framework's own self-tests: a generic, buffer-less
`content:"<uri-substring>"` rule against an **HTTP** flow

- **fires on Suricata** — its generic `content` inspects the raw/normalized stream
  payload, which includes the request line; but
- **does NOT fire on Snort 3** — Snort routes the HTTP request line/headers into
  dedicated sticky buffers (`http_uri`, `http_header`, ...), so `pkt_data` (what a
  generic `content` searches) is the HTTP *body*, which is empty for a GET.

Consequences:
- Write HTTP detections with the explicit buffer on **both** engines
  (`http.uri; content:...` on Suricata, `http_uri; content:...` on Snort 3).
- Reserve generic `content` for genuinely non-HTTP / raw flows. (The framework's
  required self-test SID 9000001 matches a synthetic **non-HTTP :4444 beacon** for
  exactly this reason; the HTTP URI match is SID 9000002.)

## 6. YARA + host antivirus (Windows Defender) interference

Writing the real **EICAR** test string (or any known-malicious signature) to disk on
the Windows host will trigger Defender, which quarantines/deletes the sample **before
YARA can read it** — your test vanishes mid-run. This framework uses a neutral marker
(`DRL_BENIGN_TP_MARKER_v1`) instead. If you must test against real
malicious samples, keep them inside the container / an excluded directory, or in a
Defender-exclusion path — never loose on the host filesystem.

## 7. YARA performance & scan limits

- **Big files / slow regexes:** YARA defaults to a `fast` mode and a per-scan timeout.
  A rule that's fine on a 4 KB sample can time out or thrash on a 2 GB memory dump.
  Test promotion candidates against representatively large inputs; consider
  `yara --timeout` and avoid unanchored `.*`/short atoms.
- **Short string atoms** (< 4 bytes) generate "slowing down scanning" warnings — use
  `yara --fail-on-warnings` in CI to catch these before they hit an endpoint agent.

## 8. Suricata config schema drift between versions

`suricata.yaml` keys are added/renamed across 6.x → 7.x → 8.x. A config that passes
`-T` on the pinned `drl/suricata:local` image may warn or error on a different
production Suricata version. Pin the production engine version and re-validate when you
bump the base image. `suricata --build-info` (baked into the image build) shows the
exact version/features compiled in.

## 9. Snort 3 builtin/decoder rules & `fast_pattern`

- We set `enable_builtin_rules = false` so only *your* SIDs alert during validation.
  Production often enables builtins (GID 116 etc.) — different alert volume/noise.
- `fast_pattern` selection: Snort/Suricata auto-pick the longest content as the fast
  pattern. A rule that "works" locally may be a performance liability in prod if its
  fast pattern is short/common. Use `suricata --engine-analysis` to inspect.

## 10. Performance bottlenecks are invisible at validation time

`-T` and single-PCAP `-r` say nothing about throughput. A regex-heavy `pcre` rule can
pass every functional test and still drop packets at line rate. Before promoting
perf-sensitive rules, replay a *large* representative PCAP and watch the engine stats
(`stats.log` / `eve.json` stats events), or run `suricata --engine-analysis`.

## 11. CRLF line endings

A single CRLF in a `.rules`, `.yar`, `.lua`, `.yaml`, the Scapy script, or the
`.githooks/pre-commit` shim breaks parsing inside the Linux container with opaque
errors. `.gitattributes` forces LF on all engine-consumed files — **do not override
it**, and if you author files outside Git, save them as LF.

## 12. Rule ordering, thresholds, and suppression

`threshold`/`detection_filter`/`event_filter` and `suppress` lists change whether an
alert *surfaces* even when the rule *matches*. Our validation asserts the match fires;
production suppression/threshold config can hide it. Validate the rule logic here, but
review threshold/suppress interactions against the production ruleset separately.

## 13. Container vs. live privileges & DAQ

Live inline (IPS) deployment uses a DAQ module (af-packet/nfq) and may need
capabilities the offline `-r` read mode never exercises. `-T`/`-r` validate
*detection logic*, not the *deployment/inline* path. Inline drop behavior
(`drop`/`reject` actions, `--runmode` differences) must be validated in a staging
sensor, not in this offline harness.
