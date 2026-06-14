-- =============================================================================
-- Minimal Snort 3 configuration for OFFLINE rule validation and PCAP replay.
-- Loaded with:  snort -c /config/snort.lua -R <rulefile> -T          (syntax)
--               snort -c /config/snort.lua -R <rulefile> -r <pcap> -A alert_fast
-- Rules are supplied at run time via -R so this file stays rule-agnostic.
-- =============================================================================

-- HOME_NET / EXTERNAL_NET must be set before including defaults.
-- Wide during validation so a rule never silently no-ops because the scope
-- excludes the synthetic traffic. In PRODUCTION these are tightened — see
-- docs/EDGE-CASES.md.
HOME_NET = 'any'
EXTERNAL_NET = 'any'

-- Pull in Snort's shipped defaults: default_wizard, default_classifications,
-- default_references, default_variables, etc. Resolved via SNORT_LUA_PATH,
-- which the drl/snort3:local image sets to the etc/snort dir.
include 'snort_defaults.lua'

-- Crafted / replayed PCAPs frequently carry placeholder (zero/invalid) checksums.
-- Without this, Snort drops them before detection and your rule "never fires".
network =
{
    checksum_eval = 'none',
}

-- Stream inspectors so flow- and HTTP-buffer rules match on reassembled traffic.
stream = { }
stream_tcp = { }
stream_udp = { }
stream_ip = { }

-- HTTP inspection + service binding so http_uri sticky-buffer rules can fire.
http_inspect = { }
wizard = default_wizard

binder =
{
    { when = { proto = 'tcp', ports = '80' }, use = { type = 'http_inspect' } },
    { use = { type = 'wizard' } },
}

-- classtype / reference resolution for rule metadata.
references = default_references
classifications = default_classifications

-- Detection engine. enable_builtin_rules=false keeps decoder/builtin GIDs quiet
-- so the only alerts you see come from YOUR rules.
ips =
{
    enable_builtin_rules = false,
}

search_engine =
{
    search_method = 'ac_full',
}

-- Human-readable alerts written to <logdir>/alert_fast.txt
alert_fast =
{
    file = true,
    packet = false,
}
