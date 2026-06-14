/*
 * =============================================================================
 * detection-rules-lab functional self-test rule (YARA) — STAGING
 * Matches the benign true-positive marker sample in tests/samples/yara/.
 * A neutral marker string is used INSTEAD of EICAR so host AV does not
 * quarantine the sample file — see docs/EDGE-CASES.md.
 * =============================================================================
 */

rule DRL_Benign_TP_Marker
{
    meta:
        author      = "detection-rules-lab"
        description = "Benign true-positive marker for functional validation"
        stage       = "staging"
        severity    = "informational"
        created     = "2026-06-14"
        reference   = "internal://detection-rules-lab/validation"
        mitre_technique = "N/A"

    strings:
        $marker = "DRL_BENIGN_TP_MARKER_v1" ascii wide

    condition:
        $marker
}
