# Hunt 002 Manual Candidate Review

**Review state:** completed static triage  
**Automatic disclosure:** disabled  
**Automatic CVE submission:** disabled

## Result

The Hunt 002 sink-only queue was reviewed against the exact published package artifacts.
One finding family survives as a strong CVE candidate. The other reviewed families are
false positives, intentional/authorized behavior, or lack a source-to-sink security
boundary.

| Package | Finding family | Disposition | Basis |
|---|---|---|---|
| `volcengine-python-sdk-aicc 0.0.41` | unsafe pickle response + remote-attestation fail-open | **STRONG_CVE_CANDIDATE** | failed attestation may still install peer key; legacy secure response is decrypted then unpickled |
| `gitomb 0.1.0` | subprocess command execution | FALSE_POSITIVE | fixed executable, argv list, no shell; Git ref path uses `--end-of-options` |
| `archcheck 0.26.0` | subprocess command execution | FALSE_POSITIVE | fixed clangd executable/options; no attacker-controlled shell command |
| `archcheck 0.26.0` | innerHTML/XSS | FALSE_POSITIVE / NO_SOURCE | embedded analysis JSON escapes `<`; reviewed dynamic render fields use escaping helpers |
| `webteam-agents 0.2.0` | subprocess command execution | INTENTIONAL_AUTHORIZED | commands come from project policy/config and require explicit `--allow-checks`; direct argv execution |
| `bluet-mcp 0.3.0-0.4.2` | dynamic eval | RULE_FALSE_POSITIVE | generic regex matched database methods named `.exec(sql)`, not language eval/exec |
| `search-gateway 1.0.3.post20260923` | innerHTML/XSS | LOW_SIGNAL / NO_SOURCE_TO_SINK | reviewed hit initializes application shell; no attacker-controlled value traced into sink |
| `volcengine-python-sdk-aicc 0.0.41` | ffmpeg subprocess | FALSE_POSITIVE | fixed ffmpeg argv list; no shell invocation |

## Lessons applied to Huginn

1. A member method named `.exec()` must not be treated as a dynamic language
   `exec()` primitive.
2. Generic `subprocess.run/Popen` detection is useful as a review signal, but argv-list
   execution without `shell=True` must not be promoted on the sink alone.
3. `innerHTML` requires source/sanitizer tracing; application-shell construction is
   not itself an XSS vulnerability.
4. Unsafe deserialization deserves much higher priority when a separate trust failure
   places an unverified remote peer inside the cryptographic boundary.
5. Exact-artifact SHA verification and static version scoping should be retained for all
   disclosure-grade candidates.

## Candidate record

See `docs/CANDIDATE_VOLCENGINE_AICC_0_0_41.md`.
