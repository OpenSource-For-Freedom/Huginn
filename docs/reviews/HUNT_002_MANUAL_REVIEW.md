# Hunt 002 — Manual Candidate Review

**Scope:** 46 static `NO_MATCH` findings from Hunt 002  
**Method:** exact-artifact static review only; package code was not executed  
**Automatic disclosure / CVE submission:** disabled

## Result

| Package / versions | Rows | Disposition |
|---|---:|---|
| `bluet-mcp` 0.3.0, 0.4.0, 0.4.1, 0.4.2 | 28 | FALSE_POSITIVE |
| `archcheck` 0.26.0 | 13 | FALSE_POSITIVE |
| `gitomb` 0.1.0 | 1 | FALSE_POSITIVE |
| `search-gateway` 1.0.3.post20260923 | 1 | FALSE_POSITIVE |
| `webteam-agents` 0.2.0 | 1 | INTENTIONAL_GUARDED_EXECUTION |
| `volcengine-python-sdk-aicc` 0.0.41 | 2 | 1 FALSE_POSITIVE + 1 NOVEL_CANDIDATE |

**Novel disclosure candidates after manual review: 1.**

## Dispositions

### bluet-mcp

All 28 rows are one precision bug: the generic dynamic-evaluation regex matched JavaScript object methods named `.exec(...)`, including database-driver and schema-migration helpers. Exact-artifact review of 0.4.2 found no reviewed hit that was global `eval(...)` or code evaluation. Hunt 002 also showed the same rule/path persisted through the immediately preceding versions.

Disposition: **FALSE_POSITIVE**.

### archcheck

The command row launches `clangd` with an argv list and no shell. The 12 HTML-sink rows were checked against the exact report template: dynamic values are escaped with the local `esc(...)` helper, inserted via `textContent`, or produced through escaping helpers such as `codeAnchor`, `fileAnchor`, and `doxygenMarkup`. The JSON embedded in the `application/json` script block is produced with `json.dumps(...).replace("<", "\\u003c")`, preventing a literal `</script>` breakout.

Disposition: **FALSE_POSITIVE** for all 13 rows.

### gitomb

The flagged Git invocation uses an argv list with `shell=False` behavior. No shell interpolation occurs.

Disposition: **FALSE_POSITIVE**.

### search-gateway

The bundled frontend's `innerHTML` assignment installs a static application shell. Exact-artifact review shows `panelHtml()` functions return static markup; API-derived vendor, log, search, and usage values are rendered afterward with `textContent`, `replaceChildren`, or created DOM nodes.

Disposition: **FALSE_POSITIVE**.

### webteam-agents

The flagged subprocess behavior is an explicit project-check feature, gated by `--allow-checks`. The documentation warns that authorized check commands can run project code and are not an OS sandbox; the controller blocks execution without user approval.

Disposition: **INTENTIONAL_GUARDED_EXECUTION**.

### volcengine-python-sdk-aicc

The ffmpeg row is a fixed argv-list subprocess call and is not shell command injection.

The second row survives review. In legacy secure DeepSeek mode, decrypted network response data reaches `pickle.loads`. The secure-channel configuration defaults `attest_must` to false; when attestation fails but returns a public key, the client installs that key and returns success. That receiver public key wraps the symmetric request key, while the client retains the same key as `ResponseKey` for authenticated response decryption. A receiver with the matching private key can therefore construct authenticated plaintext that reaches the legacy `pickle.loads` path.

Fresh September 25, 2026 package-aware checks returned `OSV=NO_MATCH` and `GHSA=NO_MATCH`, with no public CVE identifiers.

Disposition: **NOVEL_CANDIDATE — vendor/security-boundary confirmation required**.

Tracked as `docs/candidates/HUGINN-2026-001-volcengine-aicc.md`.

## Rule corrections

The manual review exposed two recurring precision problems: `.exec(...)` object methods being mistaken for dynamic evaluation, and safe argv-based Python subprocess calls being treated as generic shell-command sinks. A separate production rule-tuning branch corrects both and adds a high-confidence network-response-to-unsafe-deserialization dataflow rule.

## Decision

Hunt 002 produced one candidate worth coordinated vendor review, not 46 CVEs. No external disclosure or CVE request should occur automatically.
