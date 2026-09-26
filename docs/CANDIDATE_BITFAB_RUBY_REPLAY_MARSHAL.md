# CVE Candidate — bitfab Ruby SDK replay deserializes server-supplied Marshal data

**Status:** CVE CANDIDATE — NOT YET ASSIGNED OR DISCLOSED; security boundary pending vendor confirmation  
**Package:** `bitfab` (RubyGems)  
**Affected releases observed:** every published release, `0.9.0` (2026-03-31) through `0.62.5` (2026-09-25), 108 versions  
**Artifacts inspected:**
- `bitfab-0.62.5.gem` — SHA-256 `203dda1c7e10cc67d7760d7061ae3d08302ad1760420d8f1b5b6f20566dd631b`
- `bitfab-0.9.0.gem` — SHA-256 `8d4df7bf48d5070c0d1ecbfb813e804c74e204b54993fc65f78816ca55387a15`
**Primary weakness:** CWE-502 — Deserialization of Untrusted Data  
**Potential impact:** arbitrary Ruby code execution on the machine that runs `Bitfab::Client#replay` (developer workstation or CI), with that process's privileges  
**Found by:** Huginn local static hunt, 2026-09-26 (`generic.unsafe-deserialization` sink, manually traced to its source)  
**Automatic disclosure/submission:** disabled

## Summary

`bitfab` is the Ruby SDK for the Bitfab tracing service. Its replay feature fetches recorded
spans from the Bitfab API and re-runs them locally. During replay the SDK takes Base64 strings
from the API response (`inputSerialized`, `output_serialized` and `output_meta`) and passes
them to `Marshal.load` with no type allow-list.

`Marshal.load` on attacker-chosen bytes is a well-known Ruby code-execution primitive (for
example, the universal gadget chains built on `Gem::Requirement` and similar classes).
Anyone who can put crafted span data into a project can get code execution in the process
of whichever developer or CI job later replays that project's traces.

The SDK also passes metadata written by *other* language SDKs to `Marshal.load`. The code
comments say it "falls back" when the bytes are "a shape Ruby cannot reconstruct (e.g.
superjson/jsonpickle meta another SDK's span may carry)". This shows the field is not
limited to data this SDK wrote.

## Static evidence (0.62.5)

1. The sink — `lib/bitfab/serialize.rb:195`

   ```ruby
   def unmarshal_value(encoded)
     Marshal.load(Base64.strict_decode64(encoded)) # rubocop:disable Security/MarshalLoad
   end
   ```

   It is called from `deserialize_output` (line 212, on `meta`) and from
   `deserialize_inputs` (line 233, on `item["inputSerialized"]`).

2. The source is span data returned by the API:
   - `lib/bitfab/replay.rb:1167-1178`: `build_span_output_fetcher` calls
     `http_client.get_external_span(id, replay_view: true)`, which is
     `GET /api/sdk/externalSpans/:id`. It then passes `span_data["output_serialized"]`, or
     failing that `span_data["output_meta"]`, into `Serialize.deserialize_output`.
   - `lib/bitfab/replay.rb:1295`: `Serialize.deserialize_inputs(item)`, where each replay
     item comes from the `/api/sdk/replay/start` response.
   - `lib/bitfab/client.rb:1191-1196`: `resolve_recorded_output` deserializes
     `mock_entry[:output_meta]` from the span tree (`/api/sdk/replay/spanTree/:id`).

3. There is no integrity check (signature or MAC) on the serialized payloads, and no class
   allow-list. Errors are rescued, and the code falls back to raw JSON, so a gadget runs
   before any fallback happens.

4. The sink has been present since the first release (`0.9.0`,
   `lib/bitfab/serialize.rb:66`, reached from `replay.rb:126`).

## Trust boundary and remaining verification

A network attacker cannot exploit this, because requests use HTTPS to the configured
service URL (default `https://bitfab.ai`). The crossing is between **whoever can write
span data into a project** and **whoever replays that project's traces**:

- Tracing SDKs send spans with the project API key. That key is deployed in the traced
  production services, so anyone holding it, or controlling a traced service, can submit
  spans with arbitrary `inputSerialized` / `output_meta` fields.
- Replay runs on developer machines and CI with local source code and credentials.

So a span-ingest credential, or a compromised traced service, becomes code execution on
developer and CI hosts. A compromised or malicious Bitfab server is a second, weaker
scenario.

Still open before this can be marked VALIDATED in the ledger:

- [ ] Confirm with the vendor, or from the API docs, whether span-ingest keys are
  separable from replay/read keys, and whether the server re-validates or strips
  `inputSerialized` / `output_meta`. Either would change the severity, not the existence
  of the sink.
- [ ] OSV / GHSA / RubySec lookup. This session could not reach OSV or the GitHub advisory
  API; the Huginn pipeline's enrichment step will record the result.
- [ ] Dynamic confirmation in an isolated, no-network lab (not performed; Huginn never
  executes discovered packages).

## Suggested fix

Stop using `Marshal` for data that crosses the service boundary. Use JSON with explicit type
tags, or sign the serialized payload with a key held only by the recording process and verify
it before loading. At minimum, never feed other SDKs' `output_meta` to `Marshal.load`.

## Draft severity

CVSS 3.1 estimate `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H` (8.7, HIGH). This assumes span-write
access requires a project key (PR:L) and that a developer runs replay (UI:R). Revisit once the
key model is confirmed.
