# CVE Candidate — Volcengine AICC Python SDK 0.0.41

**Status:** STRONG CVE CANDIDATE — NOT YET ASSIGNED OR DISCLOSED  
**Package:** `volcengine-python-sdk-aicc`  
**Affected release observed:** `0.0.41`  
**Artifact:** `volcengine_python_sdk_aicc-0.0.41.tar.gz`  
**SHA-256:** `2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab`  
**Published:** 2026-09-23T08:10:47.052596Z  
**Primary weakness:** CWE-502 — Deserialization of Untrusted Data  
**Secondary condition:** remote-attestation verification can fail open for key adoption  
**Potential impact:** client-side arbitrary code execution with the privileges of the consuming application  
**Automatic disclosure/submission:** disabled

## Executive summary

Huginn identified an unsafe `pickle.loads()` response path in the newly published
`volcengine-python-sdk-aicc==0.0.41` package. Static follow-up found that the condition
is materially stronger than a standalone pickle sink.

The SDK's DeepSeek secure client creates a Jeddak secure-channel client without setting
`attest_must`. The bundled remote-attestation configuration defaults
`attest_must = False`. When remote attestation fails but the RA response contains a
public key, the secure-channel client accepts and installs that key anyway.

For legacy DeepSeek protocol versions below 3.1, the secure response plaintext is then
passed to `pickle.loads()`.

The envelope encryption uses a generated AES response key and AES-GCM integrity. This
means arbitrary network modification is not sufficient. The relevant trust-boundary
condition is a peer whose public key is accepted by the fail-open attestation path. Such
a peer can participate in the envelope exchange and create an authenticated encrypted
response whose decrypted plaintext is attacker-selected pickle data.

This creates a credible path from failed remote attestation to unsafe deserialization.

## Static evidence

### 1. Secure mode is enabled by default

`bytedance/volcengine_aicc_sdk/deepseek_inference_client.py:36`

```python
is_secure: bool = True
```

The constructor builds a Jeddak configuration but does not override `attest_must`.

### 2. Attestation is not mandatory by default

`bytedance/jeddak_secure_channel/ra.py:101`

```python
attest_must: bool = False
```

The bundled comment describes this field as controlling whether a verification report
must be returned before adopting the public key.

### 3. Failed attestation can still install the returned public key

`bytedance/jeddak_secure_channel/client.py:95-106`

```python
ret, pub_key = attest_server(token, self.config, nonce)
if ret:
    if pub_key:
        self.session_key = ClientSessionKey.load(pub_key)
        return True
else:
    if pub_key and not self.config.attest_must:
        self.session_key = ClientSessionKey.load(pub_key)
        return True
```

### 4. Several verification failures preserve and return the public key

`bytedance/jeddak_secure_channel/ra.py` collects `public_key_info` before completing
verification.

Observed failure paths include:

- missing attestation token: returns `(False, public_key_info)`;
- public-key signature check failure: returns `(False, public_key_info)`;
- nonce verification failure: `verify_ra_result()` returns false;
- JWT verification failure: `verify_ra_result()` returns false;
- no matched attestation policy: `len(token_dict.get("policies_matched")) > 0` is false.

The outer client can nevertheless accept that key because `attest_must` defaults false.

### 5. The response encryption key is tied to the accepted server key

`bytedance/jeddak_secure_channel/crypto/envelope.py:220-248`

A fresh AES key is generated, returned to the client as a `ResponseKey`, and encrypted
to `server_public_key` inside the outgoing envelope.

The response is authenticated with AES-GCM before plaintext is returned to the caller.

This rules out unauthenticated bit-flipping, but it also means a peer controlling the
accepted private key can recover the response key and create valid authenticated
response ciphertext.

### 6. Legacy DeepSeek secure responses are unpickled

`bytedance/volcengine_aicc_sdk/deepseek_inference_client.py:274-279`

```python
if self.is_secure and encrypt_key:
    for elm in data['choices']:
        if self.dp_version < "3.1":
            elm['message'] = pickle.loads(encrypt_key.decrypt(elm['message']))
        else:
            elm['message'] = json.loads(encrypt_key.decrypt(elm['message']))
```

The same client explicitly supports the legacy branch with
`dp_version < "3.1"`; that mode requires `is_openai=False`.

## Vendor security-boundary context

Volcengine's Jeddak AICC documentation describes the Remote Attestation Service as
validating TEE attestation reports to prove service-code integrity and runtime
environment safety. Its endpoint SDK documentation also states that
`GetAttestationBackend` retrieves the remote-attestation report together with the
secure-channel public key.

This supports treating attestation failure as a meaningful trust-boundary event rather
than a cosmetic health check.

References:

- https://www.volcengine.com/docs/85010/1414788
- https://www.volcengine.com/docs/85010/1606206
- https://www.volcengine.com/docs/85010/1409669

## Exploitability preconditions

The static chain is relevant when all of the following hold:

1. `volcengine-python-sdk-aicc==0.0.41` is used.
2. `DeepSeekClient` runs with `is_secure=True` (the default).
3. A legacy `dp_version < "3.1"` is selected.
4. `is_openai=False` is used, as required by the legacy branch.
5. Remote attestation produces a public key but fails validation.
6. Because `attest_must=False`, that public key is accepted.
7. The peer corresponding to that accepted key returns an authenticated encrypted
   response containing pickle-serialized attacker-controlled data.

No target-package code was executed during this review. The analysis is based on the
published artifact, bounded static extraction, and cryptographic/control-flow tracing.

## Version scope

A static scan of every release currently exposed by the PyPI project metadata found one
published release:

- `0.0.41` — full chain present.

Therefore the presently observed affected range is `0.0.41`. Future releases must be
checked independently.

## Advisory / duplicate check

Huginn's package-aware enrichment for this exact package/version completed with:

- OSV: `NO_MATCH`
- GitHub Security Advisories: `NO_MATCH`
- dedup status: `NO_MATCH`

A current web search also did not surface an exact advisory for this package. This is
supporting novelty evidence, not proof that no private or unpublished report exists.

## Assessment

**Current disposition: STRONG_CVE_CANDIDATE**

The unsafe deserialization sink alone would not be enough. The candidate survives
review because it is paired with a default fail-open remote-attestation key-adoption
path that can place an attestation-failing peer inside the authenticated response
boundary.

The remaining validation question is threat-model intent: whether Volcengine considers
accepting a public key after failed attestation an explicitly supported insecure
compatibility mode for this client. Even if intentional in the underlying channel
library, the DeepSeek secure client does not set `attest_must=True` or expose a clear
constructor control, while the legacy response path uses pickle.

Vendor confirmation is appropriate before requesting a CVE.

## Recommended remediation

1. Replace pickle response serialization with JSON or another non-executable typed
   format for every protocol version.
2. Make remote attestation fail closed for confidential-inference clients.
3. Do not install or use a negotiated public key when token, nonce, signature, or policy
   verification fails.
4. If compatibility fallback is required, make it an explicit opt-in with a security
   warning and never combine it with executable deserialization.
5. Add regression tests for missing token, bad key signature, nonce failure, invalid JWT,
   and unmatched policy.

## Disclosure state

No vendor contact, public disclosure, GitHub Security Advisory, CNA submission, or CVE
request has been made by Huginn.
