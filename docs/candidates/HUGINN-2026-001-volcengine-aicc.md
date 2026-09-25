# HUGINN-2026-001 — Volcengine AICC candidate

**Status:** Candidate — manual/vendor validation required  
**Package:** `volcengine-python-sdk-aicc`  
**Version observed:** `0.0.41`  
**Artifact SHA-256:** `2aae4691780916114ad477ebbb6c09eaff2c597b1a60b02c8905efd4b70944ab`  
**First published:** 2026-09-23  
**Automatic disclosure:** disabled  
**CVE requested:** no

## Candidate summary

Huginn identified an unsafe-deserialization path in the legacy secure DeepSeek protocol. The same package contains a remote-attestation configuration that is permissive by default: a receiver public key can be adopted after attestation failure when `attest_must` remains false.

The combination is security-relevant because the adopted receiver public key is used to wrap a fresh symmetric key. The client retains that same symmetric key as a `ResponseKey` and later decrypts the receiver response with it. In the legacy DeepSeek path, the resulting plaintext is passed to `pickle.loads`.

This is not yet a CVE. The remaining question is whether an attacker can cause an untrusted/compromised receiver key to be returned by the configured attestation service in a supported deployment without already possessing equivalent control over the client.

## Static chain

### 1. Secure mode is enabled by default

`DeepSeekClient.__init__` defaults to:

```python
is_secure: bool = True
```

The client constructs `jeddak_secure_channel.ClientConfig` without overriding `attest_must`.

### 2. Attestation enforcement is permissive by default

`bytedance/jeddak_secure_channel/ra.py`:

```python
attest_must: bool = False
```

The field documentation states that it controls whether a verification report must be returned before adopting the public key.

### 3. Failed attestation may still install the receiver key

`bytedance/jeddak_secure_channel/client.py`:

```python
if pub_key and not self.config.attest_must:
    self.session_key = ClientSessionKey.load(pub_key)
    return True
```

The remote-attestation implementation can return `public_key_info` while the attestation result is false.

### 4. The installed receiver public key controls the envelope key exchange

`ClientSessionKey.encrypt_stream` generates or receives an AES key and wraps that key with the receiver public key:

```python
encrypted_key = self.server_public_key.encrypt(symmetric_key.key)
```

`encrypt_with_response` retains the same AES key as a `ResponseKey`. A receiver holding the corresponding private key can therefore recover the request AES key and create a valid authenticated encrypted response under that key.

### 5. Legacy secure DeepSeek response reaches unsafe deserialization

For `dp_version < "3.1"`, the secure response path contains:

```python
elm["message"] = pickle.loads(encrypt_key.decrypt(elm["message"]))
```

The request side also uses pickle for that legacy protocol.

## Preconditions observed in source

The unsafe response path requires all of the following:

- `is_secure=True` (the default);
- a legacy `dp_version < "3.1"`;
- the non-OpenAI legacy mode, because legacy versions are rejected when `is_openai=True`;
- a receiver response encrypted under the negotiated response key.

The package contains explicit legacy v2/v3.0 handling, so the path is implemented rather than dead syntax. However, `dp_version` defaults to `3.1`, so the unsafe-deserialization path is not the default DeepSeek protocol.

## Affected-version scope

PyPI exposed one release during the review:

- `0.0.41` — full static chain present.

No earlier package release was available for comparison at review time.

## Public security contract

The package metadata describes the project as providing confidential and secure AI inference and describes `jeddak_secure_channel` as a confidential-computing secure channel with remote-attestation report verification.

That description is relevant to the trust-boundary analysis, but the source also explicitly exposes `attest_must=False`; vendor confirmation is needed to determine whether accepting a key after failed attestation is intended compatibility behavior or violates the supported security contract.

## Weakness candidates

Primary:
- CWE-502 — Deserialization of Untrusted Data.

Contributing trust-boundary weakness, pending vendor interpretation:
- fail-open remote-attestation/public-key acceptance;
- potentially an improper authentication/verification or insecure-default class.

Do not assign a final contributing CWE until the intended attestation contract is confirmed.

## Potential impact

If an attacker can become or control a receiver whose public key is returned while attestation fails, the receiver can derive the response encryption key and choose the authenticated plaintext delivered to the client. In the legacy secure DeepSeek response path, attacker-chosen plaintext reaching `pickle.loads` can result in arbitrary Python object deserialization and potentially client-side code execution.

No exploit payload was created or executed during validation.

## Novelty status

Hunt 002 package-aware OSV and GHSA checks returned no match for `volcengine-python-sdk-aicc 0.0.41`.

A fresh package-aware advisory recheck completed on September 25, 2026:
- OSV: `NO_MATCH`
- GHSA: `NO_MATCH`
- returned public CVE identifiers: none

The package-aware novelty check completed without lookup errors. This does not replace vendor confirmation or broader coordinated-disclosure review.

## Evidence quality

All package evidence was collected from the exact PyPI source artifact identified by the SHA-256 above. Package code was not executed. Review used static archive extraction and static source tracing.

## Manual validation gates before disclosure

The candidate must not be submitted until all are satisfied:

- [x] exact artifact and affected version identified;
- [x] unsafe deserialization sink confirmed;
- [x] encrypted response origin traced to receiver-controlled response data;
- [x] receiver-key adoption after failed attestation confirmed in source;
- [x] response-key cryptographic flow confirmed statically;
- [ ] supported deployment can expose a client to an untrusted/compromised receiver that fails attestation yet receives a usable public key;
- [ ] vendor confirms the fail-open behavior is not an intentional security mode with an explicitly accepted trust model;
- [ ] current public advisory databases still have no equivalent issue;
- [ ] affected configuration/version scope is confirmed by vendor or documentation;
- [ ] disclosure contact and coordinated disclosure plan approved.

## Recommended remediation direction

Without prescribing vendor implementation details, the two risky behaviors should be separated:

1. a secure/attested mode should not silently adopt a receiver key after attestation failure unless the caller has explicitly opted into that weaker trust model; and
2. network/service responses should not be deserialized with Python pickle. A non-code-executing serialization format should be used for legacy compatibility as well.

## Review disposition

Keep in the `NOVEL_CANDIDATE` queue with **manual security-boundary validation required**. Do not call this an assigned CVE and do not disclose automatically.
