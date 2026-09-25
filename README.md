# oneid-sdk

Python SDK for [1id.com](https://1id.com) -- hardware-anchored identity for AI agents.

Implements the AIRS (Agent Identity Registry System) drafts:
- `draft-drake-email-hardware-attestation-03` -- email attestation via hardware keys
- `draft-drake-agent-identity-registry-04` -- agent identity registry protocol

## Quick start

```python
import oneid

# Enroll at declared tier (no HSM needed, always works)
identity = oneid.enroll(request_tier="declared", display_name="Sparky")
print(f"Enrolled: {identity.handle}")
# URN: urn:aid:global:id-XXXXX-XXXXX-XXXXX-XXXXX
print(f"URN: {identity.agent_identity_urn}")

# Call an API that accepts 1ID tokens. Tokens are sender-constrained (cnf.jwk):
# each request is signed with your enrolled key (RFC 9421), so a copied token
# alone is refused. This does the signing for you:
response = oneid.send_http_request_with_sender_constrained_token(
  "GET", "https://1id.com/api/v1/identity/devices")
# From the shell: oneid request GET https://1id.com/api/v1/identity/devices

# Check identity
me = oneid.whoami()
print(f"I am {me.handle}, trust tier: {me.trust_tier.value}")
```

### Hardware-backed enrollment

```python
# TPM enrollment (sovereign tier) - requires Windows/Linux with TPM 2.0
identity = oneid.enroll(request_tier="sovereign")

# YubiKey enrollment (portable tier) - requires YubiKey 5 inserted
identity = oneid.enroll(request_tier="portable")

# Virtual TPM (VMware/Hyper-V/QEMU)
identity = oneid.enroll(request_tier="virtual")
```

## Trust tiers

| Tier | Hardware | Sybil Resistant | Trust Level |
|------|----------|-----------------|-------------|
| `sovereign` | TPM (Intel, AMD, Infineon) with valid cert | Yes | Highest |
| `portable` | YubiKey with PIV attestation (other PIV vendors are not yet accepted) | Yes | High |
| `virtual` | VMware / Hyper-V / QEMU vTPM | No | Verified Hardware |
| `declared` | None (software keys) | No | Software |

`request_tier` is a **requirement**, not a preference. You get exactly what you ask for, or an exception. No silent fallbacks.

## Key algorithms

Like SSH, agents can choose their preferred key algorithm for declared-tier enrollment.
Only ECDSA P-256 (the default) and RSA keys can also sign email Hardware-Attestation
(Mode 1) proofs; Ed25519 and P-384 keys work for authentication only:

```python
identity = oneid.enroll(request_tier="declared", key_algorithm="ecdsa-p256")  # default (ES256; signs email)
identity = oneid.enroll(request_tier="declared", key_algorithm="ed25519")     # authentication only
identity = oneid.enroll(request_tier="declared", key_algorithm="rsa-4096")    # RSA (RS256; signs email)
```

## Verifying another agent (peer verification)

```python
import os, oneid

nonce = os.urandom(32)                          # verifier: a fresh challenge
bundle = oneid.sign_challenge(nonce)            # prover: enrolled key + Registrar binding
peer = oneid.verify_peer_identity(nonce, bundle.to_dict())   # verifier
print(peer.agent_identity_urn, peer.trust_tier, peer.hardware_locked)
```

The verifier resolves the peer's identity at the AIRS Registry (it must be
operational), takes the current issuer from there, checks the Registrar
binding against that issuer's published keys, then checks the nonce signature
with the bound key. Trust tier and identity facts never come from the bundle.
This is online by design (a decommissioned identity fails); the Node SDK
(`verifyPeerIdentity`) is equivalent and bundles are interchangeable.

## Installation

```bash
pip install oneid
```

Requires Python 3.10+.

## License

Apache-2.0

