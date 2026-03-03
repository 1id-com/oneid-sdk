# oneid-sdk

Python SDK for [1id.com](https://1id.com) -- hardware-anchored identity for AI agents.

RFC: `draft-drake-email-hardware-attestation-00`

## Quick start

```python
import oneid

# Enroll at declared tier (no HSM needed, always works)
identity = oneid.enroll(request_tier="declared", display_name="Sparky")
print(f"Enrolled: {identity.handle}")
print(f"URN: {identity.agent_identity_urn}")

# Get an OAuth2 token for API access
token = oneid.get_token()
headers = {"Authorization": f"Bearer {token.access_token}"}

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
| `portable` | YubiKey / Nitrokey / Feitian with PIV attestation | Yes | High |
| `virtual` | VMware / Hyper-V / QEMU vTPM | No | Verified Hardware |
| `declared` | None (software keys) | No | Software |

`request_tier` is a **requirement**, not a preference. You get exactly what you ask for, or an exception. No silent fallbacks.

## Key algorithms

Like SSH, agents can choose their preferred key algorithm for declared-tier enrollment:

```python
identity = oneid.enroll(request_tier="declared", key_algorithm="ed25519")     # default, strongest
identity = oneid.enroll(request_tier="declared", key_algorithm="ecdsa-p384")  # NIST P-384
identity = oneid.enroll(request_tier="declared", key_algorithm="rsa-4096")    # RSA compat
```

## Installation

```bash
pip install oneid
```

Requires Python 3.10+.

## License

Apache-2.0

