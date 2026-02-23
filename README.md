# oneid-sdk

Python SDK for [1id.com](https://1id.com) -- hardware-anchored identity for AI agents.

## Quick start

```python
import oneid

# Enroll at declared tier (no HSM needed, always works)
identity = oneid.enroll(request_tier="declared")
print(f"Enrolled: {identity.handle}")

# Get an OAuth2 token for API access
token = oneid.get_token()
headers = {"Authorization": token.authorization_header_value}

# Check identity
me = oneid.whoami()
print(f"I am {me.handle}, trust tier: {me.trust_tier.value}")
```

### Hardware-backed enrollment

```python
# TPM enrollment (sovereign tier) - requires Windows/Linux with TPM 2.0
# Will prompt for UAC/sudo elevation once during enrollment
identity = oneid.enroll(request_tier="sovereign")

# YubiKey enrollment (sovereign-portable tier) - requires YubiKey 5 inserted
identity = oneid.enroll(request_tier="sovereign-portable")

# Virtual TPM (VMware/Hyper-V/QEMU)
identity = oneid.enroll(request_tier="virtual")
```

## Trust tiers

| Tier | Hardware | Sybil Resistant | Trust Level |
|------|----------|-----------------|-------------|
| `sovereign` | TPM (Intel, AMD, Infineon) with valid cert | Yes | Highest |
| `sovereign-portable` | YubiKey / Nitrokey / Feitian with attestation | Yes | Highest |
| `legacy` | Hardware TPM or security key with expired cert | Yes | High |
| `virtual` | VMware / Hyper-V / QEMU vTPM | No | Verified Hardware |
| `enclave` | Apple Secure Enclave (TOFU) | No | Verified Hardware |
| `declared` | None (software keys) | No | Software |

`request_tier` is a **requirement**, not a preference. You get exactly what you ask for, or an exception. No silent fallbacks.

## Key algorithms

Like SSH, agents can choose their preferred key algorithm for declared-tier enrollment:

```python
identity = oneid.enroll(request_tier="declared", key_algorithm="ed25519")     # default, strongest
identity = oneid.enroll(request_tier="declared", key_algorithm="ecdsa-p384")  # NIST P-384
identity = oneid.enroll(request_tier="declared", key_algorithm="rsa-4096")    # legacy compat
```

## Installation

```bash
pip install oneid
```

Requires Python 3.10+.

## License

Apache-2.0
