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

## Trust tiers

| Tier | Hardware | Sybil resistance |
|------|----------|-----------------|
| `sovereign` | TPM (discrete/firmware) | Highest -- manufacturer-attested |
| `sovereign-portable` | YubiKey/Nitrokey | High -- manufacturer-attested |
| `declared` | None (software keys) | Lowest -- self-asserted |

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
