# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

QuantumShield is a security package. If you find a vulnerability in it, please do not open a public GitHub issue — that gives attackers a head start.

Instead, email the maintainer directly with:

- A description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fix if you have one

You'll receive an acknowledgement within 48 hours and a resolution or status update within 7 days.

Once the fix is released, you'll be credited in the changelog unless you prefer to remain anonymous.

## Scope

Things we consider in scope:

- Bypass of any detection pattern in `src/middleware/detector.ts`
- Prototype pollution or injection in the package itself
- Cryptographic weaknesses in `src/crypto/quantum.ts`
- Secrets leaking through logs or HTTP responses
- Denial of service via the scanner or middleware
- Supply chain issues (malicious dependencies)

Things out of scope:

- Vulnerabilities in applications that *use* QuantumShield but don't follow its recommendations
- Theoretical quantum attacks that require hardware not yet in existence
- Social engineering

## Cryptographic Notice

The quantum-resistant primitives in this package implement CRYSTALS-Kyber-768 and CRYSTALS-Dilithium3 — the NIST Post-Quantum Cryptography standard finalists. The pure TypeScript implementations are algorithmically correct but are not hardened against CPU-level timing side-channels. For deployments with the highest security requirements, use native bindings to [liboqs](https://github.com/open-quantum-safe/liboqs).
