# Changelog

All notable changes to QuantumShield will be documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-06-14

### Added

- Express middleware (`shield()`) with zero-config defaults
- Threat detection for SQL injection, NoSQL injection, command injection, XSS, CSRF, path traversal, prototype pollution, ReDoS, and secret leakage
- Sliding-window rate limiter with IP reputation escalation
- Full OWASP security header suite with configurable Content Security Policy
- Traffic baseline and anomaly detection per endpoint
- CRYSTALS-Kyber-768 key encapsulation mechanism (NIST PQC standard)
- CRYSTALS-Dilithium3 digital signatures (NIST PQC standard)
- Quantum-safe token signing as a drop-in JWT replacement
- Hardened entropy mixing for random number generation
- AI agent with real-time threat streaming and pattern correlation
- Interactive CLI REPL (`status`, `threats`, `traffic`, `top`, `explain`)
- Multi-vector attack detection (4+ categories in 60 seconds)
- Escalating attacker detection (3+ events from one IP in 5 minutes)
- Source code scanner for hardcoded secrets and dangerous patterns
- Dependency scanner against known CVEs
- CLI commands: `scan`, `monitor`, `keygen`
- Pluggable `RateLimitStore` interface for Redis/distributed deployments
- `shieldEmitter` event bus for integration with external logging pipelines
- Dry-run mode for shadow-mode rollouts
- Full TypeScript with strict mode, declarations, and source maps
- 40+ tests covering detection, rate limiting, crypto, and token signing
