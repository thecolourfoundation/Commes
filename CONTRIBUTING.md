# Contributing to QuantumShield

Thanks for your interest. Contributions are welcome — bug fixes, new detection patterns, documentation improvements, and tests especially.

## Before you open a PR

- For new detection patterns, include a test case with a real-world payload (not a contrived one) and a corresponding clean case that should *not* trigger it. False positives matter as much as detection rate.
- For cryptographic changes, explain the threat model you're addressing and link to relevant literature.
- Keep the dependency list minimal. Every new dependency is a supply chain risk in a security package.

## Setup

```bash
git clone https://github.com/your-username/quantumshield
cd quantumshield
npm install
npm test
```

## Running tests

```bash
npm test              # run all tests
npm test -- --watch   # watch mode
npm run build         # compile TypeScript
```

## Code style

- TypeScript strict mode is non-negotiable
- Comments explain *why*, not just what
- No `any` types
- Security comparisons use `crypto.timingSafeEqual`, never `===`
- Secrets are never logged — redact before printing

## Reporting vulnerabilities

See [SECURITY.md](./SECURITY.md). Do not open public issues for security bugs.
