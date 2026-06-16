# Commes

A quantum-resistant, AI-powered security layer for Node.js applications.

Commes combines platform-level threat detection with developer-first vulnerability defence and post-quantum cryptographic primitives — all surfaced through an AI agent that talks to you in plain English while your application runs.

---

## What it does

**Threat detection** — every incoming request is inspected for SQL injection, NoSQL injection, command injection, XSS, path traversal, prototype pollution, CSRF, and secret leakage before it reaches your handlers.

**Rate limiting and IP reputation** — a sliding-window rate limiter tracks request volume per IP. IPs that trigger repeated attack events are automatically graduated from rate-limited to fully blocked. The reputation system is stateful across the session.

**Behavioural anomaly detection** — a traffic baseline is maintained for each endpoint. Requests that deviate significantly from established patterns are flagged even when they don't match a known signature.

**Post-quantum cryptography** — token signing uses CRYSTALS-Dilithium3, the NIST-standardised lattice-based signature scheme. Key encapsulation uses CRYSTALS-Kyber-768. Both are secure against Shor's algorithm running on a cryptographically-relevant quantum computer.

**Security headers** — every response gets the full OWASP-recommended header suite: strict CSP, HSTS, X-Frame-Options, Permissions-Policy, Cross-Origin-*-Policy, and more.

**Dependency and source scanning** — the CLI scanner audits your `package.json` against known CVEs and walks your source tree looking for hardcoded secrets, dangerous patterns like `eval()`, and unsafe shell invocations.

**AI agent** — an interactive CLI agent listens to the event stream, prints structured threat reports, correlates events across IPs, detects multi-vector attack patterns, and answers your questions about what's happening and why.

---

## Installation

```bash
npm install commes
```

Node.js 18 or later is required.

---

## Quick start

### Express middleware

```typescript
import express from 'express';
import { shield } from 'commes';

const app = express();

// Parse bodies before Commes so it can inspect them
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Drop this in as early as possible in your middleware stack
app.use(shield({
  rateLimit: {
    windowMs: 60_000,    // 1-minute window
    maxRequests: 100,    // requests per window per IP
    blockDurationMs: 300_000, // block for 5 minutes after threshold
  },
  whitelist: ['/healthz'], // paths that bypass all checks
  dryRun: false,           // set true to observe without blocking
}));

app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000);
```

### Listening to threat events

```typescript
import { shieldEmitter } from 'commes';

// Fires for every detected threat, blocked or flagged
shieldEmitter.on('threat', (event) => {
  console.log(`[${event.severity}] ${event.category} from ${event.source.ip}`);
  // Forward to your logging pipeline, Slack, PagerDuty, etc.
});

// Fires only for requests that were actually blocked
shieldEmitter.on('blocked', (event) => {
  myLogger.warn('Request blocked', { event });
});
```

### AI agent alongside your server

```typescript
import { Agent } from 'commes';

const agent = new Agent({
  verbosity: 'verbose',   // 'concise' for one-liners, 'verbose' for full detail
  streamEvents: true,     // print events as they arrive
  color: true,
});

agent.start(true); // true = open the interactive REPL
```

### Post-quantum token signing

```typescript
import { dilithiumKeyGen, signToken, verifyToken } from 'commes';

// Generate a key pair once and store the private key securely
const { publicKey, privateKey } = dilithiumKeyGen();

// Sign a payload (equivalent to JWT signing, but quantum-resistant)
const token = signToken({ userId: '123', role: 'admin' }, privateKey);

// Verify — returns the payload or null if the signature is invalid
const payload = verifyToken(token, publicKey);
if (!payload) {
  throw new Error('Invalid token');
}
```

---

## CLI

### Scan a project

```bash
npx commes scan ./
npx commes scan ./ --deps-only    # only check package.json
npx commes scan ./ --source-only  # only check source files
```

The scanner exits with code 1 if any critical or high severity findings are present, making it straightforward to fail CI pipelines on vulnerable builds.

### Start the interactive agent

```bash
npx commes monitor
npx commes monitor --quiet  # one-line-per-event mode
```

**Agent REPL commands:**

| Command | Description |
|---|---|
| `status` | Overall threat statistics and uptime |
| `threats` | The 10 most recent threat events |
| `traffic` | Request rate by endpoint |
| `top` | Top attacker IP addresses |
| `explain <type>` | Deep explanation of a threat category |
| `clear` | Clear the terminal |
| `exit` | Shut down the agent |

Examples: `explain xss` · `explain sql-injection` · `explain prototype-pollution`

### Generate a post-quantum key pair

```bash
npx commes keygen
npx commes keygen --output ./keys
```

Add the generated `qs-private.key` to your `.gitignore` immediately.

---

## Configuration reference

```typescript
interface ShieldConfig {
  // Paths that bypass all security checks. Health checks only.
  whitelist?: string[];

  // IPs blocked before any other check runs.
  blacklist?: string[];

  rateLimit: {
    windowMs: number;         // Rolling window in milliseconds
    maxRequests: number;      // Maximum requests per window per IP
    blockDurationMs: number;  // How long to block after threshold is hit
  };

  quantum: {
    // Reject connections without post-quantum key exchange advertisement.
    // Only useful for internal services where you control both ends.
    enforcePostQuantumHandshake: boolean;

    // Lattice-based signature scheme for token signing.
    signatureScheme: 'dilithium3' | 'dilithium5' | 'falcon512';
  };

  agent: {
    verbosity: 'concise' | 'verbose';
    streamEvents: boolean;  // Print events in real time
    color: boolean;         // ANSI colour output
  };

  // Observe without blocking. Events are still emitted and logged.
  dryRun?: boolean;
}
```

---

## Cryptographic primitives

Commes implements the NIST Post-Quantum Cryptography standard finalists:

**CRYSTALS-Kyber-768** — a lattice-based key encapsulation mechanism (KEM) whose security reduces to the hardness of the Module Learning With Errors (MLWE) problem. Used for quantum-safe key exchange.

**CRYSTALS-Dilithium3** — a lattice-based digital signature scheme whose security reduces to the hardness of Module-LWE and Module-Short Integer Solution (MSIS). Used for token signing.

Both algorithms are secure against known quantum attacks, including Shor's algorithm (which breaks RSA and ECDSA) and Grover's algorithm (which halves the effective security of symmetric keys).

For a production deployment handling regulated data, replace the pure-TypeScript implementations with native bindings to [liboqs](https://github.com/open-quantum-safe/liboqs) or [AWS s2n-tls](https://github.com/aws/s2n-tls) to obtain constant-time guarantees and side-channel resistance.

---

## Multi-instance deployments

The default rate limiter and IP reputation tracker use in-memory stores, which means state is not shared across processes. For multi-instance or clustered deployments, implement the `RateLimitStore` interface and back it with Redis:

```typescript
import { shield } from 'commes';
import type { RateLimitStore, RateLimitEntry } from 'commes';
import { createClient } from 'redis';

class RedisStore implements RateLimitStore {
  constructor(private readonly client: ReturnType<typeof createClient>) {}

  get(key: string): RateLimitEntry | undefined {
    // Redis is async; wrap in a synchronous cache or use a different pattern
    // (see docs/redis-store.md for a full async adapter example)
    return undefined;
  }

  set(key: string, entry: RateLimitEntry): void {
    void this.client.setEx(`qs:${key}`, 3600, JSON.stringify(entry));
  }

  delete(key: string): void {
    void this.client.del(`qs:${key}`);
  }
}
```

---

## Security of the package itself

Commes is designed to not be a liability:

- **No telemetry.** Nothing leaves your machine except the HTTP responses your application sends.
- **No eval.** The package never calls `eval()`, `Function()`, or any dynamic code execution.
- **Minimal dependencies.** The runtime dependency list is kept deliberately short to minimise the supply-chain attack surface.
- **Secrets are never logged.** The evidence field in threat events is always redacted before printing. Full payloads are never stored.
- **Constant-time comparisons.** All security-critical comparisons use `crypto.timingSafeEqual` to prevent timing oracle attacks.
- **Responses never leak internals.** Blocked requests receive a generic 403 with a request ID only. The threat detail is communicated to the developer via the agent, not to the attacker via the response body.

---

## Limitations

Commes is a strong first line of defence, not a complete security programme. It does not replace:

- A properly configured WAF or CDN (Cloudflare, AWS WAF) at the network edge
- Secrets management (Vault, AWS Secrets Manager, environment variables)
- Secure authentication (passkeys, MFA, session management)
- Dependency updates and patch management
- Security testing (penetration testing, DAST, SAST)
- Proper access control and least-privilege architecture

No tool prevents every attack. Security is a practice, not a product.

---

## Contributing

Issues and pull requests are welcome. Please run `npm test` before submitting and include a test case for any new detection patterns.

---

## License

MIT
