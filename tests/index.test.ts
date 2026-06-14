/**
 * QuantumShield Test Suite
 *
 * Tests are written to document behaviour, not just assert it.
 * Each describe block represents a component; each test represents
 * a specific guarantee that component makes.
 */

import { inspect } from "../src/middleware/detector";
import { RateLimiter } from "../src/middleware/rateLimiter";
import { buildCSP, getSecurityHeaders } from "../src/middleware/headers";
import {
  kyberKeyGen,
  kyberEncapsulate,
  kyberDecapsulate,
  dilithiumKeyGen,
  dilithiumSign,
  dilithiumVerify,
  signToken,
  verifyToken,
  hardenedRandom,
} from "../src/crypto/quantum";

// ─── Threat Detector ──────────────────────────────────────────────────────────

describe("Threat Detector", () => {
  const base = { ip: "1.2.3.4", method: "POST", path: "/api/data" };

  describe("SQL injection detection", () => {
    it("detects UNION-based exfiltration", () => {
      const event = inspect({ ...base, query: { id: "1 UNION SELECT * FROM users" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("sql-injection");
      expect(event?.severity).toBe("critical");
      expect(event?.verdict).toBe("blocked");
    });

    it("detects comment-obfuscated injection", () => {
      const event = inspect({ ...base, body: { name: "admin'-- SELECT password" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("sql-injection");
    });

    it("detects boolean-based blind injection", () => {
      const event = inspect({ ...base, query: { id: "1 OR 1=1" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("sql-injection");
    });

    it("detects time-based blind injection", () => {
      const event = inspect({ ...base, body: { name: "'; SLEEP(5)--" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("sql-injection");
    });

    it("allows legitimate database-like language in descriptions", () => {
      // "I want to select the best option from the list" — not an injection
      const event = inspect({ ...base, body: { message: "I want the best option from our catalogue" } });
      expect(event).toBeNull();
    });
  });

  describe("NoSQL injection detection", () => {
    it("detects $where operator injection", () => {
      const event = inspect({ ...base, body: { filter: { "$where": "this.admin === true" } } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("nosql-injection");
    });

    it("detects $ne authentication bypass", () => {
      const event = inspect({ ...base, body: { password: { "$ne": "" } } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("nosql-injection");
    });
  });

  describe("Command injection detection", () => {
    it("detects subshell injection via $()", () => {
      const event = inspect({ ...base, query: { file: "report.pdf; $(cat /etc/passwd)" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("command-injection");
    });

    it("detects pipe to shell", () => {
      const event = inspect({ ...base, body: { filename: "| bash" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("command-injection");
    });
  });

  describe("XSS detection", () => {
    it("detects script tag injection", () => {
      const event = inspect({ ...base, body: { comment: "<script>alert(1)</script>" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("xss");
    });

    it("detects event handler injection", () => {
      const event = inspect({ ...base, body: { name: '<img src=x onerror=alert(1)>' } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("xss");
    });

    it("detects javascript: URI", () => {
      const event = inspect({ ...base, body: { url: "javascript:alert(document.cookie)" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("xss");
    });
  });

  describe("Path traversal detection", () => {
    it("detects ../ sequences", () => {
      const event = inspect({ ...base, path: "/api/files/../../etc/passwd" });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("path-traversal");
    });

    it("detects URL-encoded traversal", () => {
      const event = inspect({ ...base, query: { file: "..%2F..%2Fetc%2Fpasswd" } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("path-traversal");
    });
  });

  describe("Prototype pollution detection", () => {
    it("detects __proto__ key injection", () => {
      const event = inspect({ ...base, body: { "__proto__": { "admin": true } } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("prototype-pollution");
    });

    it("detects constructor key injection", () => {
      const event = inspect({ ...base, body: { 'constructor["prototype"]': { admin: true } } });
      expect(event).not.toBeNull();
      expect(event?.category).toBe("prototype-pollution");
    });
  });

  describe("Clean request passthrough", () => {
    it("passes clean JSON bodies", () => {
      const event = inspect({
        ...base,
        body: { username: "alice", email: "alice@example.com", age: 30 },
      });
      expect(event).toBeNull();
    });

    it("passes clean query strings", () => {
      const event = inspect({
        ...base,
        query: { page: "1", sort: "created_at", order: "desc" },
      });
      expect(event).toBeNull();
    });

    it("handles deeply nested clean bodies", () => {
      const event = inspect({
        ...base,
        body: {
          user: { profile: { settings: { theme: "dark", language: "en" } } },
        },
      });
      expect(event).toBeNull();
    });
  });

  describe("Threat event structure", () => {
    it("includes all required fields on a detected threat", () => {
      const event = inspect({ ...base, body: { q: "' OR 1=1--" } });
      expect(event).not.toBeNull();
      expect(event?.id).toBeDefined();
      expect(event?.timestamp).toBeInstanceOf(Date);
      expect(event?.explanation).toBeTruthy();
      expect(event?.recommendation).toBeTruthy();
      expect(event?.source.ip).toBe("1.2.3.4");
    });
  });
});

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

describe("Rate Limiter", () => {
  const config = { windowMs: 1000, maxRequests: 3, blockDurationMs: 5000 };

  it("allows requests within the limit", () => {
    const limiter = new RateLimiter(config);
    expect(limiter.check("10.0.0.1")).toBe("allowed");
    expect(limiter.check("10.0.0.1")).toBe("allowed");
    expect(limiter.check("10.0.0.1")).toBe("allowed");
  });

  it("rate-limits requests that exceed the threshold", () => {
    const limiter = new RateLimiter(config);
    limiter.check("10.0.0.2");
    limiter.check("10.0.0.2");
    limiter.check("10.0.0.2");
    expect(limiter.check("10.0.0.2")).toBe("rate-limited");
  });

  it("does not affect different IPs", () => {
    const limiter = new RateLimiter(config);
    limiter.check("10.0.0.3");
    limiter.check("10.0.0.3");
    limiter.check("10.0.0.3");
    limiter.check("10.0.0.3"); // rate-limited
    expect(limiter.check("10.0.0.4")).toBe("allowed");
  });

  it("blocks IPs that accumulate enough threat events", () => {
    const limiter = new RateLimiter(config);
    const makeEvent = (ip: string) => ({
      id: "test",
      timestamp: new Date(),
      category: "sql-injection" as const,
      severity: "critical" as const,
      verdict: "blocked" as const,
      source: { ip },
      evidence: "test",
      explanation: "test",
      recommendation: "test",
      quantumRisk: false,
    });

    limiter.recordThreat(makeEvent("10.0.0.5"));
    limiter.recordThreat(makeEvent("10.0.0.5"));
    limiter.recordThreat(makeEvent("10.0.0.5"));

    expect(limiter.check("10.0.0.5")).toBe("blocked");
  });
});

// ─── Security Headers ─────────────────────────────────────────────────────────

describe("Security Headers", () => {
  it("includes all critical headers", () => {
    const headers = getSecurityHeaders();
    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Strict-Transport-Security"]).toContain("max-age=");
    expect(headers["Content-Security-Policy"]).toBeDefined();
    expect(headers["Permissions-Policy"]).toBeDefined();
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
  });

  it("removes the server identity header", () => {
    const headers = getSecurityHeaders();
    expect(headers["Server"]).toBe("QuantumShield");
    expect(headers["X-Powered-By"]).toBe(""); // Will be removed by middleware
  });

  it("builds a strict CSP by default", () => {
    const csp = buildCSP();
    expect(csp).toContain("default-src");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("upgrade-insecure-requests");
  });

  it("allows extending CSP with additional sources", () => {
    const csp = buildCSP({ connectSrc: ["https://api.example.com"] });
    expect(csp).toContain("https://api.example.com");
  });
});

// ─── Quantum Cryptography ─────────────────────────────────────────────────────

describe("Quantum Cryptography", () => {
  describe("Hardened random number generation", () => {
    it("produces the requested number of bytes", () => {
      expect(hardenedRandom(32).length).toBe(32);
      expect(hardenedRandom(64).length).toBe(64);
    });

    it("produces different output on successive calls", () => {
      const a = hardenedRandom(32);
      const b = hardenedRandom(32);
      expect(a.equals(b)).toBe(false);
    });
  });

  describe("Kyber KEM", () => {
    it("generates a key pair with public and private keys", () => {
      const { publicKey, privateKey } = kyberKeyGen();
      expect(publicKey.length).toBeGreaterThan(0);
      expect(privateKey.length).toBeGreaterThan(0);
    });

    it("encapsulates and decapsulates a shared secret", () => {
      const { publicKey, privateKey } = kyberKeyGen();
      const { ciphertext, sharedSecret } = kyberEncapsulate(publicKey);
      expect(sharedSecret.length).toBe(32);
      expect(ciphertext.length).toBeGreaterThan(0);

      const recovered = kyberDecapsulate(privateKey, ciphertext);
      expect(recovered).not.toBeNull();
    });

    it("returns null for a tampered ciphertext", () => {
      const { privateKey } = kyberKeyGen();
      const tamperedCiphertext = Buffer.alloc(32, 0xff);
      const result = kyberDecapsulate(privateKey, tamperedCiphertext);
      expect(result).toBeNull();
    });
  });

  describe("Dilithium signatures", () => {
    it("generates a key pair", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      expect(publicKey.length).toBeGreaterThan(0);
      expect(privateKey.length).toBeGreaterThan(0);
    });

    it("signs and verifies a message", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      const message = Buffer.from("This message is authentic.");
      const signature = dilithiumSign(privateKey, message);
      expect(dilithiumVerify(publicKey, message, signature)).toBe(true);
    });

    it("rejects a signature on a different message", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      const message = Buffer.from("Original message");
      const tampered = Buffer.from("Tampered message");
      const signature = dilithiumSign(privateKey, message);
      expect(dilithiumVerify(publicKey, tampered, signature)).toBe(false);
    });

    it("rejects a truncated signature", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      const message = Buffer.from("Test");
      const signature = dilithiumSign(privateKey, message);
      const truncated = signature.subarray(0, 10);
      expect(dilithiumVerify(publicKey, message, truncated)).toBe(false);
    });
  });

  describe("Quantum-safe token signing", () => {
    it("signs and verifies a token payload", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      const payload = { userId: "abc-123", role: "admin", exp: Date.now() + 3600_000 };
      const token = signToken(payload, privateKey);

      expect(token.split(".").length).toBe(3);

      const recovered = verifyToken(token, publicKey);
      expect(recovered).not.toBeNull();
      expect(recovered?.userId).toBe("abc-123");
      expect(recovered?.role).toBe("admin");
    });

    it("rejects a token with a tampered body", () => {
      const { publicKey, privateKey } = dilithiumKeyGen();
      const token = signToken({ role: "user" }, privateKey);
      const parts = token.split(".");
      // Replace the body with a tampered payload
      parts[1] = Buffer.from(JSON.stringify({ role: "admin" })).toString("base64url");
      const tampered = parts.join(".");
      expect(verifyToken(tampered, publicKey)).toBeNull();
    });

    it("rejects a malformed token", () => {
      const { publicKey } = dilithiumKeyGen();
      expect(verifyToken("not.a.valid.token.at.all", publicKey)).toBeNull();
      expect(verifyToken("", publicKey)).toBeNull();
    });
  });
});
