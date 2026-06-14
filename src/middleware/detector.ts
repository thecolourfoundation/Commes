/**
 * Threat Detection Engine
 *
 * Every request that enters your application passes through here.
 * This module is the Snyk half of QuantumShield: it knows what attacks
 * look like at the payload level and either blocks them or surfaces them
 * for the AI agent to explain.
 *
 * The detection patterns are not copied from generic lists. Each one was
 * written to minimise false positives while catching real attack payloads —
 * the kind found in real CVEs and HackerOne disclosures, not contrived demos.
 */

import { createHash } from "crypto";
import type {
  ThreatCategory,
  ThreatSeverity,
  ThreatEvent,
  ThreatVerdict,
} from "../types.js";

// ─── Pattern Library ──────────────────────────────────────────────────────────

/**
 * SQL injection patterns that account for encoding tricks, comment obfuscation,
 * and the classic UNION-based exfiltration chain.
 */
const SQL_PATTERNS: RegExp[] = [
  /(\bUNION\b.{0,30}\bSELECT\b)/i,
  /(\bSELECT\b.{0,50}\bFROM\b)/i,
  /(\bINSERT\b\s+\bINTO\b)/i,
  /(\bDROP\b\s+\bTABLE\b)/i,
  /(\bDELETE\b\s+\bFROM\b)/i,
  /(\bEXEC\b\s*\()/i,
  /(\bEXECUTE\b\s*\()/i,
  /(--|#|\/\*).{0,20}(SELECT|INSERT|DROP|DELETE|UPDATE)/i,
  /\b(OR|AND)\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/i,
  /'\s*(OR|AND)\s+'[\w\d]+'\s*=\s*'/i,
  /\b(SLEEP|BENCHMARK|WAITFOR)\s*\(/i,
  /\bINFORMATION_SCHEMA\b/i,
  /\bLOAD_FILE\s*\(/i,
  /\bINTO\s+(OUTFILE|DUMPFILE)\b/i,
];

/**
 * NoSQL injection — primarily targeting MongoDB's query operators,
 * which are trivially injected via JSON bodies.
 */
const NOSQL_PATTERNS: RegExp[] = [
  /\$where\s*:/i,
  /\$gt\s*:\s*['"]?\s*['"]?/,
  /\$ne\s*:/,
  /\$or\s*:\s*\[/,
  /\$regex\s*:/i,
  /\$expr\s*:/i,
  /\$function\s*:/i,
  /mapReduce\s*\(/i,
  /\$accumulator\s*:/i,
];

/**
 * Command injection — shell metacharacters and interpreter invocations
 * that can break out of a subprocess call or template context.
 */
const CMD_PATTERNS: RegExp[] = [
  /[;&|`]\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|php|nc|ncat)/i,
  /\$\(.*\)/,                          // $(command)
  /`[^`]+`/,                           // `command`
  /\|\s*(bash|sh|cmd|powershell)/i,
  /(^|[^a-z])(\/bin\/|\/usr\/bin\/)/i,
  /\bexec\s*\(/i,
  /\bsystem\s*\(/i,
  /\bpopen\s*\(/i,
  /\bpassthru\s*\(/i,
  /\beval\s*\(/i,
];

/**
 * XSS — covering reflected, stored, and DOM-based vectors.
 * Note the encoding bypasses: decimal, hex, and Unicode escapes.
 */
const XSS_PATTERNS: RegExp[] = [
  /<script[\s>]/i,
  /<\/script>/i,
  /javascript\s*:/i,
  /on(load|error|click|mouse|key|focus|blur|change|submit|reset|select|input|drag|drop|scroll|touch|pointer)\s*=/i,
  /<iframe[\s>]/i,
  /<object[\s>]/i,
  /<embed[\s>]/i,
  /<svg[\s>][^>]*on/i,
  /&#x[0-9a-f]{2,4};/i,               // Hex entity encoding
  /&#\d{2,4};/,                        // Decimal entity encoding
  /\u202e|\u200b|\u200c|\u200d/,       // Zero-width + bidirectional override
  /expression\s*\([^)]*\)/i,           // CSS expression()
  /url\s*\(\s*javascript/i,
];

/**
 * Path traversal — directory climbing attempts, including encoding variants
 * that bypass naive string checks.
 */
const PATH_TRAVERSAL_PATTERNS: RegExp[] = [
  /\.\.[\/\\]/,
  /\.\.%2[fF]/,
  /\.\.%5[cC]/,
  /%2e%2e[\/\\]/i,
  /\.\.(\/|\\){2,}/,
  /\/etc\/(passwd|shadow|hosts|crontab)/i,
  /\/proc\/(self|[0-9]+)\//i,
  /[cC]:\\(Windows|Users|Program\s*Files)/,
  /(boot\.ini|win\.ini|system\.ini)/i,
];

/**
 * Prototype pollution — targeting the `__proto__` and `constructor`
 * keys that can silently corrupt JavaScript's object prototype chain.
 */
const PROTO_PATTERNS: RegExp[] = [
  /__proto__/,
  /constructor\s*\[/,
  /prototype\s*\[/,
  /"__proto__"\s*:/,
  /"constructor"\s*:\s*\{/,
  /Object\.prototype/,
];

/**
 * Secret leakage — API keys, tokens, and credentials that should never
 * appear in request bodies, headers, or query strings.
 */
const SECRET_PATTERNS: RegExp[] = [
  /sk-[a-zA-Z0-9]{20,}/,              // OpenAI secret key
  /AKIA[0-9A-Z]{16}/,                  // AWS access key
  /gh[pousr]_[A-Za-z0-9_]{36,}/,      // GitHub PATs
  /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
  /-----BEGIN OPENSSH PRIVATE KEY-----/,
  /[a-f0-9]{40}/,                      // Git commit-looking tokens / SHA-1 secrets
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/,   // Raw bearer tokens
  /password\s*[:=]\s*['"]?[^'"&\s]{8,}/i,
  /passwd\s*[:=]\s*['"]?[^'"&\s]{8,}/i,
  /api[_-]?key\s*[:=]\s*['"]?[^\s'"&]{16,}/i,
];

/**
 * ReDoS — regular expressions with catastrophic backtracking potential
 * embedded inside request data, attempting to cause denial of service in
 * any downstream regex engine.
 */
const REDOS_PATTERNS: RegExp[] = [
  /(\w+)+$/,                           // Exponential backtracking trigger
  /([a-zA-Z]+)*$/,
  /\(a+\)+$/,
];

// ─── Classifier ───────────────────────────────────────────────────────────────

interface DetectionResult {
  matched: boolean;
  category?: ThreatCategory;
  severity?: ThreatSeverity;
  evidence?: string;
}

function scanString(input: string): DetectionResult {
  // SQL injection
  for (const p of SQL_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "sql-injection",
        severity: "critical",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // NoSQL injection
  for (const p of NOSQL_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "nosql-injection",
        severity: "high",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // Command injection
  for (const p of CMD_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "command-injection",
        severity: "critical",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // XSS
  for (const p of XSS_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "xss",
        severity: "high",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // Path traversal
  for (const p of PATH_TRAVERSAL_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "path-traversal",
        severity: "high",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // Prototype pollution
  for (const p of PROTO_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "prototype-pollution",
        severity: "high",
        evidence: m[0].substring(0, 80),
      };
    }
  }

  // Secret leakage (flag, not block — you may legitimately POST an API key to your own endpoint)
  for (const p of SECRET_PATTERNS) {
    const m = p.exec(input);
    if (m) {
      return {
        matched: true,
        category: "secret-leakage",
        severity: "medium",
        evidence: `${m[0].substring(0, 12)}[redacted]`,
      };
    }
  }

  return { matched: false };
}

/**
 * Recursively flatten a nested object into an array of string leaves
 * so we can scan every value in a request body regardless of depth.
 */
function flattenValues(obj: unknown, depth = 0): string[] {
  if (depth > 10) return []; // Guard against deeply nested DoS payloads
  if (typeof obj === "string") return [obj];
  if (typeof obj === "number" || typeof obj === "boolean") return [String(obj)];
  if (Array.isArray(obj)) return obj.flatMap((v) => flattenValues(v, depth + 1));
  if (obj !== null && typeof obj === "object") {
    return Object.entries(obj).flatMap(([k, v]) => [
      k,
      ...flattenValues(v, depth + 1),
    ]);
  }
  return [];
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface InspectTarget {
  ip: string;
  method?: string;
  path?: string;
  query?: Record<string, unknown>;
  headers?: Record<string, unknown>;
  body?: unknown;
  userAgent?: string;
}

let eventCounter = 0;

function generateId(): string {
  return createHash("sha256")
    .update(`${Date.now()}-${++eventCounter}-${Math.random()}`)
    .digest("hex")
    .substring(0, 16);
}

/**
 * Inspect an incoming request for all known attack signatures.
 *
 * Returns a ThreatEvent if something was found, or null if the request
 * looks clean. The caller decides what to do with the event.
 */
export function inspect(target: InspectTarget): ThreatEvent | null {
  const candidates: string[] = [];

  if (target.path) candidates.push(target.path);
  if (target.query) candidates.push(...flattenValues(target.query));
  if (target.body) candidates.push(...flattenValues(target.body));

  // Scan headers selectively — not the full object, just values that
  // a user controls (skip standard headers like Content-Type).
  const headerAllowList = ["user-agent", "referer", "x-forwarded-for", "x-custom-header"];
  if (target.headers) {
    for (const [key, value] of Object.entries(target.headers)) {
      if (headerAllowList.some((h) => key.toLowerCase().includes(h))) {
        candidates.push(...flattenValues(value));
      }
    }
  }

  for (const candidate of candidates) {
    const result = scanString(candidate);
    if (result.matched && result.category && result.severity) {
      const verdict: ThreatVerdict =
        result.category === "secret-leakage" ? "flagged" : "blocked";

      return {
        id: generateId(),
        timestamp: new Date(),
        category: result.category,
        severity: result.severity,
        verdict,
        source: {
          ip: target.ip,
          userAgent: target.userAgent,
          path: target.path,
          method: target.method,
        },
        evidence: result.evidence ?? "(redacted)",
        explanation: buildExplanation(result.category),
        recommendation: buildRecommendation(result.category),
        quantumRisk: false,
      };
    }
  }

  return null;
}

// ─── Human-Readable Explanations ─────────────────────────────────────────────

function buildExplanation(category: ThreatCategory): string {
  const map: Record<ThreatCategory, string> = {
    "sql-injection":
      "The request contains SQL syntax that, if executed by a database, could read, modify, or destroy data. Classic vectors include UNION-based exfiltration and boolean-based blind injection.",
    "nosql-injection":
      "MongoDB query operators ($where, $ne, $gt) were detected in user-supplied input. These can bypass authentication or exfiltrate documents by manipulating query logic.",
    "command-injection":
      "Shell metacharacters or interpreter names were found in the request. If passed to exec() or a template engine, an attacker could run arbitrary commands on your server.",
    "xss":
      "The payload contains HTML tags or JavaScript event handlers. In a reflected or stored context, this would execute attacker-controlled script in a victim's browser.",
    "csrf":
      "The request lacks a valid cross-site request forgery token. This suggests it may have originated from a third-party page rather than your own UI.",
    "path-traversal":
      "Directory traversal sequences (../, %2e%2e/) were detected. These are used to escape the intended file directory and read sensitive files like /etc/passwd.",
    "prototype-pollution":
      "__proto__ or constructor keys were found in the request body. Merging this into a plain object would corrupt JavaScript's prototype chain for all objects in the process.",
    "regex-dos":
      "The input matches the signature of a ReDoS payload — data crafted to trigger catastrophic backtracking in regular expressions, causing CPU exhaustion.",
    "brute-force":
      "This source IP has exceeded the request threshold for this endpoint, consistent with a brute-force or credential-stuffing attack.",
    "ip-reputation":
      "The source IP is on the blocklist, either from a prior attack or a known-malicious network range.",
    "secret-leakage":
      "A pattern matching an API key, private key, or credential was detected in the request body. This may indicate a misconfigured client sending secrets it should keep local.",
    "dependency-vulnerability":
      "A known CVE was found in one of your declared dependencies. An attacker who knows your stack can target this vulnerability directly.",
    "anomaly":
      "The request deviates significantly from the established baseline for this endpoint — unusual size, timing, or structure.",
    "quantum-downgrade":
      "The connection negotiated a classical cipher suite (RSA/ECDSA) when post-quantum key exchange was expected. This may indicate a downgrade attack.",
  };

  return map[category] ?? "An unclassified security anomaly was detected.";
}

function buildRecommendation(category: ThreatCategory): string {
  const map: Record<ThreatCategory, string> = {
    "sql-injection":
      "Use parameterised queries or a query builder (Knex, Prisma) exclusively. Never concatenate user input into SQL strings.",
    "nosql-injection":
      "Validate and strip MongoDB operators from user input before passing to queries. Use a schema validation library like Zod or Joi at the boundary.",
    "command-injection":
      "Avoid passing user input to child_process functions. If unavoidable, use execFile() with an explicit argument array — never exec() with a shell string.",
    "xss":
      "Encode all output for the context in which it appears (HTML, JS, CSS, URL). Use a Content Security Policy header to restrict script sources.",
    "csrf":
      "Issue a cryptographically random CSRF token per session and validate it on all state-changing requests. SameSite=Strict cookies also mitigate this class.",
    "path-traversal":
      "Resolve the full path with path.resolve() and assert it begins with the intended root directory before opening any file.",
    "prototype-pollution":
      "Use Object.create(null) for dictionaries. Validate all incoming JSON against a strict schema before merging. Freeze Object.prototype in entry points.",
    "regex-dos":
      "Audit regexes for nested quantifiers. Use a safe regex library (safe-regex, re2) for patterns applied to user input.",
    "brute-force":
      "Enforce rate limiting on authentication endpoints. Implement exponential back-off and account lockout after N failures.",
    "ip-reputation":
      "Block the IP at the load balancer or CDN level. Investigate whether the IP belongs to a proxy or VPN range that needs a different policy.",
    "secret-leakage":
      "Audit the client sending this request. Secrets should be stored in environment variables or a vault, never in request payloads.",
    "dependency-vulnerability":
      "Run `npm audit fix` and review the changelog for the patched version. Pin to the fixed version in your lockfile.",
    "anomaly":
      "Review the raw request in the event log. If this is a legitimate new usage pattern, update the baseline. Otherwise, investigate the source IP.",
    "quantum-downgrade":
      "Ensure both client and server are configured to prefer CRYSTALS-Kyber key exchange. Reject connections that fall back to classical suites in high-security contexts.",
  };

  return map[category] ?? "Review the flagged request and apply input validation at the entry point.";
}
