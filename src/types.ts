/**
 * Core type definitions for QuantumShield.
 *
 * These types are the contract between every layer of the system —
 * from the middleware that intercepts requests to the AI agent that
 * explains what happened and why.
 */

// ─── Threat Classification ────────────────────────────────────────────────────

export type ThreatCategory =
  | "sql-injection"
  | "nosql-injection"
  | "command-injection"
  | "xss"
  | "csrf"
  | "path-traversal"
  | "prototype-pollution"
  | "regex-dos"
  | "brute-force"
  | "ip-reputation"
  | "secret-leakage"
  | "dependency-vulnerability"
  | "anomaly"
  | "quantum-downgrade";

export type ThreatSeverity = "low" | "medium" | "high" | "critical";

export type ThreatVerdict = "blocked" | "flagged" | "allowed" | "rate-limited";

export interface ThreatEvent {
  id: string;
  timestamp: Date;
  category: ThreatCategory;
  severity: ThreatSeverity;
  verdict: ThreatVerdict;
  source: {
    ip: string;
    userAgent?: string;
    path?: string;
    method?: string;
  };
  evidence: string;
  explanation: string;
  recommendation: string;
  quantumRisk: boolean;
}

// ─── Configuration ────────────────────────────────────────────────────────────

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
  blockDurationMs: number;
}

export interface QuantumCryptoConfig {
  /**
   * Whether to reject connections that do not advertise support for
   * post-quantum key exchange. Useful for internal services where you
   * control both ends of the connection.
   */
  enforcePostQuantumHandshake: boolean;
  /**
   * The lattice-based signature scheme to use for token signing.
   * CRYSTALS-Dilithium (dilithium3) is the NIST-standardised default.
   */
  signatureScheme: "dilithium3" | "dilithium5" | "falcon512";
}

export interface AgentConfig {
  /**
   * How the agent speaks. "concise" gives one-line summaries.
   * "verbose" gives the full explanation with recommendations.
   */
  verbosity: "concise" | "verbose";
  /**
   * Whether the agent should print in real time as threats arrive,
   * or batch events and summarise on demand.
   */
  streamEvents: boolean;
  /**
   * Colour output. Disable for CI environments or log pipelines.
   */
  color: boolean;
}

export interface ShieldConfig {
  /**
   * Paths that bypass all security checks entirely.
   * Keep this list as short as possible — health checks and nothing else.
   */
  whitelist?: string[];
  /**
   * IPs that are permanently blocked before any other check runs.
   */
  blacklist?: string[];
  rateLimit: RateLimitConfig;
  quantum: QuantumCryptoConfig;
  agent: AgentConfig;
  /**
   * When true, threats are logged and explained but never blocked.
   * Useful for a shadow-mode rollout where you want to observe before enforcing.
   */
  dryRun?: boolean;
}

export const defaultConfig: ShieldConfig = {
  whitelist: [],
  blacklist: [],
  rateLimit: {
    windowMs: 60_000,
    maxRequests: 100,
    blockDurationMs: 300_000,
  },
  quantum: {
    enforcePostQuantumHandshake: false,
    signatureScheme: "dilithium3",
  },
  agent: {
    verbosity: "verbose",
    streamEvents: true,
    color: true,
  },
  dryRun: false,
};

// ─── Internal State ───────────────────────────────────────────────────────────

export interface RateLimitEntry {
  count: number;
  windowStart: number;
  blockedUntil?: number;
}

export interface ScanResult {
  vulnerable: boolean;
  findings: Array<{
    category: ThreatCategory;
    severity: ThreatSeverity;
    location: string;
    detail: string;
  }>;
}
