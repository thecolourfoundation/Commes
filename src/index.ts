/**
 * QuantumShield
 *
 * A quantum-resistant, AI-powered security layer for Node.js applications.
 * Combines platform-level threat detection (à la Palo Alto Networks) with
 * developer-first vulnerability defence (à la Snyk) and post-quantum
 * cryptographic primitives from the NIST PQC standard.
 *
 * @example
 * // Express middleware
 * import express from 'express';
 * import { shield, Agent } from 'quantumshield';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(shield({ rateLimit: { windowMs: 60_000, maxRequests: 50 } }));
 *
 * // AI agent (separate process or alongside your server)
 * const agent = new Agent({ verbosity: 'verbose', streamEvents: true, color: true });
 * agent.start(true); // true = interactive REPL
 *
 * @example
 * // CLI scanning
 * // $ quantumshield scan ./
 * // $ quantumshield monitor
 */

// Middleware
export { shield, shieldEmitter } from "./middleware/express.js";
export { getSecurityHeaders, buildCSP, generateNonce } from "./middleware/headers.js";
export { RateLimiter } from "./middleware/rateLimiter.js";
export type { RateLimitStore } from "./middleware/rateLimiter.js";

// Threat detection
export { inspect } from "./middleware/detector.js";
export type { InspectTarget } from "./middleware/detector.js";

// Scanner
export { scan } from "./scanner/index.js";
export type { ScanOptions } from "./scanner/index.js";

// Monitor
export { monitor, Monitor } from "./monitor/index.js";
export type { MonitorStats } from "./monitor/index.js";

// Agent
export { Agent } from "./agent/index.js";

// Quantum cryptography
export {
  kyberKeyGen,
  kyberEncapsulate,
  kyberDecapsulate,
  dilithiumKeyGen,
  dilithiumSign,
  dilithiumVerify,
  signToken,
  verifyToken,
  hardenedRandom,
} from "./crypto/quantum.js";
export type { KyberKeyPair, KyberEncapsulation, DilithiumKeyPair } from "./crypto/quantum.js";

// Types
export type {
  ThreatEvent,
  ThreatCategory,
  ThreatSeverity,
  ThreatVerdict,
  ShieldConfig,
  AgentConfig,
  RateLimitConfig,
  QuantumCryptoConfig,
  ScanResult,
} from "./types.js";

export { defaultConfig } from "./types.js";
