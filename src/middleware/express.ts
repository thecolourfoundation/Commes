/**
 * Express Middleware
 *
 * The glue between QuantumShield's detection engine and your Express
 * application. Drop this in as early as possible in your middleware
 * stack — ideally as the first thing after body parsing.
 *
 * import { shield } from 'quantumshield';
 * app.use(shield());
 */

import type { Request, Response, NextFunction } from "express";
import { inspect } from "./detector.js";
import { RateLimiter } from "./rateLimiter.js";
import { getSecurityHeaders } from "./headers.js";
import type { ShieldConfig, ThreatEvent } from "../types.js";
import { defaultConfig } from "../types.js";
import { EventEmitter } from "events";

// ─── Shield EventEmitter ──────────────────────────────────────────────────────

/**
 * QuantumShield emits events so your application can react to threats
 * beyond simply blocking them — logging, alerting, updating dashboards.
 *
 * shieldEmitter.on('threat', (event: ThreatEvent) => { ... });
 * shieldEmitter.on('blocked', (event: ThreatEvent) => { ... });
 */
export const shieldEmitter = new EventEmitter();

// ─── Middleware Factory ───────────────────────────────────────────────────────

/**
 * Create the QuantumShield middleware with the given configuration.
 *
 * @example
 * import express from 'express';
 * import { shield } from 'quantumshield';
 *
 * const app = express();
 * app.use(express.json());
 * app.use(shield({
 *   dryRun: false,
 *   rateLimit: { windowMs: 60_000, maxRequests: 100, blockDurationMs: 300_000 },
 * }));
 */
export function shield(userConfig: Partial<ShieldConfig> = {}) {
  const config: ShieldConfig = {
    ...defaultConfig,
    ...userConfig,
    rateLimit: { ...defaultConfig.rateLimit, ...userConfig.rateLimit },
    quantum: { ...defaultConfig.quantum, ...userConfig.quantum },
    agent: { ...defaultConfig.agent, ...userConfig.agent },
  };

  const limiter = new RateLimiter(config.rateLimit);
  const securityHeaders = getSecurityHeaders();
  const whitelist = new Set(config.whitelist ?? []);
  const blacklist = new Set(config.blacklist ?? []);

  return function quantumShieldMiddleware(
    req: Request,
    res: Response,
    next: NextFunction
  ): void {
    // Apply security headers to every response — no exceptions
    for (const [key, value] of Object.entries(securityHeaders)) {
      if (value) res.setHeader(key, value);
      else res.removeHeader(key);
    }

    // Whitelisted paths bypass all checks — use sparingly
    if (whitelist.has(req.path)) {
      next();
      return;
    }

    const ip = extractIP(req);

    // Hard-blocked IPs are rejected immediately, before rate limiting
    if (blacklist.has(ip)) {
      const event = makeBlockEvent(ip, req, "ip-reputation", "IP is on the permanent blocklist.");
      emitAndRespond(event, res, config, true);
      return;
    }

    // Rate limiting
    const verdict = limiter.check(ip);
    if (verdict === "blocked" || verdict === "rate-limited") {
      const event = makeBlockEvent(ip, req, "brute-force",
        verdict === "blocked"
          ? "IP has been blocked due to repeated attack events."
          : "Request rate exceeds the configured threshold."
      );
      emitAndRespond(event, res, config, !config.dryRun);
      if (config.dryRun) next();
      return;
    }

    // Threat detection
    const threatEvent = inspect({
      ip,
      method: req.method,
      path: req.path,
      query: req.query as Record<string, unknown>,
      headers: req.headers as Record<string, unknown>,
      body: req.body as unknown,
      userAgent: req.headers["user-agent"],
    });

    if (threatEvent) {
      limiter.recordThreat(threatEvent);
      shieldEmitter.emit("threat", threatEvent);

      if (config.dryRun || threatEvent.verdict === "flagged") {
        // In dry-run or flagged mode, let the request through but log it
        shieldEmitter.emit("flagged", threatEvent);
        next();
        return;
      }

      emitAndRespond(threatEvent, res, config, true);
      return;
    }

    next();
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractIP(req: Request): string {
  // Trust X-Forwarded-For only if you're behind a trusted proxy.
  // In raw deployments, use req.socket.remoteAddress instead.
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    // The leftmost address is the client; the rest are proxies
    return forwarded.split(",")[0]?.trim() ?? req.socket.remoteAddress ?? "unknown";
  }
  return req.socket.remoteAddress ?? "unknown";
}

function makeBlockEvent(
  ip: string,
  req: Request,
  category: ThreatEvent["category"],
  evidence: string
): ThreatEvent {
  const { createHash } = require("crypto") as typeof import("crypto");
  return {
    id: createHash("sha256").update(`${Date.now()}-${ip}`).digest("hex").slice(0, 16),
    timestamp: new Date(),
    category,
    severity: "high",
    verdict: "blocked",
    source: {
      ip,
      userAgent: req.headers["user-agent"],
      path: req.path,
      method: req.method,
    },
    evidence,
    explanation: evidence,
    recommendation: "Review traffic from this IP and consider adding it to your CDN blocklist.",
    quantumRisk: false,
  };
}

function emitAndRespond(
  event: ThreatEvent,
  res: Response,
  config: ShieldConfig,
  block: boolean
): void {
  shieldEmitter.emit("blocked", event);

  if (!block) return;

  res.status(403).json({
    error: "Forbidden",
    // Never leak internal details in the response body — the agent
    // communicates details to the developer, not to the attacker
    message: "This request was blocked by QuantumShield.",
    requestId: event.id,
  });
}
