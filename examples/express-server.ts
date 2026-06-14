/**
 * QuantumShield — Example Usage
 *
 * A complete example showing QuantumShield protecting an Express
 * application, with the AI agent running alongside it.
 *
 * Run with: ts-node examples/express-server.ts
 */

import express from "express";
import {
  shield,
  Agent,
  shieldEmitter,
  dilithiumKeyGen,
  signToken,
  verifyToken,
  monitor,
} from "../src/index.js";
import type { ThreatEvent } from "../src/index.js";

// ─── Key Generation ───────────────────────────────────────────────────────────
// In production, generate once and persist to a secrets manager.
// Never regenerate on every startup — that invalidates all existing tokens.

const signingKeys = dilithiumKeyGen();

// ─── Express App ──────────────────────────────────────────────────────────────

const app = express();

app.use(express.json({ limit: "512kb" })); // Limit body size before inspection
app.use(express.urlencoded({ extended: true, limit: "512kb" }));

// QuantumShield middleware — the outermost gate after body parsing
app.use(
  shield({
    whitelist: ["/healthz"],
    rateLimit: {
      windowMs: 60_000,
      maxRequests: 100,
      blockDurationMs: 300_000,
    },
    agent: {
      verbosity: "verbose",
      streamEvents: true,
      color: true,
    },
    dryRun: false,
  })
);

// ─── Routes ───────────────────────────────────────────────────────────────────

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

app.post("/auth/login", (req, res) => {
  // In a real app, validate against your database here
  const { username } = req.body as { username?: string };

  if (!username) {
    res.status(400).json({ error: "username is required" });
    return;
  }

  // Issue a quantum-safe signed token
  const token = signToken(
    { sub: username, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + 3600 },
    signingKeys.privateKey
  );

  res.json({ token });
});

app.get("/protected", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    res.status(401).json({ error: "Authorization header required" });
    return;
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token, signingKeys.publicKey);

  if (!payload) {
    res.status(401).json({ error: "Invalid or expired token" });
    return;
  }

  res.json({ message: "Access granted", user: payload });
});

app.get("/stats", (_req, res) => {
  // Expose security stats — in production, protect this endpoint
  res.json(monitor.stats());
});

// ─── Threat Event Logging ─────────────────────────────────────────────────────
// In production, pipe these to your SIEM, Datadog, CloudWatch, etc.

shieldEmitter.on("blocked", (event: ThreatEvent) => {
  // Structured log — do not log the full evidence in production
  // as it may contain fragments of the malicious payload
  process.stdout.write(
    JSON.stringify({
      level: "warn",
      message: "Request blocked",
      id: event.id,
      category: event.category,
      severity: event.severity,
      ip: event.source.ip,
      path: event.source.path,
    }) + "\n"
  );
});

// ─── AI Agent ─────────────────────────────────────────────────────────────────

const agent = new Agent({
  verbosity: "verbose",
  streamEvents: true,
  color: true,
});

// Start the server first, then launch the agent's interactive REPL
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
  agent.start(true); // Opens the interactive REPL
});
