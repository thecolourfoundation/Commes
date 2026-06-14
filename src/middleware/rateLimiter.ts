/**
 * Rate Limiter & IP Reputation Tracker
 *
 * A sliding-window rate limiter backed by an in-memory store.
 * For multi-instance deployments, replace the Map with a Redis adapter
 * by implementing the RateLimitStore interface below.
 *
 * The IP reputation layer sits on top: IPs that trigger repeated attacks
 * are automatically graduated from "rate-limited" to "blocked" based on
 * their threat history within the current session.
 */

import type { RateLimitConfig, RateLimitEntry, ThreatEvent } from "../types.js";

// ─── Store Interface ──────────────────────────────────────────────────────────

export interface RateLimitStore {
  get(key: string): RateLimitEntry | undefined;
  set(key: string, entry: RateLimitEntry): void;
  delete(key: string): void;
}

class MemoryStore implements RateLimitStore {
  private readonly store = new Map<string, RateLimitEntry>();

  get(key: string): RateLimitEntry | undefined {
    return this.store.get(key);
  }

  set(key: string, entry: RateLimitEntry): void {
    this.store.set(key, entry);
  }

  delete(key: string): void {
    this.store.delete(key);
  }
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

export type RateLimitVerdict = "allowed" | "rate-limited" | "blocked";

export class RateLimiter {
  private readonly store: RateLimitStore;
  private readonly config: RateLimitConfig;

  /**
   * Tracks how many distinct attack events have originated from each IP.
   * Once an IP reaches the threshold, it moves from rate-limited to fully blocked.
   */
  private readonly threatCount = new Map<string, number>();
  private static readonly BLOCK_THRESHOLD = 3;

  constructor(config: RateLimitConfig, store?: RateLimitStore) {
    this.config = config;
    this.store = store ?? new MemoryStore();

    // Prune stale entries every 5 minutes to prevent unbounded memory growth
    setInterval(() => this.prune(), 300_000).unref();
  }

  /**
   * Check whether an IP should be allowed, rate-limited, or blocked.
   * Call this before any other processing — it's the outermost gate.
   */
  check(ip: string): RateLimitVerdict {
    const now = Date.now();

    // IPs that have triggered repeated attacks are blocked outright
    if ((this.threatCount.get(ip) ?? 0) >= RateLimiter.BLOCK_THRESHOLD) {
      return "blocked";
    }

    let entry = this.store.get(ip);

    // If we have an active block, honour it
    if (entry?.blockedUntil !== undefined && entry.blockedUntil > now) {
      return "blocked";
    }

    // If the rate window has expired, reset the counter
    if (!entry || now - entry.windowStart > this.config.windowMs) {
      entry = { count: 1, windowStart: now };
      this.store.set(ip, entry);
      return "allowed";
    }

    // Increment within the current window
    entry.count++;
    this.store.set(ip, entry);

    if (entry.count > this.config.maxRequests) {
      entry.blockedUntil = now + this.config.blockDurationMs;
      this.store.set(ip, entry);
      return "rate-limited";
    }

    return "allowed";
  }

  /**
   * Record that an attack event was attributed to this IP.
   * After enough events, the IP is promoted to permanently blocked
   * for the lifetime of this process.
   */
  recordThreat(event: ThreatEvent): void {
    if (event.severity === "low") return; // Low-severity events don't count toward IP reputation

    const current = this.threatCount.get(event.source.ip) ?? 0;
    this.threatCount.set(event.source.ip, current + 1);
  }

  reputationScore(ip: string): number {
    return this.threatCount.get(ip) ?? 0;
  }

  private prune(): void {
    const now = Date.now();
    // We can't iterate a generic store, so this only works with MemoryStore.
    // Custom stores should implement their own TTL mechanism.
    if (this.store instanceof MemoryStore) {
      // Access the internal Map via the typed store reference
      const ms = this.store as MemoryStore & { store: Map<string, RateLimitEntry> };
      for (const [key, entry] of ms["store"]) {
        const expired =
          now - entry.windowStart > this.config.windowMs &&
          (entry.blockedUntil === undefined || entry.blockedUntil < now);
        if (expired) ms["store"].delete(key);
      }
    }
  }
}
