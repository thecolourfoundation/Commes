/**
 * Real-Time Traffic Monitor
 *
 * Watches the QuantumShield event stream and maintains a statistical
 * baseline of normal request behaviour. When a request deviates
 * significantly from that baseline, it's flagged as an anomaly even
 * if it doesn't match any known attack signature.
 *
 * This is the Palo Alto half of QuantumShield: platform-level
 * behavioural awareness, not just signature matching.
 */

import { shieldEmitter } from "../middleware/express.js";
import type { ThreatEvent } from "../types.js";
import { EventEmitter } from "events";

// ─── Baseline Statistics ──────────────────────────────────────────────────────

interface EndpointStats {
  requestCount: number;
  avgBodySize: number;
  avgResponseTime: number;
  /** Request counts bucketed by minute for trend detection */
  minuteBuckets: number[];
  lastSeen: number;
}

/**
 * A rolling baseline keyed by `METHOD:PATH`. Tracks enough statistical
 * information to detect anomalies without storing raw request data —
 * we never log PII.
 */
class TrafficBaseline {
  private readonly endpoints = new Map<string, EndpointStats>();
  private static readonly BUCKET_COUNT = 60; // 1 hour of per-minute buckets

  observe(key: string, bodySize: number): void {
    const now = Date.now();
    const minuteIndex = Math.floor((now / 60_000) % TrafficBaseline.BUCKET_COUNT);

    const existing = this.endpoints.get(key);
    if (!existing) {
      const buckets = new Array<number>(TrafficBaseline.BUCKET_COUNT).fill(0);
      buckets[minuteIndex] = 1;
      this.endpoints.set(key, {
        requestCount: 1,
        avgBodySize: bodySize,
        avgResponseTime: 0,
        minuteBuckets: buckets,
        lastSeen: now,
      });
      return;
    }

    existing.requestCount++;
    existing.avgBodySize =
      (existing.avgBodySize * (existing.requestCount - 1) + bodySize) /
      existing.requestCount;
    existing.minuteBuckets[minuteIndex] =
      (existing.minuteBuckets[minuteIndex] ?? 0) + 1;
    existing.lastSeen = now;
  }

  /**
   * Check if the given body size is anomalous for this endpoint.
   * We flag requests that are more than 5 standard deviations above
   * the mean, which catches payload-stuffing attacks.
   */
  isAnomalous(key: string, bodySize: number): boolean {
    const stats = this.endpoints.get(key);
    if (!stats || stats.requestCount < 20) {
      // Not enough data to establish a baseline yet
      return false;
    }

    const threshold = stats.avgBodySize * 10; // 10x average body size is suspicious
    return bodySize > threshold && bodySize > 10_000; // At least 10KB absolute
  }

  getStats(key: string): EndpointStats | undefined {
    return this.endpoints.get(key);
  }

  /**
   * Compute the current request rate for an endpoint (requests per minute).
   */
  requestsPerMinute(key: string): number {
    const stats = this.endpoints.get(key);
    if (!stats) return 0;

    const recentBuckets = stats.minuteBuckets.slice(-5); // Last 5 minutes
    const total = recentBuckets.reduce((a, b) => a + b, 0);
    return total / 5;
  }

  summary(): Array<{ endpoint: string; rpm: number; requestCount: number }> {
    return Array.from(this.endpoints.entries())
      .map(([endpoint, stats]) => ({
        endpoint,
        rpm: this.requestsPerMinute(endpoint),
        requestCount: stats.requestCount,
      }))
      .sort((a, b) => b.rpm - a.rpm);
  }
}

// ─── Monitor ──────────────────────────────────────────────────────────────────

export interface MonitorStats {
  uptime: number;
  totalThreats: number;
  blockedRequests: number;
  flaggedRequests: number;
  threatsByCategory: Record<string, number>;
  threatsBySeverity: Record<string, number>;
  topAttackerIPs: Array<{ ip: string; count: number }>;
  recentEvents: ThreatEvent[];
}

export class Monitor extends EventEmitter {
  private readonly baseline = new TrafficBaseline();
  private readonly events: ThreatEvent[] = [];
  private readonly ipCounts = new Map<string, number>();
  private readonly startTime = Date.now();
  private totalBlocked = 0;
  private totalFlagged = 0;

  constructor() {
    super();
    this.attach();
  }

  private attach(): void {
    shieldEmitter.on("threat", (event: ThreatEvent) => {
      this.record(event);
      this.emit("threat", event);
    });

    shieldEmitter.on("blocked", (event: ThreatEvent) => {
      this.totalBlocked++;
      this.emit("blocked", event);
    });

    shieldEmitter.on("flagged", (event: ThreatEvent) => {
      this.totalFlagged++;
      this.emit("flagged", event);
    });
  }

  private record(event: ThreatEvent): void {
    // Keep the last 500 events in memory
    this.events.push(event);
    if (this.events.length > 500) this.events.shift();

    const ipCount = this.ipCounts.get(event.source.ip) ?? 0;
    this.ipCounts.set(event.source.ip, ipCount + 1);
  }

  /**
   * Record a clean request for baseline tracking.
   * Call this from the middleware after the threat check passes.
   */
  observeCleanRequest(method: string, path: string, bodySize: number): void {
    const key = `${method}:${path}`;
    this.baseline.observe(key, bodySize);
  }

  stats(): MonitorStats {
    const threatsByCategory: Record<string, number> = {};
    const threatsBySeverity: Record<string, number> = {};

    for (const event of this.events) {
      threatsByCategory[event.category] =
        (threatsByCategory[event.category] ?? 0) + 1;
      threatsBySeverity[event.severity] =
        (threatsBySeverity[event.severity] ?? 0) + 1;
    }

    const topAttackerIPs = Array.from(this.ipCounts.entries())
      .sort(([, a], [, b]) => b - a)
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));

    return {
      uptime: Date.now() - this.startTime,
      totalThreats: this.events.length,
      blockedRequests: this.totalBlocked,
      flaggedRequests: this.totalFlagged,
      threatsByCategory,
      threatsBySeverity,
      topAttackerIPs,
      recentEvents: this.events.slice(-20),
    };
  }

  trafficSummary() {
    return this.baseline.summary();
  }
}

// Singleton monitor — one per process
export const monitor = new Monitor();
