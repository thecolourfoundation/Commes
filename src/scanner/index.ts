/**
 * Dependency & Code Scanner
 *
 * The Snyk-inspired half of QuantumShield. Rather than intercepting
 * requests, this scanner analyses your project at rest — reading your
 * package.json, auditing dependencies against known CVEs, and scanning
 * source files for hardcoded secrets and dangerous coding patterns.
 *
 * Run this as a pre-commit hook or in CI: `quantumshield scan ./`
 */

import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, extname, relative } from "path";
import type { ScanResult, ThreatCategory, ThreatSeverity } from "../types.js";

// ─── File Scanner ─────────────────────────────────────────────────────────────

/**
 * Patterns that indicate a hardcoded secret in source code.
 * Each has a name, a regex, and a severity — not all hardcoded
 * strings are equally dangerous.
 */
const SOURCE_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  category: ThreatCategory;
  severity: ThreatSeverity;
}> = [
  {
    name: "Hardcoded OpenAI API key",
    pattern: /sk-[a-zA-Z0-9]{20,}/,
    category: "secret-leakage",
    severity: "critical",
  },
  {
    name: "Hardcoded AWS access key",
    pattern: /AKIA[0-9A-Z]{16}/,
    category: "secret-leakage",
    severity: "critical",
  },
  {
    name: "Hardcoded GitHub token",
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/,
    category: "secret-leakage",
    severity: "critical",
  },
  {
    name: "Private key in source",
    pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/,
    category: "secret-leakage",
    severity: "critical",
  },
  {
    name: "eval() usage",
    pattern: /\beval\s*\(/,
    category: "command-injection",
    severity: "high",
  },
  {
    name: "exec() with string argument",
    pattern: /exec\s*\(\s*[`'"]/,
    category: "command-injection",
    severity: "high",
  },
  {
    name: "Prototype assignment via bracket notation",
    pattern: /\[['"]__proto__['"]\]/,
    category: "prototype-pollution",
    severity: "high",
  },
  {
    name: "SQL string concatenation",
    pattern: /query\s*[=+]\s*['"`][^'"`;]*\+\s*(req|params|body|query)/,
    category: "sql-injection",
    severity: "critical",
  },
  {
    name: "Inline TODO with credentials",
    pattern: /\/\/\s*(TODO|FIXME|HACK)\s*:?[^:]*\b(password|secret|key|token)\b/i,
    category: "secret-leakage",
    severity: "medium",
  },
  {
    name: "HTTP (non-TLS) URL hardcoded",
    pattern: /http:\/\/(?!localhost|127\.|0\.0\.0\.0)/,
    category: "anomaly",
    severity: "low",
  },
];

// File extensions worth scanning
const SCANNABLE_EXTENSIONS = new Set([
  ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
  ".json", ".env", ".yml", ".yaml", ".toml",
]);

// Directories to always skip
const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next",
  "coverage", ".cache", "tmp",
]);

function scanFile(filePath: string): ScanResult["findings"] {
  const findings: ScanResult["findings"] = [];

  let content: string;
  try {
    content = readFileSync(filePath, "utf-8");
  } catch {
    return findings;
  }

  const lines = content.split("\n");

  for (const { name, pattern, category, severity } of SOURCE_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line && pattern.test(line)) {
        findings.push({
          category,
          severity,
          location: `${filePath}:${i + 1}`,
          detail: `${name} — ${redactLine(line.trim())}`,
        });
        break; // One finding per pattern per file is enough
      }
    }
  }

  return findings;
}

function redactLine(line: string): string {
  // Show the first 60 chars, redact the rest to avoid printing secrets into logs
  return line.length > 60 ? line.substring(0, 60) + "…[redacted]" : line;
}

function walkDirectory(dir: string, maxDepth = 8, depth = 0): string[] {
  if (depth > maxDepth) return [];

  const results: string[] = [];
  let entries: string[];

  try {
    entries = readdirSync(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;

    const fullPath = join(dir, entry);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isDirectory()) {
      results.push(...walkDirectory(fullPath, maxDepth, depth + 1));
    } else if (SCANNABLE_EXTENSIONS.has(extname(entry))) {
      results.push(fullPath);
    }
  }

  return results;
}

// ─── Dependency Scanner ───────────────────────────────────────────────────────

/**
 * A curated list of packages with known critical CVEs.
 * In production, augment this by fetching the OSV.dev or GitHub Advisory
 * Database API — the scanner is architecturally ready for that.
 */
const KNOWN_VULNERABLE: Record<string, { below: string; cve: string; summary: string }[]> = {
  "lodash": [
    {
      below: "4.17.21",
      cve: "CVE-2021-23337",
      summary: "Prototype pollution via zipObjectDeep and template functions",
    },
  ],
  "axios": [
    {
      below: "1.6.0",
      cve: "CVE-2023-45857",
      summary: "CSRF vulnerability — custom headers stripped on redirect",
    },
  ],
  "jsonwebtoken": [
    {
      below: "9.0.0",
      cve: "CVE-2022-23529",
      summary: "Arbitrary file read via secretOrPublicKey parameter",
    },
  ],
  "express": [
    {
      below: "4.19.2",
      cve: "CVE-2024-29041",
      summary: "Open redirect in res.redirect()",
    },
  ],
  "semver": [
    {
      below: "7.5.2",
      cve: "CVE-2022-25883",
      summary: "ReDoS via untrusted version strings",
    },
  ],
  "tough-cookie": [
    {
      below: "4.1.3",
      cve: "CVE-2023-26136",
      summary: "Prototype pollution via cookie jar",
    },
  ],
};

function parseVersion(v: string): number[] {
  return v
    .replace(/^[^0-9]*/, "")
    .split(".")
    .map((n) => parseInt(n, 10) || 0);
}

function versionBelow(version: string, threshold: string): boolean {
  const v = parseVersion(version);
  const t = parseVersion(threshold);
  for (let i = 0; i < 3; i++) {
    const vi = v[i] ?? 0;
    const ti = t[i] ?? 0;
    if (vi < ti) return true;
    if (vi > ti) return false;
  }
  return false;
}

function scanDependencies(projectRoot: string): ScanResult["findings"] {
  const findings: ScanResult["findings"] = [];
  const pkgPath = join(projectRoot, "package.json");

  if (!existsSync(pkgPath)) return findings;

  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
  } catch {
    return findings;
  }

  const allDeps = {
    ...(pkg.dependencies as Record<string, string> | undefined ?? {}),
    ...(pkg.devDependencies as Record<string, string> | undefined ?? {}),
  };

  for (const [name, versionRange] of Object.entries(allDeps)) {
    const knownIssues = KNOWN_VULNERABLE[name];
    if (!knownIssues) continue;

    // Strip range operators to get the installed version
    const version = String(versionRange).replace(/^[\^~>=<*]/, "").trim();

    for (const issue of knownIssues) {
      if (versionBelow(version, issue.below)) {
        findings.push({
          category: "dependency-vulnerability",
          severity: "high",
          location: `package.json → ${name}@${version}`,
          detail: `${issue.cve}: ${issue.summary}. Fix: upgrade to >=${issue.below}`,
        });
      }
    }
  }

  return findings;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ScanOptions {
  /** Root directory to scan. Defaults to process.cwd(). */
  root?: string;
  /** Skip source file scanning, only check dependencies. */
  depsOnly?: boolean;
  /** Skip dependency scanning, only check source files. */
  sourceOnly?: boolean;
}

export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const root = options.root ?? process.cwd();
  const findings: ScanResult["findings"] = [];

  if (!options.sourceOnly) {
    findings.push(...scanDependencies(root));
  }

  if (!options.depsOnly) {
    const files = walkDirectory(root);
    for (const file of files) {
      const relPath = relative(root, file);
      const fileFindings = scanFile(file);
      // Re-label locations as relative paths for cleaner output
      findings.push(...fileFindings.map((f) => ({
        ...f,
        location: f.location.replace(file, relPath),
      })));
    }
  }

  return {
    vulnerable: findings.length > 0,
    findings,
  };
}
