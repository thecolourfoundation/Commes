#!/usr/bin/env node
/**
 * QuantumShield CLI
 *
 * The command-line interface for the QuantumShield agent and scanner.
 * Designed to feel like a tool built by people who use terminals —
 * clear output, no unnecessary noise, helpful errors.
 */

"use strict";

const { Command } = require("commander");
const path = require("path");

const program = new Command();

program
  .name("quantumshield")
  .description("Quantum-resistant security agent and scanner for Node.js applications")
  .version("1.0.0");

// ─── Scan Command ─────────────────────────────────────────────────────────────

program
  .command("scan [directory]")
  .description("Scan a project directory for vulnerabilities and hardcoded secrets")
  .option("-d, --deps-only", "Only scan dependencies (skip source files)")
  .option("-s, --source-only", "Only scan source files (skip dependencies)")
  .option("--no-color", "Disable colour output")
  .action(async (directory, options) => {
    const targetDir = directory
      ? path.resolve(directory)
      : process.cwd();

    const useColor = options.color !== false;
    const c = makeColors(useColor);

    console.log();
    console.log(c.bold(c.cyan("  QuantumShield Scanner")));
    console.log(c.gray(`  Scanning ${targetDir}`));
    console.log();

    // Spinner
    const frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let frameIndex = 0;
    const spinner = setInterval(() => {
      process.stdout.write(
        `\r  ${c.cyan(frames[frameIndex % frames.length])}  Scanning...`
      );
      frameIndex++;
    }, 80);

    try {
      // Dynamic import to avoid loading the full module at startup
      const { scan } = require("../dist/scanner/index.js");
      const result = await scan({
        root: targetDir,
        depsOnly: options.depsOnly || false,
        sourceOnly: options.sourceOnly || false,
      });

      clearInterval(spinner);
      process.stdout.write("\r" + " ".repeat(40) + "\r");

      if (!result.vulnerable) {
        console.log(c.green("  ✓ No vulnerabilities found."));
        console.log();
        process.exit(0);
        return;
      }

      // Group findings by severity
      const bySeverity = { critical: [], high: [], medium: [], low: [] };
      for (const finding of result.findings) {
        bySeverity[finding.severity]?.push(finding);
      }

      const totalCount = result.findings.length;
      console.log(c.red(`  ✗ Found ${totalCount} issue${totalCount !== 1 ? "s" : ""}`));
      console.log();

      const severityOrder = ["critical", "high", "medium", "low"];
      for (const severity of severityOrder) {
        const findings = bySeverity[severity];
        if (!findings || findings.length === 0) continue;

        const severityLabel = {
          critical: c.red(c.bold("  CRITICAL")),
          high: c.yellow(c.bold("  HIGH    ")),
          medium: c.magenta(c.bold("  MEDIUM  ")),
          low: c.gray(c.bold("  LOW     ")),
        }[severity];

        for (const finding of findings) {
          console.log(`${severityLabel}  ${c.bold(finding.category)}`);
          console.log(c.gray(`           ${finding.location}`));
          console.log(`           ${finding.detail}`);
          console.log();
        }
      }

      // Exit code 1 if critical or high findings exist
      const hasBlockingIssues =
        bySeverity.critical.length > 0 || bySeverity.high.length > 0;
      process.exit(hasBlockingIssues ? 1 : 0);
    } catch (err) {
      clearInterval(spinner);
      process.stdout.write("\r" + " ".repeat(40) + "\r");
      console.error(c.red("  Error during scan:"), err instanceof Error ? err.message : String(err));
      process.exit(2);
    }
  });

// ─── Monitor Command ──────────────────────────────────────────────────────────

program
  .command("monitor")
  .description("Start the AI agent in interactive monitoring mode")
  .option("--no-color", "Disable colour output")
  .option("-q, --quiet", "Concise output — one line per event instead of full detail")
  .action((options) => {
    try {
      const { Agent } = require("../dist/agent/index.js");

      const agent = new Agent({
        verbosity: options.quiet ? "concise" : "verbose",
        streamEvents: true,
        color: options.color !== false,
      });

      agent.start(true);
    } catch (err) {
      console.error("Failed to start agent:", err instanceof Error ? err.message : String(err));
      console.error("Make sure you've run `npm run build` first, or install from npm.");
      process.exit(1);
    }
  });

// ─── Keygen Command ───────────────────────────────────────────────────────────

program
  .command("keygen")
  .description("Generate a Dilithium3 post-quantum signing key pair")
  .option("-o, --output <dir>", "Directory to write keys to", ".")
  .action((options) => {
    const c = makeColors(true);
    try {
      const { dilithiumKeyGen } = require("../dist/crypto/quantum.js");
      const fs = require("fs");
      const outDir = path.resolve(options.output);

      const keyPair = dilithiumKeyGen();
      const pubPath = path.join(outDir, "qs-public.key");
      const privPath = path.join(outDir, "qs-private.key");

      fs.writeFileSync(pubPath, keyPair.publicKey.toString("hex"), { mode: 0o644 });
      fs.writeFileSync(privPath, keyPair.privateKey.toString("hex"), { mode: 0o600 });

      console.log();
      console.log(c.green("  ✓ Key pair generated (CRYSTALS-Dilithium3)"));
      console.log(c.gray(`    Public key  → ${pubPath}`));
      console.log(c.gray(`    Private key → ${privPath}`));
      console.log();
      console.log(c.yellow("  ⚠ Keep the private key out of source control."));
      console.log(c.gray("    Add qs-private.key to your .gitignore immediately."));
      console.log();
    } catch (err) {
      console.error(c.red("  Keygen failed:"), err instanceof Error ? err.message : String(err));
      process.exit(1);
    }
  });

// ─── Colour Utilities (inline to avoid runtime dep in CLI) ───────────────────

function makeColors(enabled) {
  if (!enabled) {
    const id = (s) => s;
    return { red: id, yellow: id, green: id, cyan: id, magenta: id, gray: id, bold: id };
  }
  return {
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    green: (s) => `\x1b[32m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
    magenta: (s) => `\x1b[35m${s}\x1b[0m`,
    gray: (s) => `\x1b[90m${s}\x1b[0m`,
    bold: (s) => `\x1b[1m${s}\x1b[0m`,
  };
}

program.parse(process.argv);
