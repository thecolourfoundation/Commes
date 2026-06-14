/**
 * QuantumShield AI Agent
 *
 * The agent is the nerve centre of the system. It sits on top of the
 * monitor, listens to every threat event, and communicates with the
 * developer in natural language. It doesn't just report — it reasons,
 * correlates events, notices patterns, and makes recommendations.
 *
 * The agent also provides an interactive REPL so you can query your
 * application's security posture in plain English while it's running.
 */

import { createInterface } from "readline";
import { monitor } from "../monitor/index.js";
import type { ThreatEvent } from "../types.js";
import type { AgentConfig } from "../types.js";

// ─── Formatting Utilities ─────────────────────────────────────────────────────

// We conditionally apply ANSI codes rather than importing chalk at runtime,
// so the agent works in environments where the terminal doesn't support colour.

type ColorFn = (s: string) => string;

function makeColors(enabled: boolean): {
  red: ColorFn;
  yellow: ColorFn;
  green: ColorFn;
  cyan: ColorFn;
  magenta: ColorFn;
  gray: ColorFn;
  bold: ColorFn;
  dim: ColorFn;
} {
  if (!enabled) {
    const id: ColorFn = (s) => s;
    return {
      red: id, yellow: id, green: id, cyan: id,
      magenta: id, gray: id, bold: id, dim: id,
    };
  }
  return {
    red: (s) => `\x1b[31m${s}\x1b[0m`,
    yellow: (s) => `\x1b[33m${s}\x1b[0m`,
    green: (s) => `\x1b[32m${s}\x1b[0m`,
    cyan: (s) => `\x1b[36m${s}\x1b[0m`,
    magenta: (s) => `\x1b[35m${s}\x1b[0m`,
    gray: (s) => `\x1b[90m${s}\x1b[0m`,
    bold: (s) => `\x1b[1m${s}\x1b[0m`,
    dim: (s) => `\x1b[2m${s}\x1b[0m`,
  };
}

function severityColor(
  severity: ThreatEvent["severity"],
  c: ReturnType<typeof makeColors>
): ColorFn {
  switch (severity) {
    case "critical": return c.red;
    case "high": return c.yellow;
    case "medium": return c.magenta;
    case "low": return c.gray;
  }
}

function formatTimestamp(date: Date): string {
  return date.toTimeString().split(" ")[0] ?? date.toISOString();
}

function formatUptime(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

// ─── Agent ────────────────────────────────────────────────────────────────────

export class Agent {
  private readonly config: AgentConfig;
  private readonly c: ReturnType<typeof makeColors>;
  private rl: ReturnType<typeof createInterface> | null = null;
  private patternBuffer: ThreatEvent[] = [];

  constructor(config: AgentConfig) {
    this.config = config;
    this.c = makeColors(config.color);
  }

  /**
   * Start the agent. It immediately begins listening for events and,
   * if interactive mode is requested, opens the REPL.
   */
  start(interactive = false): void {
    this.printBanner();
    this.attachEventListeners();

    if (interactive) {
      this.startREPL();
    }
  }

  private printBanner(): void {
    const { bold, cyan, gray, green } = this.c;
    console.log();
    console.log(bold(cyan("  ██████╗ ███████╗   ██████╗  ██████╗ ")));
    console.log(bold(cyan("  ██╔═══██╗██╔════╝   ╚════██╗██╔═══██╗")));
    console.log(bold(cyan("  ██║   ██║███████╗    █████╔╝██║   ██║")));
    console.log(bold(cyan("  ██║▄▄ ██║╚════██║   ██╔═══╝ ██║▄▄ ██║")));
    console.log(bold(cyan("  ╚██████╔╝███████║██╗███████╗╚██████╔╝")));
    console.log(bold(cyan("   ╚══▀▀═╝ ╚══════╝╚═╝╚══════╝ ╚══▀▀═╝ ")));
    console.log();
    console.log(bold("  QuantumShield") + gray(" — Quantum-Resistant Security Agent"));
    console.log(gray("  Post-quantum crypto · AI threat analysis · Real-time defence"));
    console.log();
    console.log(green("  ✓ Agent online. Monitoring active."));
    console.log(gray("  Type") + " help " + gray("in the REPL for available commands."));
    console.log();
  }

  private attachEventListeners(): void {
    monitor.on("threat", (event: ThreatEvent) => {
      if (this.config.streamEvents) {
        this.printThreatEvent(event);
        this.analysePattern(event);
      }
    });
  }

  private printThreatEvent(event: ThreatEvent): void {
    const { bold, gray, green, dim } = this.c;
    const color = severityColor(event.severity, this.c);
    const ts = formatTimestamp(event.timestamp);

    if (this.config.verbosity === "concise") {
      console.log(
        gray(`[${ts}]`) + " " +
        color(`[${event.severity.toUpperCase()}]`) + " " +
        bold(event.category) + " " +
        gray(`from ${event.source.ip}`) + " " +
        (event.verdict === "blocked" ? green("→ BLOCKED") : dim("→ flagged"))
      );
      return;
    }

    // Verbose mode
    console.log();
    console.log(color("  ┌─ Threat Detected " + "─".repeat(46)));
    console.log(color("  │") + gray(` [${ts}] `) + bold(event.id));
    console.log(color("  │"));
    console.log(color("  │") + `  Category   : ` + bold(event.category));
    console.log(color("  │") + `  Severity   : ` + color(event.severity.toUpperCase()));
    console.log(color("  │") + `  Verdict    : ` + (event.verdict === "blocked" ? bold(green("BLOCKED")) : bold(dim("FLAGGED"))));
    console.log(color("  │") + `  Source     : ${event.source.ip} ${gray(event.source.method ?? "")} ${gray(event.source.path ?? "")}`);
    console.log(color("  │") + `  Evidence   : ` + dim(event.evidence));
    console.log(color("  │"));
    console.log(color("  │") + `  ${bold("What happened")}`);
    console.log(color("  │") + `  ${event.explanation}`);
    console.log(color("  │"));
    console.log(color("  │") + `  ${bold("What to do")}`);
    console.log(color("  │") + `  ${event.recommendation}`);
    console.log(color("  └" + "─".repeat(64)));
    console.log();
  }

  /**
   * Pattern analysis: look for correlated events that individually might
   * seem low-severity but together suggest a coordinated attack.
   */
  private analysePattern(event: ThreatEvent): void {
    this.patternBuffer.push(event);

    // Keep only the last 5 minutes of events
    const fiveMinutesAgo = Date.now() - 300_000;
    this.patternBuffer = this.patternBuffer.filter(
      (e) => e.timestamp.getTime() > fiveMinutesAgo
    );

    const recentFromSameIP = this.patternBuffer.filter(
      (e) => e.source.ip === event.source.ip
    );

    if (recentFromSameIP.length === 3) {
      // Escalation: same IP has triggered 3 distinct events in 5 minutes
      this.printIntelligenceAlert(
        `Escalating activity from ${event.source.ip}`,
        `This IP has triggered ${recentFromSameIP.length} distinct threat events in the last 5 minutes ` +
        `across categories: ${[...new Set(recentFromSameIP.map((e) => e.category))].join(", ")}. ` +
        `This is consistent with a systematic scan or a multi-vector attack. ` +
        `Consider adding this IP to your CDN blocklist or firewall to cut it off at the edge.`
      );
    }

    const categoriesInLastMinute = new Set(
      this.patternBuffer
        .filter((e) => e.timestamp.getTime() > Date.now() - 60_000)
        .map((e) => e.category)
    );

    if (categoriesInLastMinute.size >= 4) {
      this.printIntelligenceAlert(
        "Multi-vector attack pattern detected",
        `${categoriesInLastMinute.size} different attack categories were detected in the last 60 seconds: ` +
        `${[...categoriesInLastMinute].join(", ")}. ` +
        `This breadth suggests an automated vulnerability scanner (e.g. Nikto, nuclei) or a coordinated ` +
        `attack testing multiple entry points simultaneously. Review your CDN and WAF rules immediately.`
      );
    }
  }

  private printIntelligenceAlert(title: string, detail: string): void {
    const { bold, yellow, gray } = this.c;
    console.log();
    console.log(yellow("  ⚡ INTELLIGENCE ALERT: ") + bold(title));
    console.log(gray("  ") + detail);
    console.log();
  }

  // ─── REPL ──────────────────────────────────────────────────────────────────

  private startREPL(): void {
    this.rl = createInterface({
      input: process.stdin,
      output: process.stdout,
      prompt: this.c.cyan("  qs> "),
      completer: (line: string) => {
        const completions = [
          "status", "threats", "traffic", "help",
          "clear", "scan", "top", "explain", "exit",
        ];
        const hits = completions.filter((c) => c.startsWith(line));
        return [hits.length ? hits : completions, line];
      },
    });

    this.rl.prompt();

    this.rl.on("line", (input: string) => {
      const trimmed = input.trim().toLowerCase();
      this.handleCommand(trimmed);
      this.rl?.prompt();
    });

    this.rl.on("close", () => {
      console.log(this.c.gray("\n  Agent shutting down. Stay safe."));
      process.exit(0);
    });
  }

  private handleCommand(input: string): void {
    const [cmd, ...args] = input.split(" ");

    switch (cmd) {
      case "status":
        this.printStatus();
        break;
      case "threats":
        this.printRecentThreats();
        break;
      case "traffic":
        this.printTrafficSummary();
        break;
      case "top":
        this.printTopAttackers();
        break;
      case "explain":
        this.explainCategory(args.join(" "));
        break;
      case "clear":
        process.stdout.write("\x1Bc");
        this.printBanner();
        break;
      case "exit":
      case "quit":
        this.rl?.close();
        break;
      case "help":
        this.printHelp();
        break;
      case "":
        break;
      default:
        console.log(this.c.gray(`  Unknown command: "${cmd}". Type help to see available commands.`));
    }
  }

  private printStatus(): void {
    const { bold, green, yellow, red, gray, cyan } = this.c;
    const stats = monitor.stats();

    console.log();
    console.log(bold(cyan("  System Status")));
    console.log(gray("  " + "─".repeat(40)));
    console.log(`  Uptime          : ${bold(formatUptime(stats.uptime))}`);
    console.log(`  Total threats   : ${bold(stats.totalThreats.toString())}`);
    console.log(`  Blocked         : ${bold(red(stats.blockedRequests.toString()))}`);
    console.log(`  Flagged         : ${bold(yellow(stats.flaggedRequests.toString()))}`);

    if (Object.keys(stats.threatsByCategory).length > 0) {
      console.log();
      console.log(bold(cyan("  Threats by Category")));
      console.log(gray("  " + "─".repeat(40)));
      const sorted = Object.entries(stats.threatsByCategory)
        .sort(([, a], [, b]) => b - a);
      for (const [cat, count] of sorted) {
        const bar = "█".repeat(Math.min(count, 20));
        console.log(`  ${cat.padEnd(28)} ${green(bar)} ${count}`);
      }
    }

    console.log();
  }

  private printRecentThreats(): void {
    const { bold, gray, cyan } = this.c;
    const { recentEvents } = monitor.stats();

    if (recentEvents.length === 0) {
      console.log(this.c.green("  No threats detected yet."));
      return;
    }

    console.log();
    console.log(bold(cyan("  Recent Threats")));
    console.log(gray("  " + "─".repeat(60)));

    for (const event of recentEvents.slice(-10).reverse()) {
      const color = severityColor(event.severity, this.c);
      console.log(
        `  ${gray(formatTimestamp(event.timestamp))}  ` +
        color(`[${event.severity}]`.padEnd(10)) +
        ` ${event.category.padEnd(26)} ` +
        gray(event.source.ip)
      );
    }
    console.log();
  }

  private printTrafficSummary(): void {
    const { bold, gray, cyan, green } = this.c;
    const summary = monitor.trafficSummary().slice(0, 15);

    if (summary.length === 0) {
      console.log(gray("  No traffic data yet."));
      return;
    }

    console.log();
    console.log(bold(cyan("  Traffic Summary (Top Endpoints)")));
    console.log(gray("  " + "─".repeat(60)));
    console.log(gray("  Endpoint".padEnd(40) + "  RPM".padEnd(10) + "  Total"));
    console.log(gray("  " + "─".repeat(60)));

    for (const { endpoint, rpm, requestCount } of summary) {
      const rpmStr = rpm.toFixed(1).padStart(6);
      console.log(
        `  ${endpoint.substring(0, 38).padEnd(40)}  ` +
        green(rpmStr) + "    " +
        gray(requestCount.toString())
      );
    }
    console.log();
  }

  private printTopAttackers(): void {
    const { bold, red, gray, cyan } = this.c;
    const { topAttackerIPs } = monitor.stats();

    if (topAttackerIPs.length === 0) {
      console.log(this.c.green("  No attackers recorded yet."));
      return;
    }

    console.log();
    console.log(bold(cyan("  Top Attacker IPs")));
    console.log(gray("  " + "─".repeat(40)));

    for (const { ip, count } of topAttackerIPs) {
      const bar = "▰".repeat(Math.min(count, 20));
      console.log(`  ${ip.padEnd(20)} ${red(bar)} ${count} event${count !== 1 ? "s" : ""}`);
    }
    console.log();
  }

  private explainCategory(category: string): void {
    const { bold, cyan, gray } = this.c;

    const explanations: Record<string, { what: string; why: string; fix: string }> = {
      "sql-injection": {
        what: "SQL injection occurs when user-supplied data is interpreted as SQL commands by the database engine.",
        why: "It's the most common critical vulnerability in web applications. A successful injection can exfiltrate your entire database, bypass authentication, or destroy data.",
        fix: "Use parameterised queries. No exceptions. Even if the input 'looks safe', never concatenate user data into SQL strings.",
      },
      "xss": {
        what: "Cross-Site Scripting injects malicious scripts into pages served to other users.",
        why: "XSS lets an attacker steal session cookies, log keystrokes, redirect users, or completely take over a browser session.",
        fix: "Encode all output for its context (HTML, JavaScript, CSS). Set a strict Content Security Policy. Use a templating engine that escapes by default.",
      },
      "prototype-pollution": {
        what: "Prototype pollution corrupts the root Object.prototype by injecting properties through __proto__ or constructor keys.",
        why: "Because all JavaScript objects inherit from Object.prototype, polluting it affects every object in the process — potentially enabling privilege escalation or remote code execution.",
        fix: "Validate all incoming JSON. Use Object.create(null) for dictionaries. Freeze Object.prototype at startup. Avoid deep-merge libraries on untrusted input.",
      },
      "command-injection": {
        what: "Command injection allows an attacker to execute arbitrary shell commands on your server.",
        why: "It's typically game over — an attacker with RCE can read secrets, install backdoors, pivot to your network, and exfiltrate everything.",
        fix: "Never pass user input to shell commands. Use execFile() with explicit argument arrays. Validate and sanitise any path or filename from user input.",
      },
      "brute-force": {
        what: "Brute-force attacks repeatedly attempt to guess credentials or API tokens.",
        why: "Weak or reused passwords are common. Automated tools can try millions of combinations per minute without rate limiting.",
        fix: "Rate-limit authentication endpoints aggressively. Implement exponential back-off. Consider CAPTCHA for login flows. Monitor for credential stuffing patterns.",
      },
    };

    const key = category.toLowerCase().trim();
    const info = explanations[key];

    if (!info) {
      console.log(gray(`  No detailed explanation for "${category}". Try: sql-injection, xss, prototype-pollution, command-injection, brute-force`));
      return;
    }

    console.log();
    console.log(bold(cyan(`  ${key}`)));
    console.log(gray("  " + "─".repeat(60)));
    console.log(`  ${bold("What")}  ${info.what}`);
    console.log();
    console.log(`  ${bold("Why")}   ${info.why}`);
    console.log();
    console.log(`  ${bold("Fix")}   ${info.fix}`);
    console.log();
  }

  private printHelp(): void {
    const { bold, cyan, gray } = this.c;
    console.log();
    console.log(bold(cyan("  QuantumShield Agent Commands")));
    console.log(gray("  " + "─".repeat(50)));
    const commands = [
      ["status", "Show overall threat statistics and uptime"],
      ["threats", "List the 10 most recent threat events"],
      ["traffic", "Show request rate by endpoint"],
      ["top", "List the top attacker IP addresses"],
      ["explain <type>", "Deep-dive on a threat category"],
      ["clear", "Clear the terminal and reprint the banner"],
      ["exit", "Shut down the agent"],
    ];
    for (const [cmd, desc] of commands) {
      console.log(`  ${bold(cmd.padEnd(20))} ${gray(desc)}`);
    }
    console.log();
    console.log(gray("  Examples: explain xss  |  explain sql-injection  |  top"));
    console.log();
  }
}
