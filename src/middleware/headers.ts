/**
 * Security Headers
 *
 * HTTP response headers are one of the cheapest defenses available — a
 * single middleware that runs on every response and eliminates entire
 * classes of browser-side attacks. This module applies the full suite
 * recommended by OWASP, hardened with a strict Content Security Policy.
 *
 * Each header is documented with what it does and what it prevents,
 * because headers that developers don't understand tend to get quietly
 * removed when something breaks.
 */

export interface SecurityHeaders {
  [key: string]: string;
}

export interface CSPOptions {
  /**
   * Additional script sources beyond 'self'. Avoid 'unsafe-inline' —
   * if you need inline scripts, use a nonce (generateNonce()) instead.
   */
  scriptSrc?: string[];
  /**
   * Additional style sources. Prefer externalising inline styles to avoid
   * needing 'unsafe-inline' here.
   */
  styleSrc?: string[];
  /**
   * Domains your application fetches data from (APIs, CDNs).
   */
  connectSrc?: string[];
  /**
   * Allowed image sources. 'data:' is common for inline images but
   * should be combined with strict object-src to limit XSS via SVG.
   */
  imgSrc?: string[];
  /**
   * Report-URI for CSP violations. Set this to an endpoint you control
   * to get real-time visibility into policy violations.
   */
  reportUri?: string;
}

/**
 * Build a strict Content Security Policy header value.
 * The default policy is deny-by-default for every directive,
 * with only 'self' permitted for scripts and styles.
 */
export function buildCSP(options: CSPOptions = {}): string {
  const directives: string[] = [
    // Scripts: only your own origin, and explicitly no inline or eval
    `script-src 'self'${options.scriptSrc ? " " + options.scriptSrc.join(" ") : ""}`,

    // Styles: same policy as scripts
    `style-src 'self'${options.styleSrc ? " " + options.styleSrc.join(" ") : ""}`,

    // Objects and plugins: block entirely — Flash, Java applets, etc.
    "object-src 'none'",

    // Frames: block entirely to prevent clickjacking via CSP (belt and suspenders with X-Frame-Options)
    "frame-src 'none'",
    "frame-ancestors 'none'",

    // Base tag: prevent base tag injection from hijacking relative URLs
    "base-uri 'self'",

    // Form submissions: only to your own origin
    "form-action 'self'",

    // Images: allow data URIs for inline images (common legitimate use)
    `img-src 'self' data:${options.imgSrc ? " " + options.imgSrc.join(" ") : ""}`,

    // Fonts: only your own origin
    "font-src 'self'",

    // Fetch/XHR: allow configured external APIs
    `connect-src 'self'${options.connectSrc ? " " + options.connectSrc.join(" ") : ""}`,

    // Media: your own origin only
    "media-src 'self'",

    // Workers: your own origin only (prevents malicious service worker injection)
    "worker-src 'self'",

    // Manifest: your own origin
    "manifest-src 'self'",

    // Upgrade all HTTP requests to HTTPS automatically
    "upgrade-insecure-requests",
  ];

  if (options.reportUri) {
    directives.push(`report-uri ${options.reportUri}`);
  }

  return directives.join("; ");
}

/**
 * The full set of security headers to apply to every response.
 * These are the OWASP-recommended headers plus a few additions
 * that defend against specific modern attack vectors.
 */
export function getSecurityHeaders(cspOptions?: CSPOptions): SecurityHeaders {
  return {
    // Prevent MIME type sniffing — forces the browser to honour Content-Type
    "X-Content-Type-Options": "nosniff",

    // Block the page from being framed — clickjacking defense
    "X-Frame-Options": "DENY",

    // Disable the legacy XSS filter (which could itself be exploited) and
    // instead block the page entirely if an XSS attempt is detected
    "X-XSS-Protection": "1; mode=block",

    // HSTS: tell browsers to only ever connect via HTTPS, for 2 years,
    // including all subdomains, and register in browser preload lists
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",

    // Referrer: only send the origin (not the full URL) to external sites
    "Referrer-Policy": "strict-origin-when-cross-origin",

    // Permissions: explicitly deny access to sensitive browser APIs
    // that your app doesn't need — camera, microphone, geolocation, etc.
    "Permissions-Policy": [
      "accelerometer=()",
      "camera=()",
      "geolocation=()",
      "gyroscope=()",
      "magnetometer=()",
      "microphone=()",
      "payment=()",
      "usb=()",
      "interest-cohort=()", // Opt out of FLoC
    ].join(", "),

    // Cross-Origin-Embedder-Policy: prevent loading cross-origin resources
    // that haven't explicitly granted permission — enables SharedArrayBuffer
    "Cross-Origin-Embedder-Policy": "require-corp",

    // Cross-Origin-Opener-Policy: isolate your browsing context from others
    // to prevent Spectre-style attacks via shared memory
    "Cross-Origin-Opener-Policy": "same-origin",

    // Cross-Origin-Resource-Policy: prevent other origins from loading your resources
    "Cross-Origin-Resource-Policy": "same-origin",

    // Content Security Policy
    "Content-Security-Policy": buildCSP(cspOptions),

    // Remove the server banner — never tell attackers what you're running
    "Server": "QuantumShield",

    // Remove Express's X-Powered-By equivalent
    "X-Powered-By": "",
  };
}

/**
 * Generate a cryptographically random nonce for use in CSP script-src
 * and style-src directives, allowing individual inline scripts/styles
 * without enabling 'unsafe-inline' globally.
 *
 * Usage: add nonce="${nonce}" to your <script> tags and
 * 'nonce-${nonce}' to your CSP header.
 */
export function generateNonce(): string {
  const { randomBytes } = require("crypto") as typeof import("crypto");
  return randomBytes(16).toString("base64");
}
