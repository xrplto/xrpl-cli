export interface Keypair {
  address: string;
  publicKey: string;
  seed: string;
}

export interface EncryptionEnvelope {
  v: 1;
  iv: string;
  tag: string;
  data: string;
}

export interface AuthHeaders {
  'X-Wallet': string;
  'X-Timestamp': string;
  'X-Signature': string;
  'X-Public-Key': string;
}

export interface SignResult {
  signature: string;
  publicKey: string;
  address: string;
}

export interface Config {
  baseUrl: string;
  apiKey: string | null;
  wallet: string | null;
  format: string;
}

export type ConfigKey = keyof Config;

export interface RawApiResponse<T = unknown> {
  status: number;
  data: T;
  headers: Headers;
}

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  fields?: string;
  authHeaders?: AuthHeaders;
  rawResponse?: boolean;
  authenticated?: boolean;
}

export interface ErrorPayload {
  error: string;
  details?: string | Record<string, unknown>;
}

// ─── URL validation ──────────────────────────────────────────
// Shared between config set-url and api.ts request-time checks

const PRIVATE_IP_RANGES = [
  /^127\./,              // loopback
  /^10\./,               // RFC 1918
  /^172\.(1[6-9]|2\d|3[01])\./,  // RFC 1918
  /^192\.168\./,         // RFC 1918
  /^169\.254\./,         // link-local
  /^0\./,                // current network
  /^100\.(6[4-9]|[7-9]\d|1[0-2]\d|127)\./,  // CGNAT
];

/** Resolve a URL hostname to its canonical IPv4 string (handles hex, octal, decimal IPs) */
function resolveHostnameIP(hostname: string): string | null {
  // Node's URL parser normalizes some IP forms but not all.
  // Try to create a URL and check what the browser/Node parser resolves to.
  try {
    const u = new URL(`http://${hostname}/`);
    return u.hostname;
  } catch {
    return null;
  }
}

export function isPrivateOrBlockedHost(hostname: string): boolean {
  const resolved = resolveHostnameIP(hostname) ?? hostname;
  // Block cloud metadata endpoints (all known forms)
  const blockedHosts = ['169.254.169.254', 'metadata.google.internal', 'instance-data', '100.100.100.200'];
  if (blockedHosts.includes(resolved) || blockedHosts.includes(hostname)) return true;
  // Check resolved IP against private ranges
  for (const range of PRIVATE_IP_RANGES) {
    if (range.test(resolved)) return true;
  }
  // Block IPv6 loopback and IPv6-mapped IPv4 private addresses
  if (resolved === '::1' || resolved === '[::1]') return true;
  const v4Mapped = resolved.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (v4Mapped) {
    for (const range of PRIVATE_IP_RANGES) {
      if (range.test(v4Mapped[1])) return true;
    }
  }
  return false;
}

export function validateBaseUrl(url: string): { error: string } | { parsed: URL } {
  let parsed: URL;
  try { parsed = new URL(url); } catch { return { error: 'Invalid URL format' }; }

  // Protocol allowlist: only http and https
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return { error: `Protocol ${parsed.protocol} not allowed. Use https: (or http: for localhost).` };
  }

  // Block embedded credentials
  if (parsed.username || parsed.password) {
    return { error: 'URLs with embedded credentials are not allowed.' };
  }

  // For HTTP, only allow literal "localhost" or "127.0.0.1" in the original URL.
  // Node's URL parser normalizes hex/octal IPs (0x7f000001, 0177.0.0.1) to 127.0.0.1,
  // so we must check the raw input to prevent SSRF bypass via IP encoding tricks.
  const hostFromInput = (() => {
    try {
      // Extract host portion from original URL string (between :// and next / or :)
      const afterProto = url.replace(/^https?:\/\//, '');
      return afterProto.split(/[/:?#]/)[0].toLowerCase();
    } catch { return ''; }
  })();
  const isLocalhost = hostFromInput === 'localhost' || hostFromInput === '127.0.0.1';
  if (parsed.protocol === 'http:' && !isLocalhost) {
    return { error: 'Only HTTPS URLs are allowed (except localhost for development).' };
  }

  // Block private/metadata IPs (catches all forms via Node's hostname resolution)
  if (!isLocalhost && isPrivateOrBlockedHost(parsed.hostname)) {
    return { error: 'Blocked: private or reserved IP address.' };
  }

  return { parsed };
}
