import dns from 'dns';
import * as config from './config';
import * as output from './output';
import type { AuthHeaders, RawApiResponse, RequestOptions } from './types';
import { validateBaseUrl, isPrivateOrBlockedHost } from './types';

// Endpoints that don't need an API key
const PUBLIC_PATHS = new Set([
  '/health', '/docs', '/tokens', '/search',
  '/keys/tiers', '/keys/packages', '/keys/costs',
  '/web-search'
]);

function isPublicPath(urlPath: string): boolean {
  for (const p of PUBLIC_PATHS) {
    if (urlPath === p || urlPath.startsWith(p + '/') || urlPath.startsWith(p + '?')) return true;
  }
  return false;
}

export async function request<T = unknown>(method: string, urlPath: string, opts: RequestOptions & { rawResponse: true }): Promise<RawApiResponse<T>>;
export async function request<T = unknown>(method: string, urlPath: string, opts?: RequestOptions): Promise<T>;
export async function request<T = unknown>(method: string, urlPath: string, opts: RequestOptions = {}): Promise<T | RawApiResponse<T>> {
  const { query, body, fields, authHeaders, rawResponse, authenticated } = opts;
  const cfg = config.load();
  const base = cfg.baseUrl.replace(/\/$/, '');

  // Validate URL at request time (protocol, private IPs, credentials)
  const urlCheck = validateBaseUrl(base);
  if ('error' in urlCheck) {
    output.error(`Refusing connection: ${urlCheck.error}`, 40);
  }

  const url = new URL(`${base}${urlPath}`);

  // DNS resolution check — prevent DNS rebinding SSRF
  const hostname = url.hostname;
  if (hostname !== 'localhost' && hostname !== '127.0.0.1' && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    try {
      const resolved = await new Promise<string[]>((resolve, reject) => {
        dns.resolve4(hostname, (err, addrs) => err ? reject(err) : resolve(addrs));
      });
      for (const ip of resolved) {
        if (isPrivateOrBlockedHost(ip)) {
          output.error(`Refusing connection: ${hostname} resolves to private IP ${ip}`, 40);
        }
      }
    } catch {}
  }

  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, String(v));
    }
  }
  if (fields) url.searchParams.set('fields', fields);

  const headers: Record<string, string> = { 'User-Agent': 'xrpl-cli/1.0.0', 'Accept': 'application/json' };

  // Only send API key when needed (authenticated !== false and not a public path)
  const needsAuth = authenticated !== false && !isPublicPath(urlPath);
  if (needsAuth && cfg.apiKey) headers['X-Api-Key'] = cfg.apiKey;
  if (authHeaders) {
    headers['X-Wallet'] = authHeaders['X-Wallet'];
    headers['X-Timestamp'] = authHeaders['X-Timestamp'];
    headers['X-Signature'] = authHeaders['X-Signature'];
    headers['X-Public-Key'] = authHeaders['X-Public-Key'];
  }

  const fetchOpts: RequestInit = { method, headers };
  if (body && method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    fetchOpts.body = JSON.stringify(body);
  }

  let res: Response;
  try {
    fetchOpts.signal = AbortSignal.timeout(30000);
    res = await fetch(url.toString(), fetchOpts);
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'TimeoutError') output.error('Request timed out (30s)', 40);
    // Sanitize network errors — don't leak internal details
    output.error('Network error: could not connect to API', 40);
  }

  let data: T;
  try {
    data = await res.json() as T;
  } catch {
    output.error(`Invalid response from API (HTTP ${res.status})`, 40);
  }

  if (rawResponse) return { status: res.status, data, headers: res.headers };

  if (!res.ok) {
    const msg = (data as Record<string, string>)?.error || (data as Record<string, string>)?.message || `HTTP ${res.status}`;
    if (res.status === 401) output.error(msg, 10, 'Run: xrpl signup  OR  xrpl config set-key <key>');
    if (res.status === 402) output.error(msg, 30, data as unknown as Record<string, unknown>);
    if (res.status === 404) output.error(msg, 20);
    if (res.status === 429) output.error(msg, 31, data as unknown as Record<string, unknown>);
    output.error(msg, 40);
  }

  // Attach rate limit headers if present
  const credits = res.headers.get('x-credits-remaining');
  if (credits && output.isJson() && typeof data === 'object' && data !== null) {
    const parsed = parseInt(credits, 10);
    if (!isNaN(parsed)) {
      (data as Record<string, unknown>)._credits_remaining = parsed;
    }
  }

  return data;
}

export async function get<T = unknown>(urlPath: string, opts: RequestOptions & { rawResponse: true }): Promise<RawApiResponse<T>>;
export async function get<T = unknown>(urlPath: string, opts?: RequestOptions): Promise<T>;
export async function get<T = unknown>(urlPath: string, opts: RequestOptions = {}): Promise<T | RawApiResponse<T>> {
  return request('GET', urlPath, opts as RequestOptions & { rawResponse: true });
}

export async function post<T = unknown>(urlPath: string, opts: RequestOptions = {}): Promise<T> {
  return request<T>('POST', urlPath, opts);
}

export async function del<T = unknown>(urlPath: string, opts: RequestOptions = {}): Promise<T> {
  return request<T>('DELETE', urlPath, opts);
}
