const config = require('./config');
const output = require('./output');

async function request(method, path, { query, body, fields, authHeaders, rawResponse } = {}) {
  const cfg = config.load();
  const base = cfg.baseUrl.replace(/\/$/, '');
  const url = new URL(`${base}${path}`);

  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== null && v !== '') url.searchParams.set(k, v);
    }
  }
  if (fields) url.searchParams.set('fields', fields);

  const headers = { 'User-Agent': 'xrpl-cli/1.0.0', 'Accept': 'application/json' };
  if (cfg.apiKey) headers['X-Api-Key'] = cfg.apiKey;
  if (authHeaders) Object.assign(headers, authHeaders);

  const opts = { method, headers };
  if (body && method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }

  let res;
  try {
    opts.signal = AbortSignal.timeout(30000);
    res = await fetch(url.toString(), opts);
  } catch (err) {
    if (err.name === 'TimeoutError') output.error('Request timed out (30s)', 40);
    output.error(`Network error: ${err.message}`, 40);
  }

  let data;
  try {
    data = await res.json();
  } catch {
    output.error(`Invalid response from API (${res.status})`, 40);
  }

  if (rawResponse) return { status: res.status, data, headers: res.headers };

  if (!res.ok) {
    const msg = data?.error || data?.message || `HTTP ${res.status}`;
    if (res.status === 401) output.error(msg, 10, 'Run: xrpl signup  OR  xrpl config set-key <key>');
    if (res.status === 402) output.error(msg, 30, data);
    if (res.status === 404) output.error(msg, 20);
    if (res.status === 429) output.error(msg, 31, data);
    output.error(msg, 40, data);
  }

  // Attach rate limit headers if present
  const credits = res.headers.get('x-credits-remaining');
  if (credits && output.isJson()) {
    data._credits_remaining = parseInt(credits);
  }

  return data;
}

async function get(path, opts) { return request('GET', path, opts); }
async function post(path, opts) { return request('POST', path, opts); }
async function del(path, opts) { return request('DELETE', path, opts); }

module.exports = { get, post, del };
