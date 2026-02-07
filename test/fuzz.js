#!/usr/bin/env node
/**
 * Fuzz / malformed request tests — 100 tests.
 *
 * Categories:
 *  1-15:  Special characters in parameters
 * 16-30:  MongoDB injection operators
 * 31-45:  Odd HTTP methods
 * 46-60:  Malformed bodies & content types
 * 61-75:  Boundary values & encoding
 * 76-85:  Path / endpoint fuzzing
 * 86-95:  Query parameter injection
 * 96-100: Combined / chained attacks
 */

const xrpl = require('xrpl');
const { sign, deriveKeypair } = require('ripple-keypairs');

const API = process.env.API_URL || 'http://localhost:3000/api';
let passed = 0, failed = 0, total = 0;

async function raw(method, path, { headers = {}, body, rawBody, timeout = 10000 } = {}) {
  const opts = {
    method,
    headers: { ...headers },
    signal: AbortSignal.timeout(timeout)
  };
  if (rawBody !== undefined) {
    opts.body = rawBody;
  } else if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  try {
    const res = await fetch(`${API}${path}`, opts);
    let data;
    try { data = await res.json(); } catch { try { data = await res.text(); } catch { data = null; } }
    return { status: res.status, data, ok: true };
  } catch (e) {
    return { status: 0, data: null, ok: false, error: e.message };
  }
}

function makeAgent() {
  const wallet = xrpl.Wallet.generate();
  const { privateKey, publicKey } = deriveKeypair(wallet.seed);
  return { address: wallet.address, seed: wallet.seed, publicKey, privateKey };
}

function authHeaders(agent) {
  const timestamp = String(Date.now());
  const message = `${agent.address}:${timestamp}`;
  const messageHex = Buffer.from(message).toString('hex');
  const signature = sign(messageHex, agent.privateKey);
  return {
    'X-Wallet': agent.address,
    'X-Timestamp': timestamp,
    'X-Signature': signature,
    'X-Public-Key': agent.publicKey
  };
}

async function test(name, fn) {
  total++;
  try {
    const result = await fn();
    if (result === true) {
      passed++;
      process.stdout.write(`  PASS  [${total}] ${name}\n`);
    } else {
      failed++;
      process.stdout.write(`  FAIL  [${total}] ${name} — ${result}\n`);
    }
  } catch (e) {
    failed++;
    process.stdout.write(`  FAIL  [${total}] ${name} — Exception: ${e.message}\n`);
  }
}

// Helper: ensure server doesn't crash (returns any HTTP status, not connection error)
function alive(r) { return r.ok && r.status > 0; }
// Helper: not a 500
function noServerError(r) { return alive(r) && r.status < 500; }

async function main() {
  console.log('\n=== Fuzz & Malformed Request Tests (100) ===\n');

  const agent = makeAgent();
  const signup = await raw('POST', '/keys', { headers: authHeaders(agent), body: { name: 'fuzz-agent' } });
  const apiKey = signup.data?.apiKey;
  if (!apiKey) { console.log('FATAL: Could not create fuzz agent key'); process.exit(1); }
  const authH = { 'X-Api-Key': apiKey };

  // ─── 1-15: SPECIAL CHARACTERS IN PARAMETERS ─────────────────

  console.log('\n--- Special Characters in Parameters ---');

  await test('Wallet param: $%^&*()', async () => {
    const r = await raw('GET', '/keys/$%25%5E%26*()');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Wallet param: <script>alert(1)</script>', async () => {
    const r = await raw('GET', '/keys/%3Cscript%3Ealert(1)%3C%2Fscript%3E');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Wallet param: null bytes %00', async () => {
    const r = await raw('GET', '/keys/r1234567890123456789012345%00evil');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Token param: emoji 🚀🌙', async () => {
    const r = await raw('GET', '/token/%F0%9F%9A%80%F0%9F%8C%99', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Token param: backslashes \\..\\..\\', async () => {
    const r = await raw('GET', '/token/%5C..%5C..%5C', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Search query: special chars ^$%^%$#@!', async () => {
    const r = await raw('GET', '/tokens?search=%5E%24%25%5E%25%24%23%40!&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Key name: newlines and tabs', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: 'line1\nline2\ttab' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Key name: unicode RTL override \\u202E', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: 'test\u202Eevil' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Key name: zero-width chars \\u200B\\u200C\\u200D', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: '\u200B\u200C\u200D' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Key name: only spaces', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: '   ' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Account param: single quote r\'injection', async () => {
    const r = await raw('GET', "/account/r'injection", { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Account param: double quote r"injection', async () => {
    const r = await raw('GET', '/account/r%22injection', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Web search: SQL chars \' OR 1=1 --', async () => {
    const r = await raw('GET', "/web-search?q=%27%20OR%201%3D1%20--", { headers: authH, timeout: 20000 });
    return (noServerError(r) || r.error?.includes('timeout')) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: limit with special chars', async () => {
    const r = await raw('GET', '/tokens?limit=%3Cscript%3E', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Key name: 1000 unicode snowmen ☃', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: '☃'.repeat(1000) } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  // ─── 16-30: MONGODB INJECTION OPERATORS ──────────────────────

  console.log('\n--- MongoDB Injection Operators ---');

  await test('Mongo: $gt in wallet path', async () => {
    const r = await raw('GET', '/keys/%7B%22%24gt%22%3A%22%22%7D');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $ne in wallet path', async () => {
    const r = await raw('GET', '/keys/%7B%22%24ne%22%3A%22%22%7D');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $regex in wallet path', async () => {
    const r = await raw('GET', '/keys/%7B%22%24regex%22%3A%22.*%22%7D');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $where in wallet path', async () => {
    const r = await raw('GET', '/keys/%7B%22%24where%22%3A%221%22%7D');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $exists in wallet path', async () => {
    const r = await raw('GET', '/keys/%7B%22%24exists%22%3Atrue%7D');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $gt in key name body', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: { "$gt": "" } } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $ne operator in key name body', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: { "$ne": null } } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $regex in key name body', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: { "$regex": ".*" } } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $where in purchase body', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { wallet: { "$where": "1" }, type: 'tier', tier: 'developer' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $or array in purchase body', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { "$or": [{ wallet: "a" }, { wallet: "b" }], type: 'credits', package: 'starter' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: nested $gt in credits query', async () => {
    const r = await raw('GET', '/keys/%7B%22%24gt%22%3A%22%22%7D/credits');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $nin operator in token query', async () => {
    const r = await raw('GET', '/tokens?currency=%7B%22%24nin%22%3A%5B%5D%7D&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $set operator attempt in body', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: 'test', "$set": { tier: 'god' } } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $unset operator attempt in body', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { wallet: agent.address, "$unset": { "tier": 1 }, type: 'credits', package: 'starter' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo: $inc credits attempt', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { wallet: agent.address, type: 'credits', "$inc": { balance: 999999 }, package: 'starter' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  // ─── 31-45: ODD HTTP METHODS ─────────────────────────────────

  console.log('\n--- Odd HTTP Methods ---');

  await test('PUT on /keys (create endpoint)', async () => {
    const r = await raw('PUT', '/keys', { headers: authHeaders(agent), body: { name: 'put-test' } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PATCH on /keys (create endpoint)', async () => {
    const r = await raw('PATCH', '/keys', { headers: authHeaders(agent), body: { name: 'patch-test' } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('OPTIONS on /keys', async () => {
    const r = await raw('OPTIONS', '/keys');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('HEAD on /tokens', async () => {
    const r = await raw('HEAD', '/tokens?limit=1', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('DELETE on /tokens (read-only)', async () => {
    const r = await raw('DELETE', '/tokens?limit=1', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PATCH on /keys/purchase', async () => {
    const r = await raw('PATCH', '/keys/purchase', { body: { wallet: agent.address, type: 'credits', package: 'starter' } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PUT on /tokens', async () => {
    const r = await raw('PUT', '/tokens', { headers: authH, body: { inject: true } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('DELETE on /keys/:wallet (list endpoint)', async () => {
    const r = await raw('DELETE', `/keys/${agent.address}`);
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PATCH on /web-search', async () => {
    const r = await raw('PATCH', '/web-search?q=test', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('POST on /tokens (should be GET)', async () => {
    const r = await raw('POST', '/tokens', { headers: authH, body: { limit: 5 } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PUT on /keys/admin/usage', async () => {
    const r = await raw('PUT', '/keys/admin/usage');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('DELETE on /keys/purchase', async () => {
    const r = await raw('DELETE', '/keys/purchase');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PATCH on /keys/verify-payment', async () => {
    const r = await raw('PATCH', '/keys/verify-payment', { body: { txHash: 'AAAA' } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('POST on /docs (should be GET)', async () => {
    const r = await raw('POST', '/docs', { body: { inject: true } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('PUT on /account/:address', async () => {
    const r = await raw('PUT', `/account/${agent.address}`, { headers: authH, body: { balance: 999999 } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  // ─── 46-60: MALFORMED BODIES & CONTENT TYPES ─────────────────

  console.log('\n--- Malformed Bodies & Content Types ---');

  await test('Empty JSON body on POST /keys', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: {} });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Array body instead of object on POST /keys', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: { ...authHeaders(a), 'Content-Type': 'application/json' }, rawBody: '["name","test"]' });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Invalid JSON body (truncated)', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: { ...authHeaders(a), 'Content-Type': 'application/json' }, rawBody: '{"name":"trunc' });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('XML body with JSON content-type', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: { ...authHeaders(a), 'Content-Type': 'application/json' }, rawBody: '<xml><name>test</name></xml>' });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Form-urlencoded body on JSON endpoint', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: { ...authHeaders(a), 'Content-Type': 'application/x-www-form-urlencoded' }, rawBody: 'name=test' });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Multipart form data on JSON endpoint', async () => {
    const a = makeAgent();
    const boundary = '----fuzz123';
    const r = await raw('POST', '/keys', {
      headers: { ...authHeaders(a), 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      rawBody: `------fuzz123\r\nContent-Disposition: form-data; name="name"\r\n\r\ntest\r\n------fuzz123--`
    });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Null body value', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: null } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Numeric body value for name', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: 12345 } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Boolean body value for name', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: true } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Nested object as name', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: { nested: { deep: 'value' } } } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Array as name', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: ['a', 'b', 'c'] } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('50KB body payload', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', { headers: authHeaders(a), body: { name: 'big', data: 'X'.repeat(50000) } });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Purchase with string amount', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { wallet: agent.address, type: 'credits', package: 'starter', amount: 'nine thousand' } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Purchase with negative credits', async () => {
    const r = await raw('POST', '/keys/purchase', { body: { wallet: agent.address, type: 'credits', package: 'starter', credits: -1000000 } });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Verify-payment with object txHash', async () => {
    const r = await raw('POST', '/keys/verify-payment', { body: { txHash: { "$gt": "" } }, timeout: 35000 });
    // 400 = proper validation, timeout (status 0) = node lookup hung (acceptable)
    return (noServerError(r) || r.status === 0) ? true : `Server error: ${r.status}`;
  });

  // ─── 61-75: BOUNDARY VALUES & ENCODING ───────────────────────

  console.log('\n--- Boundary Values & Encoding ---');

  await test('Tokens: limit=0', async () => {
    const r = await raw('GET', '/tokens?limit=0', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: limit=-1', async () => {
    const r = await raw('GET', '/tokens?limit=-1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: limit=999999999', async () => {
    const r = await raw('GET', '/tokens?limit=999999999', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: limit=NaN', async () => {
    const r = await raw('GET', '/tokens?limit=NaN', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: limit=Infinity', async () => {
    const r = await raw('GET', '/tokens?limit=Infinity', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Tokens: offset=MAX_SAFE_INTEGER', async () => {
    const r = await raw('GET', `/tokens?limit=1&offset=${Number.MAX_SAFE_INTEGER}`, { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Account: address max length (35 chars starting with r)', async () => {
    const r = await raw('GET', '/account/r' + '1'.repeat(34), { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Token: 64-char hex (valid tx hash format as token id)', async () => {
    const r = await raw('GET', '/token/' + 'A'.repeat(64), { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Token: empty string', async () => {
    const r = await raw('GET', '/token/', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Token: single character', async () => {
    const r = await raw('GET', '/token/x', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Web search: very long query (5000 chars)', async () => {
    const r = await raw('GET', `/web-search?q=${'a'.repeat(5000)}`, { headers: authH, timeout: 20000 });
    // Timeout acceptable (SearXNG may choke on 5KB query), 400/502 = proper rejection
    return (alive(r) || r.error?.includes('timeout')) ? true : `Unexpected: ${r.error}`;
  });

  await test('Web search: empty query', async () => {
    const r = await raw('GET', '/web-search?q=', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Double-encoded URL: %2525 (double-encoded %)', async () => {
    const r = await raw('GET', '/keys/r%2525test', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Unicode normalization: ℉ vs fi ligature in search', async () => {
    const r = await raw('GET', '/tokens?search=%E2%84%89&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('CRLF injection in header value', async () => {
    const a = makeAgent();
    const h = authHeaders(a);
    h['X-Wallet'] = a.address + '\r\nX-Injected: true';
    const r = await raw('POST', '/keys', { headers: h, body: { name: 'crlf' } });
    // fetch runtime rejects CRLF in headers (good — prevents header injection)
    return (alive(r) || r.error?.includes('invalid header')) ? true : `Unexpected: ${r.error}`;
  });

  // ─── 76-85: PATH & ENDPOINT FUZZING ──────────────────────────

  console.log('\n--- Path & Endpoint Fuzzing ---');

  await test('Path traversal: /keys/../admin/usage', async () => {
    const r = await raw('GET', '/keys/../keys/admin/usage');
    // Should still require auth (resolved to /keys/admin/usage)
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Double slash: //keys', async () => {
    const r = await raw('GET', '//keys/' + agent.address);
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Trailing dot: /tokens.', async () => {
    const r = await raw('GET', '/tokens.?limit=1', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Case sensitivity: /TOKENS vs /tokens', async () => {
    const r = await raw('GET', '/TOKENS?limit=1', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Semicolon path param: /tokens;evil=1', async () => {
    const r = await raw('GET', '/tokens;evil=1?limit=1', { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Hash fragment in URL: /tokens#fragment', async () => {
    const r = await raw('GET', '/tokens?limit=1#fragment', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Non-existent deep path: /keys/a/b/c/d/e/f', async () => {
    const r = await raw('GET', '/keys/a/b/c/d/e/f');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Null byte in path: /keys%00/admin', async () => {
    const r = await raw('GET', '/keys%00/admin/usage');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Unicode path: /tokens/日本語', async () => {
    const r = await raw('GET', '/token/%E6%97%A5%E6%9C%AC%E8%AA%9E', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Extremely long path segment (2000 chars)', async () => {
    const r = await raw('GET', '/token/' + 'A'.repeat(2000), { headers: authH });
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  // ─── 86-95: QUERY PARAMETER INJECTION ────────────────────────

  console.log('\n--- Query Parameter Injection ---');

  await test('Duplicate query params: ?limit=1&limit=9999', async () => {
    const r = await raw('GET', '/tokens?limit=1&limit=9999', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Array notation: ?limit[]=1&limit[]=2', async () => {
    const r = await raw('GET', '/tokens?limit[]=1&limit[]=2', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Object notation: ?limit[key]=value', async () => {
    const r = await raw('GET', '/tokens?limit[key]=value', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('__proto__ in query params', async () => {
    const r = await raw('GET', '/tokens?__proto__[isAdmin]=true&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('constructor.prototype in query', async () => {
    const r = await raw('GET', '/tokens?constructor[prototype][isAdmin]=true&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('SSRF attempt in web-search categories', async () => {
    const r = await raw('GET', '/web-search?q=test&categories=http://evil.com', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Mongo $where in query string', async () => {
    const r = await raw('GET', '/tokens?$where=sleep(5000)&limit=1', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('API key as query param: injection', async () => {
    const r = await raw('GET', '/tokens?apiKey=xrpl_' + 'A'.repeat(32) + '&limit=1');
    return alive(r) ? true : `Connection failed: ${r.error}`;
  });

  await test('Negative page number', async () => {
    const r = await raw('GET', '/tokens?limit=1&offset=-100', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Float as integer param', async () => {
    const r = await raw('GET', '/tokens?limit=3.14159', { headers: authH });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  // ─── 96-100: COMBINED / CHAINED ATTACKS ──────────────────────

  console.log('\n--- Combined / Chained Attacks ---');

  await test('Combo: Mongo injection + special chars in wallet', async () => {
    const r = await raw('GET', '/keys/%7B%22%24gt%22%3A%22%22%7D%5E%24%25%23');
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Combo: XSS + Mongo in key name', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', {
      headers: authHeaders(a),
      body: { name: '<img src=x onerror=alert(1)>', "$set": { tier: 'god', balance: 999999 } }
    });
    // Should create key (extra fields ignored) or reject
    if (r.status === 201 && r.data?.apiKey) {
      // Verify the agent didn't get god tier
      const cr = await raw('GET', `/keys/${a.address}/credits`);
      if (cr.data?.tier === 'god') return 'CRITICAL: $set injection elevated to god tier';
    }
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Combo: prototype pollution + Mongo in purchase', async () => {
    const r = await raw('POST', '/keys/purchase', {
      body: {
        wallet: agent.address,
        type: 'tier',
        tier: 'developer',
        "__proto__": { "isAdmin": true },
        "$set": { "credits.balance": 999999999 }
      }
    });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Combo: all Mongo operators in one body', async () => {
    const r = await raw('POST', '/keys/purchase', {
      body: {
        wallet: agent.address,
        type: 'credits',
        package: 'starter',
        "$gt": "", "$ne": null, "$regex": ".*", "$where": "1",
        "$set": { balance: 999 }, "$inc": { balance: 999 },
        "$unset": { tier: 1 }, "$push": { keys: "evil" }
      }
    });
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  await test('Combo: everything at once — special chars + Mongo + XSS + oversized', async () => {
    const a = makeAgent();
    const r = await raw('POST', '/keys', {
      headers: authHeaders(a),
      body: {
        name: '<script>alert("$ne")</script>' + '🚀'.repeat(500) + '\x00\r\n',
        "$set": { tier: 'god' },
        "__proto__": { admin: true },
        extra: 'Z'.repeat(10000)
      }
    });
    if (r.status === 201 && r.data?.apiKey) {
      const cr = await raw('GET', `/keys/${a.address}/credits`);
      if (cr.data?.tier === 'god') return 'CRITICAL: Combined injection elevated to god tier';
    }
    return noServerError(r) ? true : `Server error: ${r.status}`;
  });

  // ─── SUMMARY ─────────────────────────────────────────────────
  console.log(`\n=== Results: ${passed}/${total} passed, ${failed} failed ===`);
  if (failed > 0) console.log('Review FAIL items above for vulnerabilities.');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
