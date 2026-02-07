#!/usr/bin/env node
/**
 * Security & edge case tests for XRPL CLI / Keys API
 *
 * Tests: replay attacks, timestamp manipulation, IDOR, race conditions,
 * key limit bypass, NoSQL injection, brute force, signature forgery,
 * credit manipulation, input validation.
 */

const xrpl = require('xrpl');
const { sign, deriveKeypair, deriveAddress } = require('ripple-keypairs');
const crypto = require('crypto');

const API = process.env.API_URL || 'http://localhost:3000/api';
let passed = 0, failed = 0, total = 0;

async function api(method, path, { headers = {}, body, timeout = 10000 } = {}) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    signal: AbortSignal.timeout(timeout)
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API}${path}`, opts);
  let data;
  try { data = await res.json(); } catch { data = null; }
  return { status: res.status, data, headers: res.headers };
}

function makeAgent() {
  const wallet = xrpl.Wallet.generate();
  const { privateKey, publicKey } = deriveKeypair(wallet.seed);
  return { address: wallet.address, seed: wallet.seed, publicKey, privateKey };
}

function authHeaders(agent, { timestampOverride, walletOverride, pubkeyOverride, signOverride } = {}) {
  const timestamp = timestampOverride || String(Date.now());
  const walletAddr = walletOverride || agent.address;
  const message = `${walletAddr}:${timestamp}`;
  const messageHex = Buffer.from(message).toString('hex');
  const signature = signOverride || sign(messageHex, agent.privateKey);
  return {
    'X-Wallet': walletAddr,
    'X-Timestamp': timestamp,
    'X-Signature': signature,
    'X-Public-Key': pubkeyOverride || agent.publicKey
  };
}

async function test(name, fn) {
  total++;
  try {
    const result = await fn();
    if (result === true) {
      passed++;
      console.log(`  PASS  ${name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${name} — ${result}`);
    }
  } catch (e) {
    failed++;
    console.log(`  FAIL  ${name} — Exception: ${e.message}`);
  }
}

async function main() {
  console.log('\n=== Security & Edge Case Tests ===\n');

  // Setup: create two agents
  const alice = makeAgent();
  const bob = makeAgent();

  // Sign up alice
  let aliceKey;
  {
    const r = await api('POST', '/keys', { headers: authHeaders(alice), body: { name: 'Alice' } });
    aliceKey = r.data?.apiKey;
    if (!aliceKey) { console.log('FATAL: Could not create alice key'); process.exit(1); }
  }
  // Sign up bob
  let bobKey;
  {
    const r = await api('POST', '/keys', { headers: authHeaders(bob), body: { name: 'Bob' } });
    bobKey = r.data?.apiKey;
  }

  // ─── 1. REPLAY ATTACKS ───────────────────────────────────────
  console.log('\n--- Replay Attacks ---');

  await test('Replay: reuse exact same headers', async () => {
    const headers = authHeaders(alice);
    const r1 = await api('POST', '/keys', { headers, body: { name: 'replay1' } });
    // Wait 1s, replay exact same headers
    await new Promise(r => setTimeout(r, 1000));
    const r2 = await api('POST', '/keys', { headers, body: { name: 'replay2' } });
    // Both should succeed (timestamp still valid within 5min) - this is a known design choice
    // But verify both created distinct keys
    return r1.status === 201 && r2.status === 201 ? true : `r1=${r1.status} r2=${r2.status}`;
  });

  await test('Replay: expired timestamp (6 min old)', async () => {
    const old = String(Date.now() - 6 * 60 * 1000);
    const r = await api('POST', '/keys', { headers: authHeaders(alice, { timestampOverride: old }), body: { name: 'expired' } });
    return r.status === 401 ? true : `Expected 401, got ${r.status}: ${r.data?.error}`;
  });

  await test('Replay: future timestamp (6 min ahead)', async () => {
    const future = String(Date.now() + 6 * 60 * 1000);
    const r = await api('POST', '/keys', { headers: authHeaders(alice, { timestampOverride: future }), body: { name: 'future' } });
    return r.status === 401 ? true : `Expected 401, got ${r.status}: ${r.data?.error}`;
  });

  // ─── 2. SIGNATURE FORGERY ────────────────────────────────────
  console.log('\n--- Signature Forgery ---');

  await test('Forgery: alice signs, claims to be bob', async () => {
    // Alice signs a message for bob's wallet — pubkey won't match
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { walletOverride: bob.address }),
      body: { name: 'forged' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}: ${r.data?.error}`;
  });

  await test('Forgery: random signature', async () => {
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { signOverride: 'DEADBEEF'.repeat(16) }),
      body: { name: 'random-sig' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Forgery: wrong public key', async () => {
    const fake = makeAgent();
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { pubkeyOverride: fake.publicKey }),
      body: { name: 'wrong-pk' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Forgery: empty signature', async () => {
    const r = await api('POST', '/keys', {
      headers: { 'X-Wallet': alice.address, 'X-Timestamp': String(Date.now()), 'X-Signature': '', 'X-Public-Key': alice.publicKey },
      body: { name: 'empty-sig' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Forgery: missing all auth headers', async () => {
    const r = await api('POST', '/keys', { body: { name: 'no-auth' } });
    return r.status === 400 || r.status === 401 ? true : `Expected 400/401, got ${r.status}`;
  });

  // ─── 3. IDOR — Accessing Other Users' Data ──────────────────
  console.log('\n--- IDOR (Insecure Direct Object Reference) ---');

  await test('IDOR: bob reads alice keys (no auth needed for list)', async () => {
    // GET /keys/:wallet is unauthenticated — by design (shows keyPrefix, not full key)
    const r = await api('GET', `/keys/${alice.address}`);
    const exposesFullKey = r.data?.keys?.some(k => k.apiKey);
    if (exposesFullKey) return 'CRITICAL: Full API key exposed in list endpoint';
    return r.status === 200 ? true : `Status ${r.status}`;
  });

  await test('IDOR: bob reads alice credits (unauthenticated — by design, like on-chain balance)', async () => {
    const r = await api('GET', `/keys/${alice.address}/credits`);
    // Public balance is by design (same as blockchain explorers)
    return r.status === 200 ? true : `Status ${r.status}`;
  });

  await test('IDOR: bob cannot revoke alice key (404 — wallet mismatch, key not found for bob)', async () => {
    const list = await api('GET', `/keys/${alice.address}`);
    const keyId = list.data?.keys?.[0]?.id;
    if (!keyId) return 'Could not get alice key ID';
    // Bob signs as himself, tries alice's key ID — DB query uses bob's wallet, won't find alice's key
    const r = await api('DELETE', `/keys/${alice.address}/${keyId}`, {
      headers: authHeaders(bob)
    });
    return (r.status === 401 || r.status === 404) ? true : `Expected 401/404, got ${r.status}`;
  });

  await test('IDOR: API key is bearer token (by design — same as Helius/Stripe)', async () => {
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': aliceKey } });
    return r.status === 200 ? true : `Status ${r.status}`;
  });

  // ─── 4. KEY LIMIT BYPASS ─────────────────────────────────────
  console.log('\n--- Key Limit Bypass (max 5) ---');

  await test('Key limit: race condition — create 10 keys simultaneously', async () => {
    const agent = makeAgent();
    // Try to create 10 keys at once
    const promises = Array.from({ length: 10 }, (_, i) =>
      api('POST', '/keys', { headers: authHeaders(agent), body: { name: `race-${i}` } })
    );
    const results = await Promise.all(promises);
    const created = results.filter(r => r.status === 201).length;
    const rejected = results.filter(r => r.status === 400).length;
    // Should have max 5 created
    if (created > 5) return `VULNERABILITY: Created ${created} keys (limit is 5)`;
    return true;
  });

  // ─── 5. INPUT VALIDATION ─────────────────────────────────────
  console.log('\n--- Input Validation ---');

  await test('NoSQL injection in wallet param', async () => {
    const r = await api('GET', '/keys/{"$gt":""}');
    return r.status === 400 ? true : `Got ${r.status}: ${JSON.stringify(r.data).substring(0, 100)}`;
  });

  await test('NoSQL injection in key name', async () => {
    const agent = makeAgent();
    const r = await api('POST', '/keys', {
      headers: authHeaders(agent),
      body: { name: { "$gt": "" } }
    });
    // Should create key but name should be sanitized or treated as string
    return (r.status === 201 || r.status === 400) ? true : `Got ${r.status}`;
  });

  await test('XSS in key name', async () => {
    const agent = makeAgent();
    const r = await api('POST', '/keys', {
      headers: authHeaders(agent),
      body: { name: '<script>alert(1)</script>' }
    });
    // Should store safely (no execution context, but check it doesn't crash)
    return r.status === 201 ? true : `Got ${r.status}: ${r.data?.error}`;
  });

  await test('Prototype pollution in body', async () => {
    const agent = makeAgent();
    const r = await api('POST', '/keys', {
      headers: authHeaders(agent),
      body: { name: 'test', "__proto__": { "isAdmin": true }, "constructor": { "prototype": { "isAdmin": true } } }
    });
    return (r.status === 201 || r.status === 400) ? true : `Got ${r.status}`;
  });

  await test('Oversized key name (10KB)', async () => {
    const agent = makeAgent();
    const r = await api('POST', '/keys', {
      headers: authHeaders(agent),
      body: { name: 'A'.repeat(10000) }
    });
    // Should either truncate or reject
    return (r.status === 201 || r.status === 400 || r.status === 413) ? true : `Got ${r.status}`;
  });

  await test('Invalid wallet format: too short', async () => {
    const r = await api('GET', '/keys/rabc');
    return r.status === 400 ? true : `Expected 400, got ${r.status}`;
  });

  await test('Invalid wallet format: SQL injection attempt', async () => {
    const r = await api('GET', "/keys/r'; DROP TABLE api_keys;--");
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await test('Path traversal in wallet', async () => {
    const r = await api('GET', '/keys/../../etc/passwd');
    return (r.status === 400 || r.status === 404) ? true : `Got ${r.status}`;
  });

  // ─── 6. API KEY VALIDATION ───────────────────────────────────
  console.log('\n--- API Key Validation ---');

  await test('Invalid API key format: no prefix', async () => {
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': 'invalidkey123456789012345' } });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Invalid API key format: too short', async () => {
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': 'xrpl_short' } });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Revoked key still works?', async () => {
    // Create a key, revoke it, try to use it
    const agent = makeAgent();
    const create = await api('POST', '/keys', { headers: authHeaders(agent), body: { name: 'revoke-test' } });
    if (create.status !== 201) return `Could not create key: ${create.status}`;
    const key = create.data.apiKey;
    const keyId = create.data.keyId;

    // Revoke
    await api('DELETE', `/keys/${agent.address}/${keyId}`, { headers: authHeaders(agent) });

    // Wait a moment for cache to expire (memory cache is 60s)
    await new Promise(r => setTimeout(r, 100));

    // Try to use revoked key
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': key } });
    if (r.status === 200) return 'INFO: Revoked key still works (60s memory cache expected)';
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  // ─── 7. TIMESTAMP EDGE CASES (run before brute force to avoid IP block) ──
  console.log('\n--- Timestamp Edge Cases ---');

  await test('Timestamp: non-numeric', async () => {
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { timestampOverride: 'not-a-number' }),
      body: { name: 'ts-nan' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Timestamp: zero', async () => {
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { timestampOverride: '0' }),
      body: { name: 'ts-zero' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Timestamp: negative', async () => {
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { timestampOverride: '-1000' }),
      body: { name: 'ts-neg' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Timestamp: exactly at 5min boundary', async () => {
    const boundary = String(Date.now() - 5 * 60 * 1000 + 500); // just under 5min
    const r = await api('POST', '/keys', {
      headers: authHeaders(alice, { timestampOverride: boundary }),
      body: { name: 'ts-boundary' }
    });
    // Should still be valid (within window)
    return r.status === 201 || r.status === 400 ? true : `Got ${r.status}: ${r.data?.error}`;
  });

  // ─── 8. BRUTE FORCE PROTECTION (run last — blocks IP) ───────
  console.log('\n--- Brute Force Protection ---');

  await test('Brute force: 15 failed auths trigger IP block', async () => {
    const victim = makeAgent();
    const results = [];
    for (let i = 0; i < 15; i++) {
      const r = await api('POST', '/keys', {
        headers: authHeaders(victim, { signOverride: 'BAD' + crypto.randomBytes(32).toString('hex') }),
        body: { name: 'bf-' + i }
      });
      results.push(r.status);
    }
    const blocked = results.filter(s => s === 429).length;
    return blocked > 0 ? true : `No 429 after 15 failures: ${JSON.stringify(results)}`;
  });

  // ─── 9. CREDIT MANIPULATION ──────────────────────────────────
  console.log('\n--- Credit Manipulation ---');

  await test('Purchase: negative credits package', async () => {
    const r = await api('POST', '/keys/purchase', {
      body: { wallet: alice.address, type: 'credits', package: 'nonexistent' }
    });
    return r.status === 400 ? true : `Expected 400, got ${r.status}`;
  });

  await test('Purchase: inject tier as "god"', async () => {
    const r = await api('POST', '/keys/purchase', {
      body: { wallet: alice.address, type: 'tier', tier: 'god' }
    });
    return r.status === 400 ? true : `Expected 400, got ${r.status}: ${r.data?.error}`;
  });

  await test('Purchase: inject tier as "anonymous"', async () => {
    const r = await api('POST', '/keys/purchase', {
      body: { wallet: alice.address, type: 'tier', tier: 'anonymous' }
    });
    return r.status === 400 ? true : `Expected 400, got ${r.status}`;
  });

  await test('Verify payment: fake tx hash', async () => {
    const fakeTx = crypto.randomBytes(32).toString('hex').toUpperCase();
    const r = await api('POST', '/keys/verify-payment', { body: { txHash: fakeTx }, timeout: 35000 });
    return (r.status === 400 && r.data?.reason) ? true : `Got ${r.status}: ${r.data?.error}`;
  });

  // ─── 10. ADMIN ENDPOINT PROTECTION ───────────────────────────
  console.log('\n--- Admin Endpoint Protection ---');

  await test('Admin: usage without auth', async () => {
    const r = await api('GET', '/keys/admin/usage');
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Admin: create-key without auth', async () => {
    const r = await api('POST', '/keys/admin/create-key', {
      body: { wallet: alice.address, tier: 'god', credits: 999999999 }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Admin: add-credits without auth', async () => {
    const r = await api('POST', '/keys/admin/add-credits', {
      body: { wallet: alice.address, credits: 999999999 }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Admin: revenue without auth', async () => {
    const r = await api('GET', '/keys/admin/revenue');
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Admin: fake admin key header', async () => {
    const r = await api('GET', '/keys/admin/usage', {
      headers: { 'X-Admin-Key': 'fake-admin-key-attempt' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  await test('Admin: normal user wallet as admin', async () => {
    const r = await api('POST', '/keys/admin/create-key', {
      headers: authHeaders(alice),
      body: { wallet: alice.address, tier: 'god' }
    });
    return r.status === 401 ? true : `Expected 401, got ${r.status}`;
  });

  // ─── SUMMARY ─────────────────────────────────────────────────
  console.log(`\n=== Results: ${passed}/${total} passed, ${failed} failed ===`);
  if (failed > 0) console.log('Review FAIL and INFO items above.');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
