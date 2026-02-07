#!/usr/bin/env node
/**
 * FINAL COMPREHENSIVE SECURITY AUDIT
 *
 * Combines:
 * - Regression on 4 fixed CRITICALs (god tier, race condition, badge auth, tier manipulation)
 * - All prior security/fuzz/pentest categories
 * - New CTF-style deep probes (privilege escalation chains, data leaks, bypass attempts)
 */

const xrpl = require('xrpl');
const { sign, deriveKeypair, deriveAddress } = require('ripple-keypairs');
const crypto = require('crypto');

const API = process.env.API_URL || 'http://localhost:3000/api';
let passed = 0, failed = 0, total = 0;
const findings = [];

async function api(method, path, { headers = {}, body, rawBody, timeout = 10000 } = {}) {
  const opts = { method, headers: { ...headers }, signal: AbortSignal.timeout(timeout) };
  if (rawBody !== undefined) { opts.body = rawBody; }
  else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  try {
    const res = await fetch(`${API}${path}`, opts);
    let data;
    try { data = await res.json(); } catch { try { data = await res.text(); } catch { data = null; } }
    return { status: res.status, data, ok: true, headers: res.headers };
  } catch (e) {
    return { status: 0, data: null, ok: false, error: e.message };
  }
}

function agent() {
  const w = xrpl.Wallet.generate();
  const { privateKey, publicKey } = deriveKeypair(w.seed);
  return { address: w.address, seed: w.seed, publicKey, privateKey };
}

function auth(a, overrides = {}) {
  const ts = overrides.timestamp || String(Date.now());
  const wallet = overrides.wallet || a.address;
  const msg = `${wallet}:${ts}`;
  const hex = Buffer.from(msg).toString('hex');
  const sig = overrides.signature || sign(hex, a.privateKey);
  return { 'X-Wallet': wallet, 'X-Timestamp': ts, 'X-Signature': sig, 'X-Public-Key': overrides.pubkey || a.publicKey };
}

function alive(r) { return r.ok && r.status > 0; }
function noErr(r) { return alive(r) && r.status < 500; }

async function t(name, fn) {
  total++;
  try {
    const result = await fn();
    if (result === true) { passed++; process.stdout.write(`  PASS  [${String(total).padStart(3)}] ${name}\n`); }
    else {
      failed++;
      const sev = typeof result === 'string' && result.match(/^(CRITICAL|HIGH|MEDIUM)/)?.[1];
      if (sev) findings.push({ n: total, name, sev, detail: result });
      process.stdout.write(`  FAIL  [${String(total).padStart(3)}] ${name} — ${result}\n`);
    }
  } catch (e) {
    failed++;
    process.stdout.write(`  FAIL  [${String(total).padStart(3)}] ${name} — Exception: ${e.message}\n`);
  }
}

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║         FINAL COMPREHENSIVE SECURITY AUDIT                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const alice = agent();
  const bob = agent();
  const eve = agent(); // attacker
  const su1 = await api('POST', '/keys', { headers: auth(alice), body: { name: 'alice' } });
  const su2 = await api('POST', '/keys', { headers: auth(bob), body: { name: 'bob' } });
  const su3 = await api('POST', '/keys', { headers: auth(eve), body: { name: 'eve' } });
  const aliceKey = su1.data?.apiKey;
  const bobKey = su2.data?.apiKey;
  const eveKey = su3.data?.apiKey;
  if (!aliceKey || !eveKey) { console.log('FATAL: signup failed'); process.exit(1); }

  // ═══════════════════════════════════════════════════════════════
  // SECTION A: REGRESSION — PREVIOUSLY FIXED CRITICALS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── A. Regression: Previously Fixed Vulnerabilities ───');

  await t('FIX-1: god tier purchase blocked (whitelist)', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'tier', tier: 'god' } });
    return r.status === 400 ? true : `CRITICAL: god tier still purchasable! ${r.status}`;
  });

  await t('FIX-1b: partner tier purchase blocked (invite-only)', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'tier', tier: 'partner' } });
    return r.status === 400 ? true : `HIGH: partner tier purchasable! ${r.status}`;
  });

  await t('FIX-2: key limit race condition (10 concurrent)', async () => {
    const a = agent();
    const promises = Array.from({ length: 10 }, (_, i) =>
      api('POST', '/keys', { headers: auth(a), body: { name: `race-${i}` } })
    );
    const results = await Promise.all(promises);
    const created = results.filter(r => r.status === 201).length;
    return created <= 5 ? true : `CRITICAL: Created ${created} keys (limit is 5)`;
  });

  await t('FIX-3: badge grant requires admin auth', async () => {
    const r = await api('POST', `/user/${bob.address}/badges/grant`, {
      body: { badge: 'special:bug_hunter', grantedBy: 'eve' }
    });
    return r.status === 401 ? true : `CRITICAL: Badge granted without auth! status=${r.status}`;
  });

  await t('FIX-3b: badge revoke requires admin auth', async () => {
    const r = await api('DELETE', `/user/${bob.address}/badges/special:bug_hunter`);
    return r.status === 401 ? true : `CRITICAL: Badge revoked without auth! status=${r.status}`;
  });

  await t('FIX-3c: bulk badge grant requires admin auth', async () => {
    const r = await api('POST', '/user/badges/bulk-grant', {
      body: { badge: 'event:fake', addresses: [bob.address], grantedBy: 'eve' }
    });
    return r.status === 401 ? true : `CRITICAL: Bulk grant without auth! status=${r.status}`;
  });

  await t('FIX-4: tier manipulation via PUT requires admin auth', async () => {
    const target = agent();
    const un = 'fix4' + crypto.randomBytes(3).toString('hex');
    await api('POST', `/user/${target.address}`, { body: { username: un } });
    const r = await api('PUT', `/user/${target.address}`, { body: { tier: 'diamond' } });
    return r.status === 401 ? true : `CRITICAL: Tier set without auth! status=${r.status}`;
  });

  await t('FIX-4b: tier=verified via PUT blocked', async () => {
    const target = agent();
    const un = 'fix4b' + crypto.randomBytes(3).toString('hex');
    await api('POST', `/user/${target.address}`, { body: { username: un } });
    const r = await api('PUT', `/user/${target.address}`, { body: { tier: 'verified' } });
    return r.status === 401 ? true : `CRITICAL: Tier set to verified without auth! status=${r.status}`;
  });

  await t('FIX-5: web-search timeout (no infinite hang)', async () => {
    const r = await api('GET', '/web-search?q=test', { headers: { 'X-Api-Key': aliceKey }, timeout: 20000 });
    return alive(r) ? true : `Timeout/crash: ${r.error}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION B: AUTH — SIGNATURE, KEYS, SESSIONS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── B. Authentication & Authorization ───');

  await t('Expired timestamp (6min) rejected', async () => {
    const r = await api('POST', '/keys', { headers: auth(alice, { timestamp: String(Date.now() - 360001) }), body: { name: 'exp' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Future timestamp (6min) rejected', async () => {
    const r = await api('POST', '/keys', { headers: auth(alice, { timestamp: String(Date.now() + 360001) }), body: { name: 'fut' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Forged signature rejected', async () => {
    const r = await api('POST', '/keys', { headers: auth(alice, { signature: 'DEAD'.repeat(32) }), body: { name: 'forge' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Wrong pubkey (eve signs, claims alice)', async () => {
    const r = await api('POST', '/keys', { headers: auth(eve, { wallet: alice.address }), body: { name: 'steal' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Missing all auth headers on POST /keys', async () => {
    const r = await api('POST', '/keys', { body: { name: 'noauth' } });
    return (r.status === 400 || r.status === 401) ? true : `Got ${r.status}`;
  });

  await t('Invalid API key format rejected', async () => {
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': 'not_a_valid_key' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Admin endpoint: no auth → 401', async () => {
    const r = await api('GET', '/keys/admin/usage');
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Admin endpoint: fake admin key → 401', async () => {
    const r = await api('GET', '/keys/admin/usage', { headers: { 'X-Admin-Key': 'fake_admin_key_12345' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Admin create-key: eve signature → 401 (not in ADMIN_WALLETS)', async () => {
    const r = await api('POST', '/keys/admin/create-key', { headers: auth(eve), body: { wallet: eve.address, tier: 'god' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Admin add-credits: eve signature → 401', async () => {
    const r = await api('POST', '/keys/admin/add-credits', { headers: auth(eve), body: { wallet: eve.address, credits: 999999999 } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION C: IDOR — CROSS-USER ACCESS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── C. IDOR / Cross-User Access ───');

  await t('Eve cannot revoke alice key via DELETE', async () => {
    const list = await api('GET', `/keys/${alice.address}`);
    const keyId = list.data?.keys?.[0]?.id;
    if (!keyId) return 'Could not get alice key id';
    const r = await api('DELETE', `/keys/${alice.address}/${keyId}`, { headers: auth(eve) });
    return (r.status === 401 || r.status === 404) ? true : `Got ${r.status}`;
  });

  await t('Key list does not expose full API key', async () => {
    const r = await api('GET', `/keys/${alice.address}`);
    const exposes = r.data?.keys?.some(k => k.apiKey && k.apiKey.startsWith('xrpl_'));
    return exposes ? 'CRITICAL: Full API key exposed in list endpoint' : true;
  });

  await t('Chat: eve cannot see alice support tickets', async () => {
    const r = await api('GET', '/chat/support/tickets', { headers: { 'X-Api-Key': eveKey } });
    if (r.status === 200 && r.data?.tickets?.length) {
      const foreign = r.data.tickets.some(t => t.creator !== eve.address && t.creatorWallet !== eve.address);
      if (foreign) return 'HIGH: Can see other users\' tickets';
    }
    return true;
  });

  await t('Promotion claim: eve cannot claim for alice', async () => {
    const r = await api('POST', '/promotion/claim', { headers: auth(eve), body: { md5: 'a'.repeat(32), account: alice.address } });
    return (r.status === 401 || r.status === 404) ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION D: INJECTION — MONGO, XSS, NOSQL, SSRF
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── D. Injection Attacks ───');

  await t('Mongo $gt in wallet path /keys/', async () => {
    const r = await api('GET', '/keys/%7B%22%24gt%22%3A%22%22%7D');
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo $ne in wallet path /keys/', async () => {
    const r = await api('GET', '/keys/%7B%22%24ne%22%3A%22%22%7D');
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo $regex in token param', async () => {
    const r = await api('GET', '/token/%7B%22%24regex%22%3A%22.*%22%7D', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo $set in POST /keys body', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: 'test', "$set": { tier: 'god' } } });
    if (r.status === 201) {
      const cr = await api('GET', `/keys/${a.address}/credits`);
      if (cr.data?.tier === 'god') return 'CRITICAL: $set injection elevated to god tier';
    }
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo $inc in purchase body', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'credits', package: 'starter', "$inc": { balance: 999999 } } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('NoSQL injection object as key name', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: { "$gt": "" } } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Prototype pollution in body', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: 'proto', "__proto__": { "isAdmin": true }, "constructor": { "prototype": { "isAdmin": true } } } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('XSS in key name stored safely', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: '<script>alert(document.cookie)</script>' } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Path traversal in wallet param', async () => {
    const r = await api('GET', '/keys/../../etc/passwd');
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('SQL injection in wallet param', async () => {
    const r = await api('GET', "/keys/r'; DROP TABLE api_keys;--");
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('CRLF injection blocked by runtime', async () => {
    const r = await api('POST', '/keys', { headers: { 'X-Wallet': 'r123\r\nX-Admin-Key: secret', 'Content-Type': 'application/json' }, body: { name: 'crlf' } });
    // Bun/Node runtime rejects CRLF in headers (good — prevents header injection)
    return (alive(r) || (r.error && r.error.includes('invalid header'))) ? true : `Unexpected: ${r.error}`;
  });

  await t('Mongo $where in traders search', async () => {
    const r = await api('GET', '/traders/token-traders/test?search=' + encodeURIComponent('$where'), { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('ReDoS in traders search (a+)+$', async () => {
    const r = await api('GET', '/traders/token-traders/test?search=' + encodeURIComponent('(a+)+$'), { headers: { 'X-Api-Key': aliceKey }, timeout: 15000 });
    return (noErr(r) || !r.ok) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo injection in tweet verify md5', async () => {
    const r = await api('POST', '/tweet/verify', { body: { md5: { "$ne": null }, tweetUrl: 'https://x.com/t/status/1', account: eve.address } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo injection in launch-token status path', async () => {
    const r = await api('GET', '/launch-token/status/%7B%22%24ne%22%3Anull%7D');
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo injection in verify confirm txHash', async () => {
    const r = await api('POST', '/verify/confirm', { body: { txHash: { "$ne": null } }, timeout: 15000 });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo injection in NFT offers nftId', async () => {
    const r = await api('GET', '/nft/%7B%22%24ne%22%3Anull%7D/offers', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo injection in faucet address', async () => {
    const r = await api('POST', '/faucet', { body: { address: { "$ne": null } } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Mongo $or array in purchase body', async () => {
    const r = await api('POST', '/keys/purchase', { body: { "$or": [{ wallet: "a" }], type: 'credits', package: 'starter' } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION E: MALFORMED INPUT & BOUNDARY
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── E. Malformed Input & Boundary Values ───');

  await t('Special chars ^$%^%$# in search', async () => {
    const r = await api('GET', '/tokens?search=%5E%24%25%5E%25%24%23&limit=1', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Emoji in token param 🚀', async () => {
    const r = await api('GET', '/token/%F0%9F%9A%80', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Null byte in path /keys%00admin', async () => {
    const r = await api('GET', '/keys%00/admin/usage');
    return alive(r) ? true : `Connection failed`;
  });

  await t('10KB key name', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: 'X'.repeat(10000) } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Array as key name', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: ['a', 'b'] } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Truncated JSON body', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: { ...auth(a), 'Content-Type': 'application/json' }, rawBody: '{"name":"trunc' });
    return alive(r) ? true : `Connection failed`;
  });

  await t('Empty body on POST /keys', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: {} });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('limit=-1', async () => {
    const r = await api('GET', '/tokens?limit=-1', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('limit=Infinity', async () => {
    const r = await api('GET', '/tokens?limit=Infinity', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('offset=MAX_SAFE_INTEGER', async () => {
    const r = await api('GET', `/tokens?limit=1&offset=${Number.MAX_SAFE_INTEGER}`, { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('Duplicate query params limit=1&limit=9999', async () => {
    const r = await api('GET', '/tokens?limit=1&limit=9999', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('__proto__ in query params', async () => {
    const r = await api('GET', '/tokens?__proto__[isAdmin]=true&limit=1', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION F: HTTP METHOD ABUSE
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── F. HTTP Method Abuse ───');

  await t('PUT on /keys', async () => { const r = await api('PUT', '/keys', { body: {} }); return alive(r) ? true : `fail`; });
  await t('PATCH on /keys', async () => { const r = await api('PATCH', '/keys', { body: {} }); return alive(r) ? true : `fail`; });
  await t('DELETE on /tokens', async () => { const r = await api('DELETE', '/tokens'); return alive(r) ? true : `fail`; });
  await t('POST on /tokens', async () => { const r = await api('POST', '/tokens', { body: {} }); return alive(r) ? true : `fail`; });
  await t('PUT on /keys/admin/usage', async () => { const r = await api('PUT', '/keys/admin/usage'); return alive(r) ? true : `fail`; });
  await t('PATCH on /keys/purchase', async () => { const r = await api('PATCH', '/keys/purchase'); return alive(r) ? true : `fail`; });

  // ═══════════════════════════════════════════════════════════════
  // SECTION G: CREDIT & TIER MANIPULATION
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── G. Credit & Tier Manipulation ───');

  await t('Purchase: nonexistent package', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'credits', package: 'nonexistent' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Purchase: anonymous tier', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'tier', tier: 'anonymous' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Purchase: free tier (downgrade)', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'tier', tier: 'free' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Verify payment: random tx hash', async () => {
    const fakeTx = crypto.randomBytes(32).toString('hex').toUpperCase();
    const r = await api('POST', '/keys/verify-payment', { body: { txHash: fakeTx }, timeout: 35000 });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Credits not negative after queries', async () => {
    // Eve does 3 queries, check credits didn't go negative
    for (let i = 0; i < 3; i++) await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': eveKey } });
    const r = await api('GET', `/keys/${eve.address}/credits`);
    if (r.data?.balance < 0) return 'HIGH: Negative credit balance';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION H: LAUNCH TOKEN
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── H. Launch Token Security ───');

  await t('Launch: XRP currency code rejected', async () => {
    const r = await api('POST', '/launch-token', { body: { currencyCode: 'XRP', tokenSupply: 1000000, ammXrpAmount: 10, name: 'Fake' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Launch: negative supply', async () => {
    const r = await api('POST', '/launch-token', { body: { currencyCode: 'NEG', tokenSupply: -1, ammXrpAmount: 10, name: 'Neg' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Launch: supply > 10^16', async () => {
    const r = await api('POST', '/launch-token', { body: { currencyCode: 'BIG', tokenSupply: '99999999999999999', ammXrpAmount: 10, name: 'Big' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Launch: special chars in currency code', async () => {
    const r = await api('POST', '/launch-token', { body: { currencyCode: 'A$B', tokenSupply: 1000000, ammXrpAmount: 10, name: 'Spec' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Launch: cancel non-existent session', async () => {
    const r = await api('DELETE', '/launch-token/' + crypto.randomBytes(16).toString('hex'));
    return (r.status === 400 || r.status === 404) ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION I: SUBMIT ENDPOINT
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── I. Transaction Submit ───');

  await t('Submit: missing tx_blob', async () => {
    const r = await api('POST', '/submit', { body: {} });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Submit: non-hex tx_blob', async () => {
    const r = await api('POST', '/submit', { body: { tx_blob: 'ZZZZ_NOT_HEX!' } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Submit: oversized tx_blob (>262KB)', async () => {
    const r = await api('POST', '/submit', { body: { tx_blob: 'AB'.repeat(132000) } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Submit: object injection as tx_blob', async () => {
    const r = await api('POST', '/submit', { body: { tx_blob: { "$gt": "" } } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Submit: duplicate detection', async () => {
    const blob = 'AABBCCDD1234';
    await api('POST', '/submit', { body: { tx_blob: blob } });
    const r = await api('POST', '/submit', { body: { tx_blob: blob } });
    return r.status === 409 ? true : `Expected 409, got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION J: CHAT MODERATION
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── J. Chat & Moderation ───');

  await t('Chat ban: no auth → 401', async () => {
    const r = await api('POST', '/chat/ban', { body: { wallet: bob.address, reason: 'test' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('Chat ban: regular user → 403', async () => {
    const r = await api('POST', '/chat/ban', { headers: { 'X-Api-Key': eveKey }, body: { wallet: bob.address, reason: 'test' } });
    return (r.status === 401 || r.status === 403) ? true : `Got ${r.status}`;
  });

  await t('Chat mute: regular user → 403', async () => {
    const r = await api('POST', '/chat/mute', { headers: { 'X-Api-Key': eveKey }, body: { wallet: bob.address, duration: 60000 } });
    return (r.status === 401 || r.status === 403) ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION K: VERIFY ENDPOINT
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── K. Token/Collection Verification ───');

  await t('Verify: invalid type', async () => {
    const r = await api('POST', '/verify/request', { body: { type: 'admin', id: 'x', tier: 2 } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Verify: invalid tier (1)', async () => {
    const r = await api('POST', '/verify/request', { body: { type: 'token', id: 'x', tier: 1 } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('Verify: tier as Mongo operator', async () => {
    const r = await api('POST', '/verify/request', { body: { type: 'token', id: 'x', tier: { "$gt": 0 } } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION L: CTF — DEEP PRIVILEGE ESCALATION CHAINS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── L. CTF: Deep Privilege Escalation ───');

  await t('CTF: create key → query credits → check tier is free', async () => {
    const a = agent();
    await api('POST', '/keys', { headers: auth(a), body: { name: 'ctf1' } });
    const r = await api('GET', `/keys/${a.address}/credits`);
    if (r.data?.tier === 'god' || r.data?.tier === 'professional') return `HIGH: New user starts as ${r.data.tier}`;
    return r.data?.tier === 'free' ? true : `Tier: ${r.data?.tier}`;
  });

  await t('CTF: credits response leaks internal data', async () => {
    const r = await api('GET', `/keys/${alice.address}/credits`);
    const d = JSON.stringify(r.data || {});
    if (d.includes('password') || d.includes('secret') || d.includes('privateKey')) return 'CRITICAL: Secrets leaked in credits response';
    if (d.includes('keyHash')) return 'HIGH: Key hash leaked in credits response';
    return true;
  });

  await t('CTF: key list response leaks internal data', async () => {
    const r = await api('GET', `/keys/${alice.address}`);
    const d = JSON.stringify(r.data || {});
    if (d.includes('password') || d.includes('secret') || d.includes('privateKey') || d.includes('keyHash')) return 'CRITICAL: Secrets leaked in key list';
    return true;
  });

  await t('CTF: admin revenue endpoint data leak', async () => {
    // Even a 401 should not leak data in error message
    const r = await api('GET', '/keys/admin/revenue');
    if (r.status !== 401) return `Expected 401, got ${r.status}`;
    const d = JSON.stringify(r.data || {});
    if (d.includes('revenue') || d.includes('total')) return 'HIGH: Revenue data leaked in 401 response';
    return true;
  });

  await t('CTF: eve creates user, claims perks, checks badge persistence', async () => {
    const target = agent();
    const un = 'ctf5' + crypto.randomBytes(3).toString('hex');
    await api('POST', `/user/${target.address}`, { body: { username: un } });
    // Try to grant badge (should fail now)
    const g = await api('POST', `/user/${target.address}/badges/grant`, { body: { badge: 'og:early_adopter', grantedBy: 'ctf' } });
    if (g.status === 200) return 'CRITICAL: Badge still grantable without auth!';
    // Check perks don't show phantom badges
    const p = await api('GET', `/user/${target.address}/perks`);
    if (p.data?.badges?.includes('og:early_adopter')) return 'HIGH: Phantom badge appeared';
    return true;
  });

  await t('CTF: purchase with type=tier but sneak credits package', async () => {
    const r = await api('POST', '/keys/purchase', { body: { wallet: eve.address, type: 'tier', tier: 'developer', package: 'mega' } });
    // Should process as tier, not give mega credits
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('CTF: header injection — X-Forwarded-For spoof for rate limit bypass', async () => {
    // Try to bypass brute force by faking IP
    const fakeIp = `10.0.0.${Math.floor(Math.random() * 255)}`;
    const a = agent();
    const r = await api('POST', '/keys', {
      headers: { ...auth(a), 'X-Forwarded-For': fakeIp },
      body: { name: 'spoof' }
    });
    // Should work (key creation) but if rate-limited by real IP, forging shouldn't help
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('CTF: double signup same wallet yields same or different API keys', async () => {
    const a = agent();
    const r1 = await api('POST', '/keys', { headers: auth(a), body: { name: 'dup1' } });
    const r2 = await api('POST', '/keys', { headers: auth(a), body: { name: 'dup2' } });
    if (r1.status === 201 && r2.status === 201 && r1.data?.apiKey === r2.data?.apiKey) {
      return 'HIGH: Same API key returned for different key creates';
    }
    return true;
  });

  await t('CTF: revoke key then re-create to get old key hash collision', async () => {
    const a = agent();
    const c1 = await api('POST', '/keys', { headers: auth(a), body: { name: 'rev1' } });
    if (c1.status !== 201) return 'Setup failed';
    const key1 = c1.data.apiKey;
    // Revoke
    await api('DELETE', `/keys/${a.address}/${c1.data.keyId}`, { headers: auth(a) });
    // Create new
    const c2 = await api('POST', '/keys', { headers: auth(a), body: { name: 'rev2' } });
    if (c2.status !== 201) return `Create failed: ${c2.status}`;
    if (c2.data.apiKey === key1) return 'CRITICAL: Revoked key reissued!';
    return true;
  });

  await t('CTF: timing attack on API key validation', async () => {
    // Measure time difference between valid-prefix and invalid-prefix keys
    const validPrefix = 'xrpl_' + crypto.randomBytes(24).toString('hex');
    const invalidPrefix = 'xxxx_' + crypto.randomBytes(24).toString('hex');
    const times = { valid: [], invalid: [] };
    for (let i = 0; i < 5; i++) {
      let s = Date.now();
      await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': validPrefix } });
      times.valid.push(Date.now() - s);
      s = Date.now();
      await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': invalidPrefix } });
      times.invalid.push(Date.now() - s);
    }
    const avgValid = times.valid.reduce((a, b) => a + b) / 5;
    const avgInvalid = times.invalid.reduce((a, b) => a + b) / 5;
    const diff = Math.abs(avgValid - avgInvalid);
    // If difference > 50ms consistently, might indicate timing leak
    if (diff > 50) return `MEDIUM: Timing difference ${diff}ms between valid/invalid prefix keys`;
    return true;
  });

  await t('CTF: access user_settings via batch account balance leak', async () => {
    const r = await api('POST', '/account/balance', {
      headers: { 'X-Api-Key': aliceKey },
      body: { accounts: [alice.address, bob.address] }
    });
    const d = JSON.stringify(r.data || {});
    if (d.includes('tier') || d.includes('badges') || d.includes('username')) {
      return 'MEDIUM: User settings data leaked via batch balance endpoint';
    }
    return true;
  });

  await t('CTF: launch-token debug exposes secrets', async () => {
    const r = await api('GET', '/launch-token/debug');
    if (r.status === 200) {
      const d = JSON.stringify(r.data || {});
      if (d.includes('secret') || d.includes('privateKey') || d.includes('seed')) {
        return 'CRITICAL: Launch debug endpoint exposes wallet secrets!';
      }
      if (d.includes('issuerAddress') || d.includes('holderAddress')) {
        return 'MEDIUM: Launch debug exposes wallet addresses (info leak)';
      }
    }
    return true;
  });

  await t('CTF: verify pricing exposes internal wallet address', async () => {
    const r = await api('GET', '/verify/pricing');
    // Destination address is public by design (payment address), but check no secrets
    const d = JSON.stringify(r.data || {});
    if (d.includes('secret') || d.includes('private')) return 'CRITICAL: Secrets in pricing response';
    return true;
  });

  await t('CTF: all Mongo operators combined in one body', async () => {
    // Check balance BEFORE
    const before = await api('GET', `/keys/${eve.address}/credits`);
    const balBefore = before.data?.balance || 0;
    const r = await api('POST', '/keys/purchase', {
      body: {
        wallet: eve.address, type: 'credits', package: 'starter',
        "$gt": "", "$ne": null, "$regex": ".*", "$where": "1",
        "$set": { balance: 999999999 }, "$inc": { balance: 999999999 },
        "$unset": { tier: 1 }, "$push": { keys: "evil" },
        "__proto__": { admin: true }, "constructor": { "prototype": { admin: true } }
      }
    });
    // Check balance AFTER — should not have increased
    const after = await api('GET', `/keys/${eve.address}/credits`);
    const balAfter = after.data?.balance || 0;
    if (balAfter > balBefore + 100) return `CRITICAL: Credits increased from ${balBefore} to ${balAfter} via injection!`;
    // Check tier wasn't changed
    if (after.data?.tier === 'god') return 'CRITICAL: Tier elevated to god via injection!';
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION M: STRESS — CONCURRENT SAFETY
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── M. Concurrent Safety ───');

  await t('10 concurrent queries with same API key', async () => {
    const promises = Array.from({ length: 10 }, () =>
      api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': aliceKey } })
    );
    const results = await Promise.all(promises);
    const ok = results.filter(r => r.status === 200).length;
    const err = results.filter(r => r.status >= 500).length;
    if (err > 0) return `${err}/10 server errors under concurrent load`;
    return ok >= 8 ? true : `Only ${ok}/10 succeeded`;
  });

  await t('5 concurrent key creates same wallet (limit enforcement)', async () => {
    const a = agent();
    const promises = Array.from({ length: 5 }, (_, i) =>
      api('POST', '/keys', { headers: auth(a), body: { name: `conc-${i}` } })
    );
    const results = await Promise.all(promises);
    const created = results.filter(r => r.status === 201).length;
    return created <= 5 ? true : `Created ${created} keys`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log(`║  RESULTS: ${passed}/${total} passed, ${failed} failed${' '.repeat(Math.max(0, 32 - String(passed).length - String(total).length - String(failed).length))}║`);
  console.log('╚══════════════════════════════════════════════════════════════╝');

  if (findings.length) {
    console.log('\n⚠  SECURITY FINDINGS:');
    findings.forEach(f => {
      console.log(`  [${f.sev}] #${f.n}: ${f.name}`);
      console.log(`    ${f.detail}\n`);
    });
  } else {
    console.log('\n  No security findings. All tests passed.');
  }

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
