#!/usr/bin/env node
/**
 * FINAL PENTEST — Targets gaps not covered by existing test suites.
 *
 * Focus areas:
 *  1. Shell injection via curlPost/curlGet in verify.js, submit.js, tweet_verify.js
 *  2. txHash replay in verify/confirm
 *  3. Stripe webhook forgery in verify.js
 *  4. launch_token secret exposure
 *  5. admin.js sanitizeInput bypass
 *  6. faucet cooldown bypass (address variants)
 *  7. Promotion claim double-spend
 *  8. Chat session token replay
 *  9. Race conditions on verify/confirm
 * 10. Parameter pollution & type confusion across all endpoints
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
  console.log('║         FINAL PENTEST — DEEP VULNERABILITY PROBE           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  // Setup agents
  const alice = agent();
  const eve = agent();
  const su1 = await api('POST', '/keys', { headers: auth(alice), body: { name: 'alice-pt' } });
  const su2 = await api('POST', '/keys', { headers: auth(eve), body: { name: 'eve-pt' } });
  const aliceKey = su1.data?.apiKey;
  const eveKey = su2.data?.apiKey;
  if (!aliceKey || !eveKey) { console.log('FATAL: signup failed'); process.exit(1); }

  // ═══════════════════════════════════════════════════════════════
  // SECTION 1: SHELL INJECTION — verify.js curlPost
  // verify.js curlPost does NOT escape single quotes in JSON.stringify output.
  // If txHash contains a single quote, it breaks out of the shell string.
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 1. Shell Injection: verify.js curlPost ───');

  await t('SHELL-1: single quote in txHash (shell breakout)', async () => {
    // If shell injection works, server might crash or return unexpected result
    // Safe canary: use backtick subshell that just echoes, won't cause damage
    const payload = "test'$(echo INJECTED)'rest";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    // Should get 400 (tx not found), NOT 500 (shell error) or evidence of execution
    if (r.status >= 500) return 'CRITICAL: Shell injection in verify.js curlPost — server error on single-quote payload';
    if (r.data && typeof r.data === 'string' && r.data.includes('INJECTED')) return 'CRITICAL: Shell injection confirmed — command output in response';
    return true;
  });

  await t('SHELL-2: backtick command substitution in txHash', async () => {
    const payload = "test`echo PWNED`rest";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    if (r.status >= 500) return 'CRITICAL: Shell injection via backticks in verify.js curlPost';
    return true;
  });

  await t('SHELL-3: semicolon command chain in txHash', async () => {
    const payload = "AABB; echo INJECTED; echo CC";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    if (r.status >= 500) return 'CRITICAL: Shell injection via semicolon in verify.js curlPost';
    return true;
  });

  await t('SHELL-4: pipe in txHash', async () => {
    const payload = "AABB | echo PIPED";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    if (r.status >= 500) return 'CRITICAL: Shell injection via pipe in verify.js curlPost';
    return true;
  });

  await t('SHELL-5: newline injection in txHash', async () => {
    const payload = "AABB\necho NEWLINE";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    if (r.status >= 500) return 'HIGH: Newline injection in verify.js curlPost';
    return true;
  });

  await t('SHELL-6: double-dollar variable expansion in txHash', async () => {
    const payload = "AABB$$echo test";
    const r = await api('POST', '/verify/confirm', { body: { txHash: payload }, timeout: 15000 });
    if (r.status >= 500) return 'MEDIUM: Dollar expansion in verify.js curlPost';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 2: SHELL INJECTION — tweet_verify.js fetchOembed
  // Uses encodeURIComponent on tweetUrl before inserting into curl cmd.
  // encodeURIComponent converts ' to %27, so should be safe, but verify.
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 2. Shell Injection: tweet_verify.js fetchOembed ───');

  await t('SHELL-7: single quote in tweetUrl (after valid prefix)', async () => {
    // The URL validation regex: /^https?:\/\/(x\.com|twitter\.com)\/\w+\/status\/\d+/
    // No $ anchor — allows trailing chars. But encodeURIComponent should encode quotes.
    const payload = "https://x.com/test/status/123'$(echo INJECTED)";
    const r = await api('POST', '/tweet/verify', {
      body: { md5: 'a'.repeat(32), tweetUrl: payload, account: eve.address }
    });
    if (r.status >= 500) return 'CRITICAL: Shell injection in tweet_verify.js fetchOembed';
    return true;
  });

  await t('SHELL-8: backtick in tweetUrl', async () => {
    const payload = "https://x.com/test/status/123`echo PWNED`";
    const r = await api('POST', '/tweet/verify', {
      body: { md5: 'a'.repeat(32), tweetUrl: payload, account: eve.address }
    });
    if (r.status >= 500) return 'CRITICAL: Shell injection via backtick in tweet_verify.js';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 3: SHELL INJECTION — submit.js curlPost
  // submit.js DOES have single-quote escaping (.replace(/'/g, "'\\''"))
  // But verify the curlPost is only called with validated inputs.
  // The only user-controlled call is account_info with validated XRP address.
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 3. Shell Injection: submit.js curlPost ───');

  await t('SHELL-9: submit account/sequence with shell chars in address', async () => {
    // Address is validated by regex: /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/
    // This should reject any shell chars
    const r = await api('GET', "/submit/account/r'; echo INJECTED/sequence");
    if (r.status >= 500) return 'CRITICAL: Shell injection in submit.js via address path';
    return true;
  });

  await t('SHELL-10: submit simulate with shell chars in tx_json', async () => {
    const r = await api('POST', '/submit/simulate', {
      body: { tx_json: { Account: "r'$(whoami)", TransactionType: 'Payment' } },
      timeout: 15000
    });
    // Should use XRPL client (not curl) for simulate, so shell injection shouldn't apply
    if (r.status >= 500 && r.data?.error?.includes('INJECTED')) return 'CRITICAL: Shell injection in submit simulate';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 4: VERIFY — TXHASH REPLAY & PAYMENT MANIPULATION
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 4. Verify: txHash Replay & Payment Manipulation ───');

  await t('REPLAY-1: same txHash submitted twice to verify/confirm', async () => {
    const fakeTx = crypto.randomBytes(32).toString('hex').toUpperCase();
    const r1 = await api('POST', '/verify/confirm', { body: { txHash: fakeTx }, timeout: 15000 });
    const r2 = await api('POST', '/verify/confirm', { body: { txHash: fakeTx }, timeout: 15000 });
    // Both should fail (fake tx), but if one succeeded and the other didn't get blocked, that's a replay issue
    // Since we can't generate real txs, check that no 200 response occurs
    if (r1.status === 200 || r2.status === 200) return 'CRITICAL: verify/confirm accepted fake txHash!';
    return true;
  });

  await t('REPLAY-2: verify/confirm with object txHash (type confusion)', async () => {
    const r = await api('POST', '/verify/confirm', { body: { txHash: { "$ne": null } }, timeout: 15000 });
    if (r.status === 200) return 'CRITICAL: Mongo injection bypassed txHash validation';
    if (r.status >= 500) return 'HIGH: Server crash on object txHash in verify/confirm';
    return true;
  });

  await t('REPLAY-3: verify/confirm with array txHash', async () => {
    const r = await api('POST', '/verify/confirm', { body: { txHash: ['A', 'B'] }, timeout: 15000 });
    if (r.status >= 500) return 'HIGH: Server crash on array txHash';
    return true;
  });

  await t('REPLAY-4: verify request with tier as float (2.5)', async () => {
    const r = await api('POST', '/verify/request', { body: { type: 'token', id: 'a'.repeat(32), tier: 2.5 } });
    return r.status === 400 ? true : `Got ${r.status} — should reject non-integer tier`;
  });

  await t('REPLAY-5: verify request with tier as string "2"', async () => {
    const r = await api('POST', '/verify/request', { body: { type: 'token', id: 'a'.repeat(32), tier: '2' } });
    // String "2" might pass the !=[2,3,4].includes check since "2" !== 2
    return (r.status === 400 || r.status === 404) ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 5: STRIPE WEBHOOK FORGERY
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 5. Stripe Webhook Forgery ───');

  await t('STRIPE-1: forged webhook without signature', async () => {
    const r = await api('POST', '/verify/stripe/webhook', {
      body: {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_fake',
            metadata: { type: 'token', id: 'a'.repeat(32), tier: '2' },
            amount_total: 58900,
            currency: 'usd',
            payment_intent: 'pi_fake'
          }
        }
      }
    });
    // If Stripe is configured with webhook secret, should reject
    // If not configured, might accept — check if verification was applied
    if (r.status === 200) {
      // Check if the token got verified
      const check = await api('GET', '/verify/stripe/status/cs_fake');
      if (check.data?.status === 'completed') return 'CRITICAL: Stripe webhook forgery — verification applied without signature!';
    }
    return true;
  });

  await t('STRIPE-2: webhook with malicious metadata', async () => {
    const r = await api('POST', '/verify/stripe/webhook', {
      body: {
        type: 'checkout.session.completed',
        data: {
          object: {
            id: 'cs_evil',
            metadata: { type: 'token', id: { "$ne": null }, tier: '1' },
            amount_total: 100,
            currency: 'usd'
          }
        }
      }
    });
    // 503 = webhook secret not configured (our fix), 400 = invalid signature — both OK
    if (r.status === 503 || r.status === 400) return true;
    if (r.status >= 500) return 'HIGH: Server crash on injection in Stripe webhook metadata';
    // 200 would mean the forged event was processed
    if (r.status === 200) return 'CRITICAL: Forged webhook with injection metadata accepted';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 6: LAUNCH TOKEN SECRET EXPOSURE
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 6. Launch Token Secret Exposure ───');

  await t('SECRET-1: launch-token debug does not expose secrets', async () => {
    const r = await api('GET', '/launch-token/debug');
    if (r.status === 200 && r.data) {
      const d = JSON.stringify(r.data);
      if (d.includes('Secret') || d.includes('secret') || d.includes('seed') || d.includes('privateKey'))
        return 'CRITICAL: Launch debug endpoint exposes wallet secrets';
      if (d.includes('issuerSecret') || d.includes('holderSecret'))
        return 'CRITICAL: Launch debug leaks raw secret keys';
    }
    return true;
  });

  await t('SECRET-2: launch-token status does not expose secrets', async () => {
    // Create a launch, get session, check status response
    const r = await api('POST', '/launch-token', {
      body: { currencyCode: 'TEST', tokenSupply: 1000000, ammXrpAmount: 10, name: 'SecTest' }
    });
    if (r.status === 200 || r.status === 201) {
      const sid = r.data?.sessionId;
      if (sid) {
        const s = await api('GET', `/launch-token/status/${sid}`);
        const d = JSON.stringify(s.data || {});
        if (d.includes('secret') || d.includes('privateKey') || d.includes('seed'))
          return 'CRITICAL: Launch status leaks secret keys';
        // Cleanup
        await api('DELETE', `/launch-token/${sid}`);
      }
    }
    return true;
  });

  await t('SECRET-3: launch-token cancel response does not leak secrets', async () => {
    const r = await api('POST', '/launch-token', {
      body: { currencyCode: 'TSEC', tokenSupply: 500000, ammXrpAmount: 5, name: 'SecCancel' }
    });
    if (r.status === 200 || r.status === 201) {
      const sid = r.data?.sessionId;
      if (sid) {
        const c = await api('DELETE', `/launch-token/${sid}`);
        const d = JSON.stringify(c.data || {});
        // Cancel may expose issuer address for manual recovery, but never secrets
        if (d.includes('secret') || d.includes('privateKey') || d.includes('seed'))
          return 'CRITICAL: Launch cancel leaks secret keys in response';
      }
    }
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 7: ADMIN.JS SANITIZE BYPASS
  // sanitizeInput only strips $ — can we bypass with nested operators?
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 7. Admin sanitizeInput Bypass ───');

  await t('ADMIN-1: forged JWT with none algorithm', async () => {
    // Create a JWT with algorithm "none" (JWT bypass)
    const header = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url');
    const payload = Buffer.from('{"account":"admin","iat":' + Math.floor(Date.now()/1000) + '}').toString('base64url');
    const fakeJwt = `${header}.${payload}.`;
    const r = await api('POST', '/admin/update-token', {
      headers: { 'X-Access-Account': 'admin', 'X-Access-Token': fakeJwt },
      body: { data: JSON.stringify({ md5: 'a'.repeat(32), slug: 'test' }), account: 'admin' }
    });
    return r.status === 401 ? true : `Got ${r.status} — JWT "none" algorithm may have been accepted`;
  });

  await t('ADMIN-2: JWT with expired but valid-format token', async () => {
    const r = await api('POST', '/admin/update-token', {
      headers: { 'X-Access-Account': 'rXXXXXXXXX12345678901234', 'X-Access-Token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhY2NvdW50IjoiclhYWFhYWFhYWDEyMzQ1Njc4OTAxMjM0IiwiaWF0IjoxNzA0MDY3MjAwLCJleHAiOjE3MDQwNjcyMDB9.fake' },
      body: { data: JSON.stringify({ md5: 'a'.repeat(32), slug: 'test2' }), account: 'rXXXXXXXXX12345678901234' }
    });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('ADMIN-3: update-token with $set in data body (bypasses sanitize)', async () => {
    // sanitizeInput strips $ but only from md5/slug. The full data object is passed to updateOne
    const r = await api('POST', '/admin/update-token', {
      headers: { 'X-Access-Account': 'admin', 'X-Access-Token': 'fake' },
      body: { data: JSON.stringify({ md5: 'a'.repeat(32), slug: 'test3', "$set": { verified: 2 } }), account: 'admin' }
    });
    // Should be 401 (auth fails first), but if auth somehow passes...
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 8: FAUCET COOLDOWN BYPASS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 8. Faucet Cooldown & Abuse ───');

  await t('FAUCET-1: cooldown uses address (not IP) — different address bypasses', async () => {
    // This is by design but verify it's address-based not IP-based
    const a1 = agent();
    const a2 = agent();
    const r1 = await api('POST', '/faucet', { body: { destination: a1.address }, timeout: 30000 });
    const r2 = await api('POST', '/faucet', { body: { destination: a2.address }, timeout: 30000 });
    // Both should work (different addresses) or both fail (testnet issue)
    if (r1.status === 200 && r2.status === 429) return 'IP-based cooldown — cannot bypass';
    return true; // Either both work (address-based) or both fail (testnet down)
  });

  await t('FAUCET-2: object as destination (Mongo injection)', async () => {
    const r = await api('POST', '/faucet', { body: { destination: { "$gt": "" } } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('FAUCET-3: amount field ignored (fixed amount)', async () => {
    const a = agent();
    const r = await api('POST', '/faucet', { body: { destination: a.address, amount: 999999 }, timeout: 30000 });
    // Amount should be ignored (fixed at DEFAULT_AMOUNT)
    if (r.status === 200 && r.data?.amount > 200) return 'HIGH: Faucet sent more than max amount!';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 9: PROMOTION CLAIM DOUBLE-SPEND
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 9. Promotion Claim Double-Spend ───');

  await t('CLAIM-1: concurrent claims (race condition)', async () => {
    // Try to claim same reward 5x simultaneously
    const a = agent();
    const md5 = 'b'.repeat(32);
    const promises = Array.from({ length: 5 }, () =>
      api('POST', '/promotion/claim', {
        headers: auth(a),
        body: { md5, account: a.address }
      })
    );
    const results = await Promise.all(promises);
    const ok = results.filter(r => r.status === 200);
    if (ok.length > 1) return 'CRITICAL: Double-spend — multiple claims succeeded for same reward';
    return true;
  });

  await t('CLAIM-2: claim with negative amount in body (ignored)', async () => {
    const a = agent();
    const r = await api('POST', '/promotion/claim', {
      headers: auth(a),
      body: { md5: 'c'.repeat(32), account: a.address, amount: -1000000 }
    });
    // amount field should be ignored (read from DB)
    if (r.status >= 500) return 'HIGH: Server crash on negative amount in claim body';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 10: CHAT SESSION TOKEN ABUSE
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 10. Chat Session Token Abuse ───');

  await t('CHAT-1: session token without API key', async () => {
    const r = await api('GET', '/chat/session');
    return (r.status === 400 || r.status === 401 || r.status === 429) ? true : `Got ${r.status}`;
  });

  await t('CHAT-2: rapid session creation (rate limit)', async () => {
    const promises = Array.from({ length: 15 }, () =>
      api('GET', '/chat/session', { headers: { 'X-Api-Key': eveKey } })
    );
    const results = await Promise.all(promises);
    const limited = results.filter(r => r.status === 429);
    // Should hit rate limit after 10
    return limited.length > 0 ? true : `No rate limiting on session creation (all ${results.length} succeeded)`;
  });

  await t('CHAT-3: chat status does not leak user data', async () => {
    const r = await api('GET', '/chat/status');
    if (r.status === 200) {
      const d = JSON.stringify(r.data || {});
      if (d.includes('apiKey') || d.includes('privateKey') || d.includes('secret'))
        return 'HIGH: Chat status leaks sensitive user data';
      // Should only contain online count and unread
      const keys = Object.keys(r.data || {});
      const allowed = ['online', 'unread'];
      const extra = keys.filter(k => !allowed.includes(k));
      if (extra.length > 0) return `MEDIUM: Chat status exposes extra fields: ${extra.join(', ')}`;
    }
    return true;
  });

  await t('CHAT-4: messages endpoint does not require auth', async () => {
    const r = await api('GET', '/chat/messages?limit=5');
    // Public chat messages are likely public, but check for sensitive data
    if (r.status === 200 && r.data?.messages) {
      const d = JSON.stringify(r.data.messages);
      if (d.includes('apiKey') || d.includes('privateKey') || d.includes('ip'))
        return 'HIGH: Chat messages contain sensitive user data';
    }
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 11: PARAMETER TYPE CONFUSION
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 11. Parameter Type Confusion ───');

  await t('TYPE-1: boolean as API key', async () => {
    const r = await api('GET', '/tokens?limit=1', { headers: { 'X-Api-Key': 'true' } });
    return r.status === 401 ? true : `Got ${r.status}`;
  });

  await t('TYPE-2: number as wallet address for key list', async () => {
    const r = await api('GET', '/keys/12345');
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('TYPE-3: array in POST body where string expected', async () => {
    const r = await api('POST', '/verify/request', {
      body: { type: ['token', 'collection'], id: 'test', tier: 2 }
    });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('TYPE-4: null values in required fields', async () => {
    const r = await api('POST', '/verify/request', { body: { type: null, id: null, tier: null } });
    return r.status === 400 ? true : `Got ${r.status}`;
  });

  await t('TYPE-5: very long string (1MB) in key name', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: 'X'.repeat(1000000) } });
    // Should either reject or handle gracefully
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  await t('TYPE-6: unicode overlong encoding in md5', async () => {
    const r = await api('GET', '/token/%C0%AF%C0%AF%C0%AFetc/passwd', { headers: { 'X-Api-Key': aliceKey } });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 12: HEADER INJECTION & SMUGGLING
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 12. Header Injection & Smuggling ───');

  await t('HDR-1: oversized header value (64KB)', async () => {
    const r = await api('GET', '/tokens?limit=1', {
      headers: { 'X-Api-Key': aliceKey, 'X-Custom': 'A'.repeat(65536) }
    });
    return alive(r) ? true : `Connection failed`;
  });

  await t('HDR-2: duplicate Content-Type headers', async () => {
    const r = await api('POST', '/keys', {
      headers: { ...auth(alice), 'Content-Type': 'application/json', 'content-type': 'text/xml' },
      rawBody: JSON.stringify({ name: 'dup-ct' })
    });
    return alive(r) ? true : `Connection failed`;
  });

  await t('HDR-3: X-Forwarded-For with 100 IPs', async () => {
    const ips = Array.from({ length: 100 }, (_, i) => `10.0.${Math.floor(i/255)}.${i%255}`).join(', ');
    const r = await api('GET', '/tokens?limit=1', {
      headers: { 'X-Api-Key': aliceKey, 'X-Forwarded-For': ips }
    });
    return noErr(r) ? true : `Server error: ${r.status}`;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 13: CROSS-ENDPOINT ESCALATION CHAINS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 13. Cross-Endpoint Escalation Chains ───');

  await t('CHAIN-1: signup → tier check → purchase god → verify tier unchanged', async () => {
    const a = agent();
    await api('POST', '/keys', { headers: auth(a), body: { name: 'chain1' } });
    const before = await api('GET', `/keys/${a.address}/credits`);
    // Try god tier purchase
    await api('POST', '/keys/purchase', { body: { wallet: a.address, type: 'tier', tier: 'god' } });
    const after = await api('GET', `/keys/${a.address}/credits`);
    if (after.data?.tier === 'god') return 'CRITICAL: God tier purchase succeeded!';
    return before.data?.tier === after.data?.tier ? true : `Tier changed from ${before.data?.tier} to ${after.data?.tier}`;
  });

  await t('CHAIN-2: user create → PUT tier diamond → check perks', async () => {
    const a = agent();
    await api('POST', `/user/${a.address}`, { body: { username: 'chain2_' + crypto.randomBytes(3).toString('hex') } });
    await api('PUT', `/user/${a.address}`, { body: { tier: 'diamond' } });
    const perks = await api('GET', `/user/${a.address}/perks`);
    if (perks.data?.tier === 'diamond') return 'CRITICAL: Unauthenticated tier escalation via PUT';
    return true;
  });

  await t('CHAIN-3: signup → create 5 keys → verify limit → try 6th', async () => {
    const a = agent();
    const keys = [];
    for (let i = 0; i < 6; i++) {
      const r = await api('POST', '/keys', { headers: auth(a), body: { name: `chain3-${i}` } });
      if (r.status === 201) keys.push(r.data);
    }
    return keys.length <= 5 ? true : `CRITICAL: Created ${keys.length} keys (limit is 5)`;
  });

  await t('CHAIN-4: badge meta → find grantable badges → try automated grant', async () => {
    const meta = await api('GET', '/user/badges/meta');
    if (meta.status === 200 && meta.data?.categories) {
      // Try to grant every category type
      for (const cat of Object.keys(meta.data.categories).slice(0, 3)) {
        const badge = `${cat}:escalation_test`;
        const r = await api('POST', `/user/${eve.address}/badges/grant`, {
          body: { badge, grantedBy: 'chain4' }
        });
        if (r.status === 200 && r.data?.success) return `CRITICAL: Granted ${badge} without auth`;
      }
    }
    return true;
  });

  await t('CHAIN-5: verify/pricing → manipulate XRP price → underpay', async () => {
    const pricing = await api('GET', '/verify/pricing');
    if (pricing.data?.xrpPrice) {
      // The price comes from DB, cannot be manipulated from API
      // But check that the tolerance is not too loose
      const tier4Price = pricing.data.tiers?.['4']?.priceXrp;
      if (tier4Price && tier4Price < 1) return 'MEDIUM: Verification price too low — possible price manipulation';
    }
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 14: RESPONSE DATA LEAK CHECKS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 14. Response Data Leak Checks ───');

  await t('LEAK-1: error responses do not include stack traces', async () => {
    // Trigger an error and check for stack traces
    const r = await api('POST', '/verify/confirm', { body: { txHash: undefined } });
    const d = JSON.stringify(r.data || {});
    if (d.includes('at ') && d.includes('.js:')) return 'MEDIUM: Stack trace leaked in error response';
    return true;
  });

  await t('LEAK-2: key creation response does not leak hash', async () => {
    const a = agent();
    const r = await api('POST', '/keys', { headers: auth(a), body: { name: 'leak2' } });
    if (r.status === 201) {
      const d = JSON.stringify(r.data);
      if (d.includes('keyHash') || d.includes('hash')) {
        // keyId is OK, keyHash would be bad
        if (d.includes('keyHash')) return 'HIGH: Key hash leaked in creation response';
      }
    }
    return true;
  });

  await t('LEAK-3: /keys/:wallet does not expose other wallets\' data', async () => {
    const r = await api('GET', `/keys/${alice.address}`);
    if (r.status === 200 && r.data?.keys) {
      const d = JSON.stringify(r.data);
      if (d.includes(eve.address)) return 'CRITICAL: Cross-wallet data leak in key list';
    }
    return true;
  });

  await t('LEAK-4: user perks response does not leak internal fields', async () => {
    const r = await api('GET', `/user/${alice.address}/perks`);
    const d = JSON.stringify(r.data || {});
    if (d.includes('password') || d.includes('secret') || d.includes('privateKey'))
      return 'CRITICAL: Internal fields leaked in user perks';
    return true;
  });

  await t('LEAK-5: faucet status does not expose seed', async () => {
    const r = await api('GET', '/faucet');
    const d = JSON.stringify(r.data || {});
    if (d.includes('seed') || d.includes('secret') || d.includes('privateKey'))
      return 'CRITICAL: Faucet endpoint exposes wallet seed!';
    return true;
  });

  // ═══════════════════════════════════════════════════════════════
  // SECTION 15: RACE CONDITIONS
  // ═══════════════════════════════════════════════════════════════
  console.log('\n─── 15. Race Conditions ───');

  await t('RACE-1: concurrent key creates (20x) enforce limit', async () => {
    const a = agent();
    const promises = Array.from({ length: 20 }, (_, i) =>
      api('POST', '/keys', { headers: auth(a), body: { name: `race-${i}` } })
    );
    const results = await Promise.all(promises);
    const created = results.filter(r => r.status === 201).length;
    return created <= 5 ? true : `CRITICAL: Created ${created} keys (limit 5) under 20x race`;
  });

  await t('RACE-2: concurrent badge grants (should all fail without auth)', async () => {
    const target = agent();
    const promises = Array.from({ length: 10 }, (_, i) =>
      api('POST', `/user/${target.address}/badges/grant`, {
        body: { badge: `special:race_${i}`, grantedBy: 'racer' }
      })
    );
    const results = await Promise.all(promises);
    const granted = results.filter(r => r.status === 200 && r.data?.success).length;
    return granted === 0 ? true : `CRITICAL: ${granted}/10 badges granted without auth in race`;
  });

  await t('RACE-3: concurrent promotion claims', async () => {
    const a = agent();
    const md5 = 'd'.repeat(32);
    const promises = Array.from({ length: 10 }, () =>
      api('POST', '/promotion/claim', { headers: auth(a), body: { md5, account: a.address } })
    );
    const results = await Promise.all(promises);
    const ok = results.filter(r => r.status === 200);
    return ok.length <= 1 ? true : `CRITICAL: ${ok.length}/10 claims succeeded (should be max 1)`;
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
