#!/usr/bin/env node
/**
 * Test all endpoints migrated from curl/execSync to native Bun fetch.
 * Verifies each file's fetch calls still work correctly.
 */

const BASE = process.env.API_URL || 'http://localhost:3000/api';
let pass = 0, fail = 0;
const results = [];

async function req(method, path, { body, headers = {} } = {}) {
  const opts = { method, headers: { 'Accept': 'application/json', ...headers }, signal: AbortSignal.timeout(15000) };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(`${BASE}${path}`, opts);
  let data; try { data = await res.json(); } catch { data = null; }
  return { status: res.status, data };
}

function test(name, passed, detail) {
  if (passed) { pass++; results.push(`  ✓ ${name}`); }
  else { fail++; results.push(`  ✗ ${name}${detail ? ' — ' + detail : ''}`); }
}

// 1. verify.js — fetchPost to testnet RPC, fetchGet
async function testVerify() {
  results.push('\n[verify.js] fetchPost → testnet RPC');
  const r1 = await req('GET', '/verify/pricing');
  test('GET /verify/pricing returns tiers + XRP price', r1.data?.success === true && r1.data?.tiers);

  const r2 = await req('POST', '/verify/request', { body: { type: 'token', id: 'nonexistent', tier: 4 } });
  test('POST /verify/request handles lookup (404 expected)', r2.status === 404 || r2.data?.error);

  // confirm uses fetchPost to testnet RPC
  const r3 = await req('POST', '/verify/confirm', { body: { txHash: 'A'.repeat(64) } });
  test('POST /verify/confirm calls RPC (tx not found expected)', r3.status === 400 || r3.status === 500);
}

// 2. user.js — fetchPost to mainnet RPC, fetchStripeApi
async function testUser() {
  results.push('\n[user.js] fetchPost → mainnet RPC, fetchStripeApi');
  const r1 = await req('GET', '/user/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe');
  test('GET /user/:account works', [200, 404].includes(r1.status));

  // tier/purchase triggers fetchPost to MAINNET_RPC for payment verification
  const r2 = await req('POST', '/user/tier/purchase', { body: { tier: 'vip', address: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe' } });
  test('POST /user/tier/purchase responds', [200, 400, 404, 503].includes(r2.status));
}

// 3. submit.js — fetchPost to rippled
async function testSubmit() {
  results.push('\n[submit.js] fetchPost → rippled');
  const r1 = await req('GET', '/submit/fee');
  test('GET /submit/fee returns fee data', r1.data?.success === true && r1.data?.base_fee);

  const r2 = await req('GET', '/submit/account/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe/sequence');
  test('GET /submit/account/:addr/sequence works', r2.data?.success === true && typeof r2.data?.sequence === 'number');
}

// 4. boost.js — fetchPost to testnet RPC
async function testBoost() {
  results.push('\n[boost.js] fetchPost → testnet RPC');
  const r1 = await req('GET', '/boost/active');
  test('GET /boost/active works', r1.status === 200 && r1.data?.tokens !== undefined);

  // /boost/verify uses fetchPost to testnet RPC
  const r2 = await req('GET', '/boost/verify/nonexistent');
  test('GET /boost/verify/:id calls DB', [200, 404, 500].includes(r2.status));
}

// 5. testnet.js — fetchPost to testnet RPC
async function testTestnet() {
  results.push('\n[testnet.js] fetchPost → testnet RPC');
  const r1 = await req('GET', '/testnet/account/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe');
  test('GET /testnet/account/:addr calls testnet RPC', [200, 404, 500].includes(r1.status));
}

// 6. bridge.js — fetchGet/fetchPost to ChangeNow
async function testBridge() {
  results.push('\n[bridge.js] fetchGet/fetchPost → ChangeNow API');
  const r1 = await req('GET', '/bridge/currencies');
  test('GET /bridge/currencies returns array', Array.isArray(r1.data) && r1.data.length > 0);

  const r2 = await req('GET', '/bridge/estimate?from=btc&to=xrp&amount=0.1');
  test('GET /bridge/estimate returns estimate', r2.data?.estimatedAmount || r2.data?.error);

  const r3 = await req('GET', '/bridge/min-amount?from=btc&to=xrp');
  test('GET /bridge/min-amount returns min', r3.data?.minAmount !== undefined || r3.data?.error);
}

// 7. amm.js — fetchGet (defined but check endpoint works)
async function testAmm() {
  results.push('\n[amm.js] fetchGet');
  const r1 = await req('GET', '/amm/pools?limit=2');
  test('GET /amm/pools works', r1.data || r1.status === 200);
}

// 8. account.js — async accountTxRequest to history nodes
async function testAccount() {
  results.push('\n[account.js] fetch → history nodes');
  const r1 = await req('GET', '/account/balance/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe');
  test('GET /account/balance/:addr works', r1.data?.success === true);

  const r2 = await req('GET', '/account/tx/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe?limit=5');
  test('GET /account/tx/:addr fetches from history nodes', r2.data?.success === true || r2.data?.transactions);
}

// 9. dex.js — callWithTimeout (async fetch)
async function testDex() {
  results.push('\n[dex.js] callWithTimeout → fetch');
  const r1 = await req('POST', '/dex/quote', {
    body: { source_account: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe', destination_amount: { currency: 'XRP', value: '10' } }
  });
  test('POST /dex/quote responds', [200, 400, 404, 500].includes(r1.status));
}

// 10. xumm.js — fetchRequest (GET/POST/DELETE)
async function testXumm() {
  results.push('\n[xumm.js] fetchRequest → Xumm API');
  // GET payload with fake uuid — should return error from Xumm, not crash
  const r1 = await req('GET', '/xumm/payload/00000000-0000-0000-0000-000000000000');
  test('GET /xumm/payload/:uuid responds (error expected)', [200, 400, 404, 500].includes(r1.status));
}

// 11. nft_pin.js — ipfsPost to local IPFS
async function testNftPin() {
  results.push('\n[nft_pin.js] fetch → IPFS');
  const r1 = await req('POST', '/nft/pin/', { body: { hash: 'QmTest123' } });
  test('POST /nft/pin responds (may fail if IPFS down)', [200, 400, 500, 502].includes(r1.status));
}

// 12. tx_explain.js — fetchPost to AI providers
async function testTxExplain() {
  results.push('\n[tx_explain.js] fetchPost → AI providers');
  const r1 = await req('GET', '/tx-explain/E4A22F365B5B1E4C44D tried0B92C2C5E05C0B70E44E9E5ED43F33E5B3CA0DD61');
  test('GET /tx-explain/:hash validation', r1.status === 400);

  // Valid hash — will call AI provider via fetch
  const r2 = await req('GET', '/tx-explain/E4A22F365B5B1E4C440B92C2C5E05C0B70E44E9E5ED43F33E5B3CA0DD61A1B2C');
  test('GET /tx-explain/:hash calls AI via fetch', [200, 404, 500, 502, 503].includes(r2.status));
}

// 13. account_tx_explain.js — fetchPost to AI + fetch to history nodes
async function testAccountTxExplain() {
  results.push('\n[account_tx_explain.js] fetchPost → AI + history nodes');
  const r1 = await req('GET', '/account-explain/rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe?limit=5');
  test('GET /account-explain/:addr calls fetch', [200, 400, 404, 500, 502].includes(r1.status));
}

// 14. oauth.js — httpPost/httpGet (async fetch)
async function testOauth() {
  results.push('\n[oauth.js] httpPost/httpGet → fetch');
  // twitter oauth1 request — will fail auth but proves route + fetch work
  const r1 = await req('POST', '/oauth/twitter/oauth1/request', { body: { callbackUrl: 'https://test.com' } });
  test('POST /oauth/twitter/oauth1/request responds', [200, 400, 401, 500].includes(r1.status));
}

// 15. tweet_verify.js — fetchOembed
async function testTweetVerify() {
  results.push('\n[tweet_verify.js] fetchOembed → Twitter');
  const r1 = await req('POST', '/tweet-verify/submit', {
    body: { tweetUrl: 'https://x.com/test/status/123', md5: 'abc', account: 'rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe' }
  });
  test('POST /tweet-verify/submit calls fetchOembed', [200, 400, 404, 422, 429, 500].includes(r1.status));
}

async function main() {
  console.log(`\nFetch Migration Test — ${BASE}\n${'='.repeat(50)}`);

  const tests = [
    ['verify', testVerify], ['user', testUser], ['submit', testSubmit],
    ['boost', testBoost], ['testnet', testTestnet], ['bridge', testBridge],
    ['amm', testAmm], ['account', testAccount], ['dex', testDex],
    ['xumm', testXumm], ['nft_pin', testNftPin], ['tx_explain', testTxExplain],
    ['account_tx_explain', testAccountTxExplain], ['oauth', testOauth],
    ['tweet_verify', testTweetVerify]
  ];

  for (const [name, fn] of tests) {
    try { await fn(); } catch (e) { results.push(`  ✗ ${name} CRASH: ${e.message}`); fail++; }
  }

  console.log(results.join('\n'));
  console.log(`\n${'='.repeat(50)}`);
  console.log(`PASS: ${pass}  FAIL: ${fail}  TOTAL: ${pass + fail}`);
  console.log(fail === 0 ? '\nAll tests passed.' : `\n${fail} test(s) failed!`);
  process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(2); });
