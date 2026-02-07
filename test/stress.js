#!/usr/bin/env node
/**
 * Stress test: Simulate 50-100 agents signing up and querying concurrently.
 *
 * Phase 1: Signup — generate keypair + create API key (sequential batches of 10)
 * Phase 2: Query — all agents hit endpoints concurrently
 * Phase 3: Credit check — verify billing state for all agents
 */

const xrpl = require('xrpl');
const { sign, deriveKeypair, deriveAddress } = require('ripple-keypairs');

const API_BASE = process.env.API_URL || 'http://localhost:3000/api';
const AGENT_COUNT = parseInt(process.env.AGENTS || '50');
const CONCURRENCY = parseInt(process.env.CONCURRENCY || '10');

const agents = [];
const results = { signup: { ok: 0, fail: 0, errors: {} }, query: { ok: 0, fail: 0, errors: {} }, credits: { ok: 0, fail: 0 } };
const timings = { signup: [], query: [], credits: [] };

function generateAgent(i) {
  const wallet = xrpl.Wallet.generate();
  const { privateKey, publicKey } = deriveKeypair(wallet.seed);
  return {
    id: i,
    address: wallet.address,
    seed: wallet.seed,
    publicKey,
    privateKey,
    apiKey: null
  };
}

function getAuthHeaders(agent) {
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

async function apiCall(method, path, { headers = {}, body } = {}) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json', 'User-Agent': 'xrpl-cli-stress/1.0', ...headers },
    signal: AbortSignal.timeout(30000)
  };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(`${API_BASE}${path}`, opts);
  const data = await res.json();
  return { status: res.status, data };
}

async function signupAgent(agent) {
  const start = Date.now();
  try {
    const auth = getAuthHeaders(agent);
    const { status, data } = await apiCall('POST', '/keys', {
      headers: auth,
      body: { name: `Agent-${agent.id}` }
    });
    const ms = Date.now() - start;
    timings.signup.push(ms);

    if (status === 201 && data.apiKey) {
      agent.apiKey = data.apiKey;
      results.signup.ok++;
      return true;
    } else {
      results.signup.fail++;
      const err = data.error || `HTTP ${status}`;
      results.signup.errors[err] = (results.signup.errors[err] || 0) + 1;
      return false;
    }
  } catch (e) {
    timings.signup.push(Date.now() - start);
    results.signup.fail++;
    const err = e.name === 'TimeoutError' ? 'timeout' : e.message;
    results.signup.errors[err] = (results.signup.errors[err] || 0) + 1;
    return false;
  }
}

async function queryAsAgent(agent) {
  const start = Date.now();
  try {
    const { status, data } = await apiCall('GET', '/tokens?limit=5', {
      headers: { 'X-Api-Key': agent.apiKey }
    });
    const ms = Date.now() - start;
    timings.query.push(ms);

    if (status === 200 && data.tokens) {
      results.query.ok++;
    } else {
      results.query.fail++;
      const err = data.error || `HTTP ${status}`;
      results.query.errors[err] = (results.query.errors[err] || 0) + 1;
    }
  } catch (e) {
    timings.query.push(Date.now() - start);
    results.query.fail++;
    const err = e.name === 'TimeoutError' ? 'timeout' : e.message;
    results.query.errors[err] = (results.query.errors[err] || 0) + 1;
  }
}

async function checkCredits(agent) {
  const start = Date.now();
  try {
    const { status, data } = await apiCall('GET', `/keys/${agent.address}/credits`, {
      headers: { 'X-Api-Key': agent.apiKey }
    });
    const ms = Date.now() - start;
    timings.credits.push(ms);

    if (status === 200 && data.success) {
      results.credits.ok++;
      return data;
    } else {
      results.credits.fail++;
    }
  } catch {
    timings.credits.push(Date.now() - start);
    results.credits.fail++;
  }
  return null;
}

function stats(arr) {
  if (!arr.length) return { min: 0, max: 0, avg: 0, p50: 0, p95: 0, p99: 0 };
  arr.sort((a, b) => a - b);
  return {
    min: arr[0],
    max: arr[arr.length - 1],
    avg: Math.round(arr.reduce((a, b) => a + b, 0) / arr.length),
    p50: arr[Math.floor(arr.length * 0.5)],
    p95: arr[Math.floor(arr.length * 0.95)],
    p99: arr[Math.floor(arr.length * 0.99)]
  };
}

async function runBatch(items, fn, batchSize) {
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    await Promise.all(batch.map(fn));
  }
}

async function main() {
  console.log(`\n=== XRPL CLI Stress Test ===`);
  console.log(`Agents: ${AGENT_COUNT} | Concurrency: ${CONCURRENCY} | API: ${API_BASE}\n`);

  // Phase 0: Generate keypairs
  const t0 = Date.now();
  for (let i = 0; i < AGENT_COUNT; i++) agents.push(generateAgent(i));
  console.log(`[keygen] ${AGENT_COUNT} keypairs in ${Date.now() - t0}ms`);

  // Phase 1: Signup
  console.log(`\n[signup] Registering ${AGENT_COUNT} agents (batches of ${CONCURRENCY})...`);
  const t1 = Date.now();
  await runBatch(agents, signupAgent, CONCURRENCY);
  const signupTotal = Date.now() - t1;
  console.log(`[signup] Done in ${signupTotal}ms — ${results.signup.ok} ok, ${results.signup.fail} fail`);
  if (Object.keys(results.signup.errors).length) console.log(`[signup] Errors:`, results.signup.errors);
  console.log(`[signup] Latency:`, stats(timings.signup));

  // Phase 2: Concurrent queries (only agents with keys)
  const active = agents.filter(a => a.apiKey);
  console.log(`\n[query] ${active.length} agents querying /tokens concurrently (batches of ${CONCURRENCY})...`);
  const t2 = Date.now();
  await runBatch(active, queryAsAgent, CONCURRENCY);
  const queryTotal = Date.now() - t2;
  console.log(`[query] Done in ${queryTotal}ms — ${results.query.ok} ok, ${results.query.fail} fail`);
  if (Object.keys(results.query.errors).length) console.log(`[query] Errors:`, results.query.errors);
  console.log(`[query] Latency:`, stats(timings.query));

  // Phase 3: Credit verification
  console.log(`\n[credits] Checking credits for ${active.length} agents...`);
  const t3 = Date.now();
  let totalBalance = 0, totalUsed = 0;
  const creditResults = [];
  await runBatch(active, async (agent) => {
    const cr = await checkCredits(agent);
    if (cr) {
      creditResults.push(cr);
      totalBalance += cr.balance || 0;
      totalUsed += cr.totalUsed || 0;
    }
  }, CONCURRENCY);
  const creditsTotal = Date.now() - t3;
  console.log(`[credits] Done in ${creditsTotal}ms — ${results.credits.ok} ok, ${results.credits.fail} fail`);
  console.log(`[credits] Latency:`, stats(timings.credits));

  // Summary
  const tiers = {};
  creditResults.forEach(c => { tiers[c.tier] = (tiers[c.tier] || 0) + 1; });

  console.log(`\n=== Summary ===`);
  console.log(`Total time: ${Date.now() - t0}ms`);
  console.log(`Agents created: ${results.signup.ok}/${AGENT_COUNT}`);
  console.log(`Queries passed: ${results.query.ok}/${active.length}`);
  console.log(`Credits checked: ${results.credits.ok}/${active.length}`);
  console.log(`Tier distribution:`, tiers);
  console.log(`Total balance across all agents: ${totalBalance.toLocaleString()}`);
  console.log(`Total credits used: ${totalUsed}`);
  console.log(`Avg credits remaining per agent: ${active.length ? Math.round(totalBalance / active.length).toLocaleString() : 0}`);

  // Rate limit detection
  const rateLimited = (results.signup.errors['Rate limit exceeded'] || 0) +
                      (results.query.errors['Rate limit exceeded'] || 0);
  if (rateLimited) console.log(`\nRate limited: ${rateLimited} requests`);

  const exitCode = results.signup.fail > AGENT_COUNT * 0.1 ? 1 : 0;
  console.log(`\nResult: ${exitCode === 0 ? 'PASS' : 'FAIL'} (>90% signup success required)`);
  process.exit(exitCode);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
