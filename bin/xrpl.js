#!/usr/bin/env node
const { Command } = require('commander');
const config = require('../lib/config');
const api = require('../lib/api');
const out = require('../lib/output');
const wallet = require('../lib/wallet');

const program = new Command();

program
  .name('xrpl')
  .version('1.1.0')
  .description('Official CLI for xrpl.to — XRPL token analytics & market data')
  .option('--json', 'Output as JSON (for LLM agents)')
  .hook('preAction', (thisCommand) => {
    if (thisCommand.optsWithGlobals().json) out.setJsonMode(true);
  });

// ─── Helpers ──────────────────────────────────────────────────
function requireKeypair(opts) {
  const kp = wallet.load(opts?.keypair);
  if (!kp) {
    out.error(
      'Keypair not found',
      11,
      'Run `xrpl keygen` to generate a keypair first.'
    );
  }
  return kp;
}

// ═══════════════════════════════════════════════════════════════
// COMMANDS
// ═══════════════════════════════════════════════════════════════

// ─── Keygen ──────────────────────────────────────────────────
program.command('keygen')
  .description('Generate a new XRPL keypair')
  .action(() => {
    if (wallet.keypairExists()) {
      const existing = wallet.load();
      out.error(
        `Keypair already exists at ${wallet.DEFAULT_KEYPAIR_PATH}`,
        1,
        `Address: ${existing.address}. Delete the file to regenerate.`
      );
    }
    const kp = wallet.generate();
    out.success({
      address: kp.address,
      publicKey: kp.publicKey,
      path: wallet.DEFAULT_KEYPAIR_PATH,
      next_steps: [
        'Run `xrpl signup` to create a free account and get an API key.',
        'No funding required for free tier (1M credits/month).'
      ]
    });
  });

// ─── Signup ──────────────────────────────────────────────────
program.command('signup')
  .description('Create free account + API key (requires keypair)')
  .option('-n, --name <name>', 'API key name', 'CLI Agent Key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts) => {
    const kp = requireKeypair(opts);

    const existing = await api.get(`/keys/${kp.address}`, { rawResponse: true, authenticated: false });
    if (existing.status === 200 && existing.data?.count > 0) {
      out.error(
        `Wallet ${kp.address} already has ${existing.data.count} API key(s).`,
        1,
        'Run `xrpl login` to authenticate, or `xrpl keys` to see existing keys.'
      );
    }

    const authHeaders = wallet.getAuthHeaders(kp, 'POST', '/keys');
    const result = await api.post('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (!result.success) {
      out.error(result.error || 'Signup failed', 40);
    }

    config.set('apiKey', result.apiKey);
    config.set('wallet', kp.address);

    out.success({
      status: 'account_created',
      wallet: kp.address,
      apiKey: result.apiKey,
      tier: result.tier || 'free',
      credits: result.credits,
      next_steps: [
        'Your API key has been saved to ~/.xrpl-cli/config.json',
        'Test it: curl -H "X-Api-Key: YOUR_KEY" https://api.xrpl.to/v1/tokens?limit=5',
        'Check usage: xrpl usage',
        'See endpoints: xrpl docs'
      ]
    });
  });

// ─── Login ───────────────────────────────────────────────────
program.command('login')
  .description('Authenticate with existing wallet keypair')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts) => {
    const kp = requireKeypair(opts);

    const info = await api.get(`/keys/${kp.address}`, { rawResponse: true, authenticated: false });
    if (info.status !== 200 || !info.data?.count) {
      out.error(
        `No account found for wallet ${kp.address}`,
        10,
        'Run `xrpl signup` to create an account first.'
      );
    }

    config.set('wallet', kp.address);
    const keysInfo = info.data;
    const currentKey = config.get('apiKey');

    out.success({
      status: 'logged_in',
      wallet: kp.address,
      tier: keysInfo.tier,
      credits: keysInfo.credits,
      apiKeys: keysInfo.count,
      hasApiKeyConfigured: !!currentKey,
      hint: currentKey ? null : 'No API key in config. Create one: xrpl keys create'
    });
  });

// ─── Keys ────────────────────────────────────────────────────
const keys = program.command('keys').description('API key management');

keys.command('list', { isDefault: true })
  .description('List API keys for your wallet')
  .action(async () => {
    const addr = config.get('wallet');
    if (!addr) out.error('Not logged in. Run `xrpl signup` or `xrpl login` first.', 10);
    const data = await api.get(`/keys/${addr}`);
    out.success(data);
  });

keys.command('create')
  .description('Create a new API key')
  .option('-n, --name <name>', 'Key name', 'CLI Key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts) => {
    const kp = requireKeypair(opts);
    const authHeaders = wallet.getAuthHeaders(kp, 'POST', '/keys');
    const result = await api.post('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (result.apiKey) {
      config.set('apiKey', result.apiKey);
      result.config_saved = true;
    }

    out.success(result);
  });

keys.command('revoke <keyId>')
  .description('Revoke an API key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (keyId, opts) => {
    const kp = requireKeypair(opts);
    const authHeaders = wallet.getAuthHeaders(kp, 'DELETE', `/keys/${kp.address}/${keyId}`);
    const data = await api.del(`/keys/${kp.address}/${keyId}`, { authHeaders });
    out.success(data);
  });

// ─── Usage ───────────────────────────────────────────────────
program.command('usage')
  .description('Show credits usage and billing info')
  .action(async () => {
    const addr = config.get('wallet');
    if (!addr) out.error('Not logged in. Run `xrpl signup` or `xrpl login` first.', 10);
    const [usage, credits] = await Promise.all([
      api.get(`/keys/${addr}/usage`),
      api.get(`/keys/${addr}/credits`)
    ]);
    out.success({ usage, credits });
  });

// ─── Tiers ───────────────────────────────────────────────────
program.command('tiers')
  .description('Show available pricing tiers')
  .action(async () => {
    const data = await api.get('/keys/tiers', { authenticated: false });
    out.success(data);
  });

// ─── Upgrade ─────────────────────────────────────────────────
program.command('upgrade')
  .description('Show upgrade options and payment instructions')
  .action(async () => {
    const w = config.get('wallet');

    const [tiers, subscription] = await Promise.all([
      api.get('/keys/tiers', { authenticated: false }),
      w ? api.get(`/keys/${w}/subscription`, { rawResponse: true }).then(r => r.data) : null
    ]);

    const currentTier = subscription?.subscription?.tier || 'free';

    out.success({
      wallet: w,
      currentTier,
      currentCredits: subscription?.subscription?.credits,
      availableTiers: tiers.tiers?.filter(t => {
        const order = ['free', 'developer', 'business', 'professional'];
        return order.indexOf(t.name) > order.indexOf(currentTier) && t.name !== 'partner';
      }),
      paymentAddress: tiers.paymentAddress,
      xrpRate: tiers.xrpRate,
      how_to_upgrade: [
        '1. Send XRP payment to the payment address above',
        '2. Verify: curl -X POST https://api.xrpl.to/v1/keys/verify-payment -d \'{"txHash":"YOUR_TX_HASH"}\''
      ]
    });
  });

// ─── Docs ────────────────────────────────────────────────────
program.command('docs')
  .description('Show API endpoints and documentation')
  .action(() => {
    out.success({
      baseUrl: 'https://api.xrpl.to/v1',
      authentication: 'X-Api-Key header or ?apiKey= query parameter',
      endpoints: {
        tokens: [
          'GET /tokens                          - List tokens (sort, filter, paginate)',
          'GET /token/{id}                      - Token by md5, slug, name, or issuer_currency',
          'GET /token/review/{id}               - Token safety & risk assessment',
          'GET /token/flow/{id}                 - Creator token flow analysis',
          'GET /search                          - Search tokens, NFTs, accounts'
        ],
        charts: [
          'GET /ohlc/{id}                       - OHLC candlestick data',
          'GET /sparkline/{id}                  - Price sparkline'
        ],
        trading: [
          'GET /history?md5={id}                - Trade history',
          'GET /orderbook?base=XRP&quote={md5}  - DEX orderbook',
          'POST /dex/quote                      - DEX swap quote',
          'POST /submit                         - Submit signed transaction'
        ],
        account: [
          'GET /account/balance/{address}       - XRP balance + ranking',
          'GET /account/tx/{address}            - Transaction history',
          'GET /account/trustlines/{address}    - Trust lines',
          'GET /account/info/{address}          - Account info (live + DB)',
          'GET /account/offers/{address}        - Trading offers',
          'GET /account/objects/{address}       - Escrows, checks, etc.',
          'GET /account/ancestry/{address}      - Account genealogy',
          'GET /account/nfts/{address}          - Account NFTs'
        ],
        traders: [
          'GET /traders/{address}               - Trader profile',
          'GET /traders/token/{md5}             - Top traders for token',
          'GET /traders/portfolio/{address}     - Portfolio holdings'
        ],
        nft: [
          'GET /nft/{nftId}                     - NFT details',
          'GET /nft/collections                 - List collections',
          'GET /nft/collections/{slug}          - Collection details',
          'GET /nft/{nftId}/offers              - Buy/sell offers',
          'GET /nft/history/{nftId}             - NFT history'
        ],
        analytics: [
          'GET /creator-activity/{id}           - Creator activity + signals',
          'GET /tx/explain/{hash}               - Explain transaction (AI)',
          'GET /amm-pools                       - AMM pools',
          'GET /holders/list/{md5}              - Token holders / richlist'
        ],
        keys: [
          'GET /keys/{wallet}                   - List API keys',
          'POST /keys                           - Create API key',
          'DELETE /keys/{wallet}/{keyId}        - Revoke key',
          'GET /keys/{wallet}/usage             - Usage stats',
          'GET /keys/{wallet}/credits           - Credit balance',
          'GET /keys/tiers                      - Pricing tiers',
          'GET /keys/packages                   - Credit packages'
        ]
      },
      example: 'curl -H "X-Api-Key: YOUR_KEY" https://api.xrpl.to/v1/tokens?limit=10'
    });
  });

// ─── Health ──────────────────────────────────────────────────
program.command('health')
  .description('Check API health status')
  .action(async () => {
    const data = await api.get('/health', { authenticated: false });
    out.success(data);
  });

// ─── Config ──────────────────────────────────────────────────
const cfg = program.command('config').description('Manage CLI configuration');

cfg.command('show', { isDefault: true })
  .description('Show current configuration')
  .action(() => {
    const c = config.load();
    out.success({
      baseUrl: c.baseUrl,
      apiKey: c.apiKey ? c.apiKey.substring(0, 8) + '***' : null,
      wallet: c.wallet,
      keypair: wallet.keypairExists() ? wallet.DEFAULT_KEYPAIR_PATH : null,
      configFile: config.CONFIG_FILE
    });
  });

cfg.command('set-key <apiKey>')
  .description('Set API key')
  .action((apiKey) => {
    if (!apiKey.startsWith('xrpl_') || apiKey.length < 20) {
      out.error('Invalid API key format. Keys start with xrpl_ and are 37+ chars.', 1);
    }
    config.set('apiKey', apiKey);
    out.success({ saved: true, keyPrefix: apiKey.substring(0, 8) + '***' });
  });

cfg.command('set-url <url>')
  .description('Set API base URL')
  .action((url) => {
    let parsed;
    try { parsed = new URL(url); } catch { out.error('Invalid URL format', 1); }
    if (parsed.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(parsed.hostname)) {
      out.error('Only HTTPS URLs are allowed (except localhost for development)', 1);
    }
    if (['169.254.169.254', 'metadata.google.internal'].includes(parsed.hostname)) {
      out.error('Blocked: cloud metadata endpoint', 1);
    }
    config.set('baseUrl', url);
    out.success({ saved: true, baseUrl: url });
  });

cfg.command('reset')
  .description('Reset all configuration')
  .action(() => {
    config.save({ baseUrl: 'https://api.xrpl.to/v1', apiKey: null, wallet: null });
    out.success({ reset: true });
  });

program.parse();
