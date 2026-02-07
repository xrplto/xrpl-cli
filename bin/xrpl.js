#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const config = require('../lib/config');
const api = require('../lib/api');
const out = require('../lib/output');
const wallet = require('../lib/wallet');

const program = new Command();

program
  .name('xrpl')
  .version('1.0.0')
  .description('XRPL CLI — Token analytics & market data for LLM agents')
  .option('--json', 'Output as JSON (for LLM agents)')
  .option('--fields <fields>', 'Comma-separated fields to return')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .hook('preAction', (thisCommand) => {
    const opts = thisCommand.optsWithGlobals();
    if (opts.json) out.setJsonMode(true);
  });

// ─── Helper: require keypair ───────────────────────────────────
function requireKeypair(opts) {
  const kp = wallet.load(opts?.keypair);
  if (!kp) {
    out.error(
      `Keypair not found at ${wallet.getKeypairPath(opts?.keypair)}`,
      11,
      'Run `xrpl keygen` to generate a keypair first.'
    );
  }
  return kp;
}

// ─── Helper: require API key ───────────────────────────────────
function requireApiKey() {
  const key = config.get('apiKey');
  if (!key) {
    out.error(
      'Not logged in. No API key configured.',
      10,
      'Run: xrpl signup  OR  xrpl config set-key <key>'
    );
  }
  return key;
}

// ═══════════════════════════════════════════════════════════════
// ONBOARDING COMMANDS (Helius-like flow)
// ═══════════════════════════════════════════════════════════════

// ─── Keygen ────────────────────────────────────────────────────
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

// ─── Signup ────────────────────────────────────────────────────
program.command('signup')
  .description('Create free account + API key (requires keypair)')
  .option('-n, --name <name>', 'API key name', 'CLI Agent Key')
  .action(async (opts) => {
    const kp = requireKeypair(program.opts());

    // Check if wallet already has keys
    const existing = await api.get(`/keys/${kp.address}`, { rawResponse: true });
    if (existing.status === 200 && existing.data?.count > 0) {
      out.error(
        `Wallet ${kp.address} already has ${existing.data.count} API key(s).`,
        1,
        'Run `xrpl login` to authenticate, or `xrpl keys list` to see existing keys.'
      );
    }

    // Create key via signature auth
    const authHeaders = wallet.getAuthHeaders(kp);
    const result = await api.post('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (!result.success) {
      out.error(result.error || 'Signup failed', 40);
    }

    // Auto-save the API key and wallet
    config.set('apiKey', result.apiKey);
    config.set('wallet', kp.address);

    out.success({
      status: 'account_created',
      wallet: kp.address,
      apiKey: result.apiKey,
      keyPrefix: result.keyPrefix,
      tier: result.tier || 'free',
      credits: result.credits,
      warning: result.warning,
      config_saved: true,
      next_steps: [
        'Your API key has been saved to ~/.xrpl-cli/config.json',
        'Start querying: xrpl token list --json',
        'Check usage: xrpl keys usage ' + kp.address,
        'Upgrade tier: xrpl upgrade'
      ]
    });
  });

// ─── Login ─────────────────────────────────────────────────────
program.command('login')
  .description('Authenticate with existing wallet keypair')
  .action(async (_, cmd) => {
    const kp = requireKeypair(cmd.optsWithGlobals());

    // Verify wallet has keys on the API
    const info = await api.get(`/keys/${kp.address}`, { rawResponse: true });
    if (info.status !== 200 || !info.data?.count) {
      out.error(
        `No account found for wallet ${kp.address}`,
        10,
        'Run `xrpl signup` to create an account first.'
      );
    }

    // Save wallet to config
    config.set('wallet', kp.address);

    // If no API key saved, show the keys
    const currentKey = config.get('apiKey');
    const keysInfo = info.data;

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

// ─── Upgrade ───────────────────────────────────────────────────
program.command('upgrade')
  .description('Show available tier upgrades and how to pay')
  .action(async () => {
    const w = config.get('wallet');

    // Get current subscription + available tiers
    const [tiers, subscription] = await Promise.all([
      api.get('/keys/tiers'),
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
        '1. xrpl keys purchase --type tier --tier developer',
        '2. Send the XRP payment shown in the response',
        '3. xrpl keys verify-payment <txHash>'
      ]
    });
  });

// ─── Keys ──────────────────────────────────────────────────────
const keys = program.command('keys').description('API key management');

keys.command('list [wallet]')
  .description('List API keys for a wallet')
  .action(async (w) => {
    const addr = w || config.get('wallet');
    if (!addr) out.error('Wallet address required. Run `xrpl signup` or provide wallet.', 11);
    const data = await api.get(`/keys/${addr}`);
    out.success(data);
  });

keys.command('create')
  .description('Create a new API key (requires keypair)')
  .option('-n, --name <name>', 'Key name', 'CLI Key')
  .action(async (opts) => {
    const kp = requireKeypair(program.opts());
    const authHeaders = wallet.getAuthHeaders(kp);
    const result = await api.post('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (result.apiKey) {
      // Ask if they want to save as default
      config.set('apiKey', result.apiKey);
      result.config_saved = true;
    }

    out.success(result);
  });

keys.command('revoke <keyId>')
  .description('Revoke an API key')
  .action(async (keyId) => {
    const kp = requireKeypair(program.opts());
    const authHeaders = wallet.getAuthHeaders(kp);
    const data = await api.del(`/keys/${kp.address}/${keyId}`, { authHeaders });
    out.success(data);
  });

keys.command('usage [wallet]')
  .description('Usage stats for a wallet')
  .action(async (w) => {
    const addr = w || config.get('wallet');
    if (!addr) out.error('Wallet address required.', 11);
    const data = await api.get(`/keys/${addr}/usage`);
    out.success(data);
  });

keys.command('credits [wallet]')
  .description('Credit balance and billing info')
  .action(async (w) => {
    const addr = w || config.get('wallet');
    if (!addr) out.error('Wallet address required.', 11);
    const data = await api.get(`/keys/${addr}/credits`);
    out.success(data);
  });

keys.command('subscription [wallet]')
  .description('Current subscription and billing cycle')
  .action(async (w) => {
    const addr = w || config.get('wallet');
    if (!addr) out.error('Wallet address required.', 11);
    const data = await api.get(`/keys/${addr}/subscription`);
    out.success(data);
  });

keys.command('tiers')
  .description('Available pricing tiers with XRP prices')
  .action(async () => {
    const data = await api.get('/keys/tiers');
    out.success(data);
  });

keys.command('packages')
  .description('Credit packages for purchase')
  .action(async () => {
    const data = await api.get('/keys/packages');
    out.success(data);
  });

keys.command('costs')
  .description('Endpoint credit costs')
  .action(async () => {
    const data = await api.get('/keys/costs');
    out.success(data);
  });

keys.command('purchase')
  .description('Initiate tier upgrade or credit purchase')
  .option('--type <type>', 'Purchase type: tier or credits')
  .option('--tier <tier>', 'Tier name (developer, business, professional)')
  .option('--package <pkg>', 'Credit package (starter, standard, bulk, mega)')
  .option('--billing <billing>', 'Billing cycle (monthly, yearly)', 'monthly')
  .action(async (opts) => {
    const w = config.get('wallet');
    if (!w) out.error('Wallet required. Run `xrpl signup` first.', 11);
    const body = { wallet: w, billing: opts.billing };
    if (opts.type) body.type = opts.type;
    if (opts.tier) { body.type = 'tier'; body.tier = opts.tier; }
    if (opts.package) { body.type = 'credits'; body.package = opts.package; }
    if (!body.type) out.error('Specify --tier <name> or --package <name>', 1);
    const data = await api.post('/keys/purchase', { body });
    out.success(data);
  });

keys.command('verify-payment <txHash>')
  .description('Verify an XRP payment for tier/credits')
  .action(async (txHash) => {
    const data = await api.post('/keys/verify-payment', { body: { txHash } });
    out.success(data);
  });

// ─── Config ────────────────────────────────────────────────────
const cfg = program.command('config').description('Manage CLI configuration');

cfg.command('set-key <apiKey>')
  .description('Set API key for authentication')
  .action((apiKey) => {
    if (!apiKey.startsWith('xrpl_') || apiKey.length < 20) {
      out.error('Invalid API key format. Keys start with xrpl_ and are 37+ chars.', 1);
    }
    config.set('apiKey', apiKey);
    out.success({ saved: true, keyPrefix: apiKey.substring(0, 12) + '...' });
  });

cfg.command('set-url <url>')
  .description('Set API base URL')
  .action((url) => {
    try { new URL(url); } catch { out.error('Invalid URL format', 1); }
    config.set('baseUrl', url);
    out.success({ saved: true, baseUrl: url });
  });

cfg.command('set-wallet <wallet>')
  .description('Set default wallet address')
  .action((wallet) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(wallet)) {
      out.error('Invalid XRPL address format', 1);
    }
    config.set('wallet', wallet);
    out.success({ saved: true, wallet });
  });

cfg.command('show')
  .description('Show current configuration')
  .action(() => {
    const c = config.load();
    out.success({
      baseUrl: c.baseUrl,
      apiKey: c.apiKey ? c.apiKey.substring(0, 12) + '...' : null,
      wallet: c.wallet,
      keypair: wallet.keypairExists() ? wallet.DEFAULT_KEYPAIR_PATH : null,
      configFile: config.CONFIG_FILE
    });
  });

cfg.command('reset')
  .description('Reset all configuration')
  .action(() => {
    config.save({ baseUrl: 'https://api.xrpl.to/v1', apiKey: null, wallet: null });
    out.success({ reset: true });
  });

// ═══════════════════════════════════════════════════════════════
// DATA COMMANDS
// ═══════════════════════════════════════════════════════════════

// ─── Docs ──────────────────────────────────────────────────────
program.command('docs')
  .description('Full API documentation (all endpoints, params, responses)')
  .option('-s, --section <section>', 'Filter section (tokens, charts, trading, account, nft, keys, analytics, websocket, etc.)')
  .action(async (opts) => {
    const data = await api.get('/docs');
    if (opts.section) {
      const key = opts.section.toLowerCase();
      const match = Object.entries(data).find(([k]) => k.toLowerCase() === key || k.toLowerCase().includes(key));
      if (match) {
        out.success({ section: match[0], endpoints: match[1] });
      } else {
        out.success({ sections: Object.keys(data).filter(k => Array.isArray(data[k]) || typeof data[k] === 'object'), usage: 'xrpl docs --section tokens' });
      }
    } else {
      out.success(data);
    }
  });

// ─── Health ────────────────────────────────────────────────────
program.command('health')
  .description('Check API health status')
  .action(async () => {
    const data = await api.get('/health');
    out.success(data);
  });

// ─── Search ────────────────────────────────────────────────────
program.command('search <query>')
  .description('Search tokens, NFTs, collections, accounts')
  .option('-l, --limit <n>', 'Max results', '10')
  .action(async (query, opts) => {
    const data = await api.post('/search', { body: { query, limit: parseInt(opts.limit) } });
    out.success(data);
  });

// ─── Web Search ────────────────────────────────────────────────
program.command('web-search <query>')
  .description('Search the web via SearXNG (for LLM agents)')
  .option('-l, --limit <n>', 'Max results')
  .option('-c, --categories <cats>', 'Categories (general, news, science, it)')
  .option('-e, --engines <engines>', 'Specific engines')
  .option('--language <lang>', 'Language code (en, es, etc.)')
  .option('-p, --page <n>', 'Page number')
  .action(async (q, opts) => {
    const query = { q };
    if (opts.categories) query.categories = opts.categories;
    if (opts.engines) query.engines = opts.engines;
    if (opts.language) query.language = opts.language;
    if (opts.page) query.pageno = opts.page;
    const data = await api.get('/web-search', { query });
    // Trim results if limit specified
    if (opts.limit && data.results) {
      data.results = data.results.slice(0, parseInt(opts.limit));
    }
    out.success(data);
  });

// ─── Token ─────────────────────────────────────────────────────
const token = program.command('token').description('Token data & analytics');

token.command('info <id>')
  .description('Get token details (by md5, slug, name, or issuer_currency)')
  .option('-d, --description', 'Include description')
  .action(async (id, opts) => {
    const query = {};
    if (opts.description) query.description = 'true';
    const data = await api.get(`/token/${encodeURIComponent(id)}`, { query, fields: program.opts().fields });
    out.success(data);
  });

token.command('review <id>')
  .description('Token safety review & risk assessment')
  .action(async (id) => {
    const data = await api.get(`/token/review/${encodeURIComponent(id)}`);
    out.success(data);
  });

token.command('flow <id>')
  .description('Creator token flow analysis')
  .action(async (id) => {
    const data = await api.get(`/token/flow/${encodeURIComponent(id)}`);
    out.success(data);
  });

token.command('list')
  .description('List tokens with filtering')
  .option('-l, --limit <n>', 'Max results', '20')
  .option('-s, --sort <field>', 'Sort field (vol24hxrp, mc, trustlines, age, change24h)')
  .option('--dir <dir>', 'Sort direction (asc/desc)')
  .option('--tag <tag>', 'Filter by tag')
  .option('-p, --page <n>', 'Page number')
  .action(async (opts) => {
    const query = { limit: opts.limit };
    if (opts.sort) query.sortBy = opts.sort;
    if (opts.dir) query.sortDir = opts.dir;
    if (opts.tag) query.tag = opts.tag;
    if (opts.page) query.start = (parseInt(opts.page) - 1) * parseInt(opts.limit);
    const data = await api.get('/tokens', { query, fields: program.opts().fields });
    out.success(data);
  });

// ─── Account ───────────────────────────────────────────────────
const account = program.command('account').description('Account operations');

account.command('balance <address>')
  .description('XRP balance with reserves and ranking')
  .action(async (address) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) out.error('Invalid XRPL address', 1);
    const data = await api.get(`/account/balance/${address}`);
    out.success(data);
  });

account.command('tx <address>')
  .description('Transaction history')
  .option('-l, --limit <n>', 'Max results', '20')
  .option('-m, --marker <marker>', 'Pagination marker')
  .action(async (address, opts) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) out.error('Invalid XRPL address', 1);
    const query = { limit: opts.limit };
    if (opts.marker) query.marker = opts.marker;
    const data = await api.get(`/account/tx/${address}`, { query });
    out.success(data);
  });

account.command('trustlines <address>')
  .description('Account trust lines')
  .action(async (address) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) out.error('Invalid XRPL address', 1);
    const data = await api.get(`/account/trustlines/${address}`);
    out.success(data);
  });

account.command('info <address>')
  .description('Account info (live from node + DB enrichment)')
  .action(async (address) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) out.error('Invalid XRPL address', 1);
    const data = await api.get(`/account/info/${address}`);
    out.success(data);
  });

account.command('offers <address>')
  .description('Account trading offers')
  .action(async (address) => {
    const data = await api.get(`/account/offers/${address}`);
    out.success(data);
  });

account.command('objects <address>')
  .description('Account objects (escrows, checks, etc.)')
  .action(async (address) => {
    const data = await api.get(`/account/objects/${address}`);
    out.success(data);
  });

account.command('ancestry <address>')
  .description('Account genealogy (parents, children, tokens)')
  .action(async (address) => {
    const data = await api.get(`/account/ancestry/${address}`);
    out.success(data);
  });

account.command('nfts <address>')
  .description('Account NFTs')
  .action(async (address) => {
    const data = await api.get(`/account/nfts/${address}`);
    out.success(data);
  });

account.command('token-stats <address> <md5>')
  .description('Per-account per-token trading stats')
  .action(async (address, md5) => {
    const data = await api.get(`/account/token-stats/${address}/${md5}`);
    out.success(data);
  });

// ─── Price / Charts ────────────────────────────────────────────
const price = program.command('price').description('Market data & charts');

price.command('ohlc <id>')
  .description('OHLC candlestick data')
  .option('-i, --interval <interval>', 'Interval (1m,5m,15m,1h,4h,1D,1W)', '1h')
  .option('--from <ts>', 'Start timestamp (ms)')
  .option('--to <ts>', 'End timestamp (ms)')
  .option('--currency <cur>', 'Fiat conversion (USD,EUR,JPY)')
  .action(async (id, opts) => {
    const query = { interval: opts.interval };
    if (opts.from) query.from = opts.from;
    if (opts.to) query.to = opts.to;
    if (opts.currency) query.currency = opts.currency;
    const data = await api.get(`/ohlc/${encodeURIComponent(id)}`, { query });
    out.success(data);
  });

price.command('sparkline <id>')
  .description('Lightweight price sparkline')
  .action(async (id) => {
    const data = await api.get(`/sparkline/${encodeURIComponent(id)}`);
    out.success(data);
  });

// ─── Trade ─────────────────────────────────────────────────────
const trade = program.command('trade').description('Trading & DEX data');

trade.command('history <md5>')
  .description('Trade history for a token')
  .option('-l, --limit <n>', 'Max results', '20')
  .option('--from <ts>', 'Start timestamp (ms)')
  .option('--to <ts>', 'End timestamp (ms)')
  .action(async (md5, opts) => {
    const query = { md5, limit: opts.limit };
    if (opts.from) query.from = opts.from;
    if (opts.to) query.to = opts.to;
    const data = await api.get('/history', { query });
    out.success(data);
  });

trade.command('orderbook')
  .description('DEX orderbook')
  .option('--base <base>', 'Base currency', 'XRP')
  .option('--quote <md5>', 'Quote token md5')
  .action(async (opts) => {
    if (!opts.quote) out.error('--quote <md5> is required', 1);
    const data = await api.get('/orderbook', { query: { base: opts.base, quote: opts.quote } });
    out.success(data);
  });

trade.command('quote <from> <to> <amount>')
  .description('DEX swap quote')
  .action(async (from, to, amount) => {
    const data = await api.post('/dex/quote', { body: { from, to, amount: parseFloat(amount) } });
    out.success(data);
  });

// ─── Traders ───────────────────────────────────────────────────
const traders = program.command('traders').description('Trader analytics');

traders.command('profile <address>')
  .description('Trader profile with tokens traded')
  .action(async (address) => {
    const data = await api.get(`/traders/${address}`);
    out.success(data);
  });

traders.command('token <md5>')
  .description('Top traders for a token')
  .action(async (md5) => {
    const data = await api.get(`/traders/token/${md5}`);
    out.success(data);
  });

traders.command('portfolio <address>')
  .description('Trader portfolio holdings')
  .action(async (address) => {
    const data = await api.get(`/traders/portfolio/${address}`);
    out.success(data);
  });

// ─── Creator ───────────────────────────────────────────────────
program.command('creator <id>')
  .description('Creator activity (by token md5 or address) with signals')
  .action(async (id) => {
    const data = await api.get(`/creator-activity/${encodeURIComponent(id)}`);
    out.success(data);
  });

// ─── Explain ───────────────────────────────────────────────────
program.command('explain <hash>')
  .description('Explain a transaction in natural language')
  .action(async (hash) => {
    if (!/^[A-F0-9]{64}$/i.test(hash)) out.error('Invalid transaction hash (must be 64 hex chars)', 1);
    const data = await api.get(`/tx/explain/${hash}`);
    out.success(data);
  });

// ─── Submit ──────────────────────────────────────────────────────
program.command('submit <tx_blob>')
  .description('Submit a signed transaction blob to the XRPL')
  .option('--fail-hard', 'Fail immediately if not applied to open ledger')
  .action(async (txBlob, opts) => {
    if (!/^[A-Fa-f0-9]+$/.test(txBlob)) out.error('Invalid tx_blob (must be hex)', 1);
    const body = { tx_blob: txBlob };
    if (opts.failHard) body.fail_hard = true;
    const data = await api.post('/submit', { body });
    out.success(data);
  });

// ─── NFT ───────────────────────────────────────────────────────
const nft = program.command('nft').description('NFT data');

nft.command('info <nftId>')
  .description('Get single NFT details')
  .action(async (nftId) => {
    if (!/^[A-F0-9]{64}$/i.test(nftId)) out.error('Invalid NFT ID (must be 64 hex chars)', 1);
    const data = await api.get(`/nft/${nftId}`);
    out.success(data);
  });

nft.command('collections')
  .description('List NFT collections')
  .option('-l, --limit <n>', 'Max results', '20')
  .option('-s, --sort <field>', 'Sort by (volume, floor, sales)')
  .action(async (opts) => {
    const query = { limit: opts.limit };
    if (opts.sort) query.sort = opts.sort;
    const data = await api.get('/nft/collections', { query });
    out.success(data);
  });

nft.command('collection <slug>')
  .description('Collection details')
  .action(async (slug) => {
    const data = await api.get(`/nft/collections/${slug}`);
    out.success(data);
  });

nft.command('offers <nftId>')
  .description('NFT buy/sell offers')
  .action(async (nftId) => {
    const data = await api.get(`/nft/${nftId}/offers`);
    out.success(data);
  });

nft.command('history <nftId>')
  .description('NFT transaction history')
  .action(async (nftId) => {
    const data = await api.get(`/nft/history/${nftId}`);
    out.success(data);
  });

// ─── Launch ───────────────────────────────────────────────────
const launch = program.command('launch').description('Token launch lifecycle');

launch.command('create')
  .description('Initialize a new token launch')
  .requiredOption('--currency <code>', 'Currency code, 3-20 alphanumeric')
  .requiredOption('--supply <amount>', 'Token supply, integer >= 1000')
  .requiredOption('--amm-xrp <amount>', 'AMM liquidity in XRP, >= 1')
  .requiredOption('--name <name>', 'Token display name')
  .option('--origin <origin>', 'Platform identifier', 'xrpl.to')
  .option('--user <user>', 'Creator name (default: wallet address)')
  .option('--domain <domain>', 'Token domain', 'xrpl.to')
  .option('--description <desc>', 'Token description (max 1000 chars)')
  .option('--address <addr>', 'User address for dev allocation')
  .option('--check-amount <amt>', 'Dev allocation token amount', '0')
  .option('--anti-snipe', 'Enable anti-snipe mode')
  .option('--retention <pct>', 'Platform retention % (0-10)', '3')
  .option('--telegram <handle>', 'Telegram link')
  .option('--twitter <handle>', 'Twitter link')
  .option('--bundle <addr:pct>', 'Bundle recipient (repeatable, max 10)', (val, prev) => {
    prev = prev || [];
    prev.push(val);
    return prev;
  })
  .option('--image <path>', 'Path to token image file')
  .action(async (opts) => {
    // Validate currency code
    if (!/^[A-Za-z0-9]+$/.test(opts.currency)) {
      out.error('Currency code must contain only letters and numbers (A-Z, 0-9)', 1);
    }
    if (opts.currency.length < 3 || opts.currency.length > 20) {
      out.error('Currency code must be 3-20 characters', 1);
    }
    if (opts.currency.toUpperCase() === 'XRP') {
      out.error('XRP is reserved and cannot be used as a token code', 1);
    }

    // Validate supply
    const supply = parseInt(opts.supply);
    if (isNaN(supply) || supply < 1000) {
      out.error('Token supply must be an integer >= 1000', 1);
    }

    // Validate AMM XRP
    const ammXrp = parseFloat(opts.ammXrp);
    if (isNaN(ammXrp) || ammXrp < 1) {
      out.error('AMM XRP amount must be >= 1', 1);
    }

    // Validate name
    if (opts.name.length > 100) {
      out.error('Token name must be 100 characters or less', 1);
    }

    // Validate description
    if (opts.description && opts.description.length > 1000) {
      out.error('Description must be 1000 characters or less', 1);
    }

    // Validate address format if provided
    if (opts.address && !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(opts.address)) {
      out.error('Invalid XRPL address format', 1);
    }

    // Validate check-amount requires address
    const checkAmount = parseFloat(opts.checkAmount);
    if (checkAmount > 0 && !opts.address) {
      out.error('--address is required when --check-amount > 0', 1);
    }

    // Validate retention
    const retention = parseFloat(opts.retention);
    if (isNaN(retention) || retention < 0 || retention > 10) {
      out.error('Retention must be between 0 and 10', 1);
    }

    // Parse bundle recipients
    let bundleRecipients = [];
    if (opts.bundle) {
      for (const b of opts.bundle) {
        const [addr, pct] = b.split(':');
        if (!addr || !pct || !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(addr)) {
          out.error(`Invalid bundle format "${b}". Use addr:pct (e.g. rAddr...:5)`, 1);
        }
        const pctNum = parseFloat(pct);
        if (isNaN(pctNum) || pctNum <= 0 || pctNum > 100) {
          out.error(`Invalid bundle percent "${pct}". Must be 0-100.`, 1);
        }
        bundleRecipients.push({ address: addr, percent: pctNum });
      }
      if (bundleRecipients.length > 10) {
        out.error('Maximum 10 bundle recipients allowed', 1);
      }
    }

    // Build request body
    const body = {
      currencyCode: opts.currency,
      tokenSupply: String(supply),
      ammXrpAmount: ammXrp,
      name: opts.name,
      origin: opts.origin,
      user: opts.user || config.get('wallet') || 'cli-agent',
      domain: opts.domain,
      antiSnipe: !!opts.antiSnipe,
      userCheckAmount: String(checkAmount || 0),
      platformRetentionPercent: retention
    };
    if (opts.description) body.description = opts.description;
    if (opts.address) body.userAddress = opts.address;
    if (opts.telegram) body.telegram = opts.telegram;
    if (opts.twitter) body.twitter = opts.twitter;
    if (bundleRecipients.length > 0) body.bundleRecipients = bundleRecipients;

    // Read image file if provided
    if (opts.image) {
      const imgPath = path.resolve(opts.image);
      if (!fs.existsSync(imgPath)) {
        out.error(`Image file not found: ${imgPath}`, 1);
      }
      const imgData = fs.readFileSync(imgPath);
      const ext = path.extname(imgPath).toLowerCase().replace('.', '');
      const mime = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' }[ext] || 'image/png';
      body.imageData = `data:${mime};base64,${imgData.toString('base64')}`;
    }

    const data = await api.post('/launch-token', { body });
    out.success(data);
  });

launch.command('status <sessionId>')
  .description('Poll launch progress')
  .action(async (sessionId) => {
    const data = await api.get(`/launch-token/status/${encodeURIComponent(sessionId)}`);
    out.success(data);
  });

launch.command('cancel <sessionId>')
  .description('Cancel a pending launch and refund funds')
  .option('--refund <address>', 'Refund destination address')
  .action(async (sessionId, opts) => {
    if (opts.refund && !/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(opts.refund)) {
      out.error('Invalid refund address format', 1);
    }
    const body = {};
    if (opts.refund) body.refundAddress = opts.refund;
    const data = await api.del(`/launch-token/${encodeURIComponent(sessionId)}`, { body });
    out.success(data);
  });

launch.command('calculate')
  .description('Calculate funding requirements without creating a session')
  .requiredOption('--amm-xrp <amount>', 'AMM liquidity in XRP, >= 1')
  .option('--supply <amount>', 'Token supply', '1000000')
  .option('--check-amount <amt>', 'Dev allocation amount', '0')
  .option('--anti-snipe', 'Include anti-snipe')
  .option('--bundles <n>', 'Number of bundle recipients', '0')
  .option('--retention <pct>', 'Platform retention %', '3')
  .action(async (opts) => {
    const ammXrp = parseFloat(opts.ammXrp);
    if (isNaN(ammXrp) || ammXrp < 1) {
      out.error('AMM XRP amount must be >= 1', 1);
    }
    const query = {
      ammXrpAmount: ammXrp,
      tokenSupply: opts.supply,
      userCheckAmount: opts.checkAmount,
      antiSnipe: opts.antiSnipe ? 'true' : 'false',
      bundleCount: opts.bundles,
      platformRetentionPercent: opts.retention
    };
    const data = await api.get('/launch-token/calculate-funding', { query });
    out.success(data);
  });

launch.command('image <sessionId>')
  .description('Upload token image for an active launch session')
  .requiredOption('--file <path>', 'Path to image file')
  .action(async (sessionId, opts) => {
    const imgPath = path.resolve(opts.file);
    if (!fs.existsSync(imgPath)) {
      out.error(`Image file not found: ${imgPath}`, 1);
    }
    const imgData = fs.readFileSync(imgPath);
    const ext = path.extname(imgPath).toLowerCase().replace('.', '');
    const mime = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' }[ext] || 'image/png';
    const imageData = `data:${mime};base64,${imgData.toString('base64')}`;
    const data = await api.post(`/launch-token/${encodeURIComponent(sessionId)}/image`, { body: { imageData } });
    out.success(data);
  });

launch.command('authorize <sessionId> <address>')
  .description('Authorize address for anti-snipe launch')
  .action(async (sessionId, address) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) {
      out.error('Invalid XRPL address format', 1);
    }
    const data = await api.post('/launch-token/authorize', {
      body: { sessionId, userAddress: address }
    });
    out.success(data);
  });

launch.command('check-auth <issuer> <currency> <address>')
  .description('Check if address is authorized for a token')
  .action(async (issuer, currency, address) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(issuer)) {
      out.error('Invalid issuer address format', 1);
    }
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) {
      out.error('Invalid address format', 1);
    }
    const data = await api.get(`/launch-token/check-auth/${encodeURIComponent(issuer)}/${encodeURIComponent(currency)}/${encodeURIComponent(address)}`);
    out.success(data);
  });

launch.command('queue-status <sessionId>')
  .description('Get authorization queue status')
  .action(async (sessionId) => {
    const data = await api.get(`/launch-token/queue-status/${encodeURIComponent(sessionId)}`);
    out.success(data);
  });

launch.command('auth-info <issuer> <currency>')
  .description('Get auth info for a token')
  .action(async (issuer, currency) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(issuer)) {
      out.error('Invalid issuer address format', 1);
    }
    const data = await api.get(`/launch-token/auth-info/${encodeURIComponent(issuer)}/${encodeURIComponent(currency)}`);
    out.success(data);
  });

launch.command('claim <sessionId>')
  .description('Claim dev/bundle token allocation via CheckCash')
  .action(async (sessionId, _, cmd) => {
    const xrpl = require('xrpl');
    const kp = requireKeypair(cmd.optsWithGlobals());
    const agentAddr = kp.address;
    const agentWallet = xrpl.Wallet.fromSeed(kp.seed);

    // 1. Get launch status
    const status = await api.get(`/launch-token/status/${encodeURIComponent(sessionId)}`, { rawResponse: true });
    if (status.status === 404) {
      out.error('Session not found', 20);
    }
    if (status.status !== 200 || !status.data?.success) {
      out.error(status.data?.error || `Failed to get launch status (HTTP ${status.status})`, 40);
    }
    const launch = status.data;

    // Must be completed
    if (launch.status !== 'completed' && launch.status !== 'success') {
      out.error('Launch must be completed before claiming', 1, { currentStatus: launch.status });
    }

    // 2. Find the agent's check
    let checkId = null;
    let amount = null;

    // Check dev allocation (userCheckId)
    if (launch.userCheckId) {
      // The user_check_created step has the amount
      const userStep = launch.steps?.find(s => s.step === 'user_check_created');
      if (userStep) {
        // We can't definitively know the userAddress from the status response,
        // so we try the userCheckId and let CheckCash fail if it's not ours
        checkId = launch.userCheckId;
        amount = String(userStep.amount);
      }
    }

    // Check bundle allocations (these have address fields)
    if (launch.bundleCheckIds?.length > 0) {
      const bundleMatch = launch.bundleCheckIds.find(b => b.address === agentAddr);
      if (bundleMatch) {
        checkId = bundleMatch.checkId;
        amount = String(bundleMatch.amount);
      }
    }

    // If both exist, prefer the one that matches our address explicitly (bundle)
    // If neither matched, error
    if (!checkId) {
      out.error(`No check found for wallet ${agentAddr}`, 1,
        'Your wallet address must match the --address used in launch create or appear in --bundle recipients.');
    }

    const issuer = launch.issuer;
    const currency = launch.currencyCode;

    if (!issuer || !currency) {
      out.error('Launch status missing issuer or currencyCode', 40);
    }

    // 3. Get account sequence + balance
    const acctInfo = await api.get(`/submit/account/${agentAddr}/sequence`, { rawResponse: true });
    if (acctInfo.status === 404) {
      out.error(`Wallet not funded. Need ~3 XRP for reserves + fees.`, 1,
        `Fund ${agentAddr} with at least 3 XRP before claiming.`);
    }
    if (acctInfo.status !== 200 || !acctInfo.data?.success) {
      out.error(acctInfo.data?.error || `Failed to get account info (HTTP ${acctInfo.status})`, 40);
    }
    let seq = acctInfo.data.sequence;
    const balance = acctInfo.data.balance;

    if (balance < 3) {
      out.error(`Wallet not funded. Balance: ${balance} XRP, need ~3 XRP for reserves + fees.`, 1);
    }

    // 4. Get fee
    const feeData = await api.get('/submit/fee');
    const fee = feeData.open_ledger_fee || feeData.median_fee || '12';

    // 5. Build + sign TrustSet
    const trustSetTx = {
      TransactionType: 'TrustSet',
      Account: agentAddr,
      LimitAmount: {
        currency,
        issuer,
        value: '1000000000'
      },
      Sequence: seq,
      Fee: String(fee),
      NetworkID: undefined
    };
    delete trustSetTx.NetworkID;

    const signedTrustSet = agentWallet.sign(trustSetTx);

    // 6. Submit TrustSet
    const trustResult = await api.post('/submit', {
      body: { tx_blob: signedTrustSet.tx_blob }
    });

    if (trustResult.engine_result !== 'tesSUCCESS' && trustResult.engine_result !== 'terQUEUED' && trustResult.engine_result !== 'tefPAST_SEQ') {
      // tefPAST_SEQ means trustline already exists (already set), which is fine
      if (trustResult.engine_result !== 'tefPAST_SEQ') {
        out.error(`TrustSet failed: ${trustResult.engine_result_message || trustResult.engine_result}`, 40, {
          engine_result: trustResult.engine_result,
          hash: trustResult.hash
        });
      }
    }

    // 7. Get updated sequence for CheckCash
    const acctInfo2 = await api.get(`/submit/account/${agentAddr}/sequence`);
    const seq2 = acctInfo2.sequence;

    // 8. Build + sign CheckCash
    const checkCashTx = {
      TransactionType: 'CheckCash',
      Account: agentAddr,
      CheckID: checkId,
      Amount: {
        currency,
        issuer,
        value: amount
      },
      Sequence: seq2,
      Fee: String(fee)
    };

    const signedCheckCash = agentWallet.sign(checkCashTx);

    // 9. Submit CheckCash
    const cashResult = await api.post('/submit', {
      body: { tx_blob: signedCheckCash.tx_blob }
    });

    if (cashResult.engine_result !== 'tesSUCCESS' && cashResult.engine_result !== 'terQUEUED') {
      out.error(`CheckCash failed: ${cashResult.engine_result_message || cashResult.engine_result}`, 40, {
        engine_result: cashResult.engine_result,
        hash: cashResult.hash
      });
    }

    out.success({
      status: 'claimed',
      wallet: agentAddr,
      checkId,
      amount,
      currency: launch.originalCurrencyCode || currency,
      issuer,
      trustSetHash: signedTrustSet.hash,
      checkCashHash: signedCheckCash.hash,
      trustSetResult: trustResult.engine_result,
      checkCashResult: cashResult.engine_result
    });
  });

launch.command('debug')
  .description('List all active launches (admin)')
  .action(async () => {
    const data = await api.get('/launch-token/debug');
    out.success(data);
  });

launch.command('history')
  .description('Launch history from MongoDB (admin)')
  .action(async () => {
    const data = await api.get('/launch-token/history');
    out.success(data);
  });

launch.command('cleanup')
  .description('Clean up failed/expired sessions (admin)')
  .option('--force', 'Also clean old sessions (>1hr)')
  .action(async (opts) => {
    const body = { force: !!opts.force };
    const data = await api.post('/launch-token/cleanup', { body });
    out.success(data);
  });

// ─── AMM ───────────────────────────────────────────────────────
program.command('amm')
  .description('List AMM pools')
  .option('-l, --limit <n>', 'Max results', '20')
  .option('-s, --sort <field>', 'Sort field')
  .action(async (opts) => {
    const query = { limit: opts.limit };
    if (opts.sort) query.sort = opts.sort;
    const data = await api.get('/amm-pools', { query });
    out.success(data);
  });

// ─── Holders / Richlist ────────────────────────────────────────
program.command('holders <md5>')
  .description('Token holders / richlist')
  .option('-l, --limit <n>', 'Max results', '20')
  .action(async (md5, opts) => {
    const data = await api.get(`/holders/list/${md5}`, { query: { limit: opts.limit } });
    out.success(data);
  });

// ═══════════════════════════════════════════════════════════════
// SCHEMA (Agent self-discovery)
// ═══════════════════════════════════════════════════════════════

program.command('schema [command]')
  .description('Output parameter schema for a command (agent self-discovery)')
  .action((cmd) => {
    const schemas = {
      // Discovery
      'docs':             { args: [], opts: ['--section <tokens|charts|trading|account|nft|keys|analytics|websocket|...>'], description: 'Full API documentation — all endpoints, params, responses' },
      // Onboarding
      'keygen':           { args: [], opts: [], description: 'Generate XRPL keypair to ~/.xrpl-cli/keypair.json' },
      'signup':           { args: [], opts: ['--name <name>'], description: 'Create free account (1M credits/month) + API key. Requires keypair.' },
      'login':            { args: [], opts: [], description: 'Authenticate with existing wallet keypair' },
      'upgrade':          { args: [], opts: [], description: 'Show upgrade options and payment instructions' },
      // Data
      'token info':       { args: ['id: string (md5, slug, name, issuer_currency, mptIssuanceID)'], opts: ['--description: include description'] },
      'token review':     { args: ['id: string'], opts: [], description: 'Token safety/risk assessment' },
      'token flow':       { args: ['id: string'], opts: [], description: 'Creator token flow analysis' },
      'token list':       { args: [], opts: ['--limit <n>', '--sort <vol24hxrp|mc|trustlines|age|change24h>', '--dir <asc|desc>', '--tag <tag>', '--page <n>'] },
      'account balance':  { args: ['address: string (r...)'], opts: [] },
      'account tx':       { args: ['address: string'], opts: ['--limit <n>', '--marker <marker>'] },
      'account trustlines': { args: ['address: string'], opts: [] },
      'account info':     { args: ['address: string'], opts: [] },
      'account ancestry': { args: ['address: string'], opts: [] },
      'account token-stats': { args: ['address: string', 'md5: string'], opts: [] },
      'price ohlc':       { args: ['id: string (md5 or slug)'], opts: ['--interval <1m|5m|15m|1h|4h|1D|1W>', '--from <ms>', '--to <ms>', '--currency <USD|EUR|JPY>'] },
      'price sparkline':  { args: ['id: string'], opts: [] },
      'trade history':    { args: ['md5: string'], opts: ['--limit <n>', '--from <ms>', '--to <ms>'] },
      'trade orderbook':  { args: [], opts: ['--base <currency>', '--quote <md5> (required)'] },
      'trade quote':      { args: ['from: string', 'to: string', 'amount: number'], opts: [] },
      'traders profile':  { args: ['address: string'], opts: [] },
      'traders token':    { args: ['md5: string'], opts: [] },
      'traders portfolio': { args: ['address: string'], opts: [] },
      'creator':          { args: ['id: string (md5 or address)'], opts: [], description: 'Creator activity with risk signals' },
      'explain':          { args: ['hash: string (64-char hex tx hash)'], opts: [], description: 'Explain transaction in natural language' },
      'search':           { args: ['query: string'], opts: ['--limit <n>'] },
      'web-search':       { args: ['query: string'], opts: ['--limit <n>', '--categories <general|news|science|it>', '--engines <engine>', '--language <code>', '--page <n>'], description: 'Web search via SearXNG' },
      'submit':           { args: ['tx_blob: string (hex)'], opts: ['--fail-hard'], description: 'Submit signed transaction blob' },
      'nft info':         { args: ['nftId: string (64-char hex)'], opts: [] },
      'nft collections':  { args: [], opts: ['--limit <n>', '--sort <volume|floor|sales>'] },
      'nft collection':   { args: ['slug: string'], opts: [] },
      'nft offers':       { args: ['nftId: string'], opts: [] },
      'holders':          { args: ['md5: string'], opts: ['--limit <n>'] },
      'amm':              { args: [], opts: ['--limit <n>', '--sort <field>'] },
      // Launch
      'launch create':    { args: [], opts: ['--currency <code> (required)', '--supply <amount> (required)', '--amm-xrp <amount> (required)', '--name <name> (required)', '--origin <origin>', '--user <user>', '--domain <domain>', '--description <desc>', '--address <addr>', '--check-amount <amt>', '--anti-snipe', '--retention <pct>', '--telegram <handle>', '--twitter <handle>', '--bundle <addr:pct> (repeatable)', '--image <path>'], description: 'Initialize a new token launch' },
      'launch status':    { args: ['sessionId: string'], opts: [], description: 'Poll launch progress' },
      'launch cancel':    { args: ['sessionId: string'], opts: ['--refund <address>'], description: 'Cancel & refund a pending launch' },
      'launch calculate': { args: [], opts: ['--amm-xrp <amount> (required)', '--supply <amount>', '--check-amount <amt>', '--anti-snipe', '--bundles <n>', '--retention <pct>'], description: 'Calculate funding requirements' },
      'launch image':     { args: ['sessionId: string'], opts: ['--file <path> (required)'], description: 'Upload token image' },
      'launch authorize': { args: ['sessionId: string', 'address: string'], opts: [], description: 'Authorize address for anti-snipe launch' },
      'launch check-auth': { args: ['issuer: string', 'currency: string', 'address: string'], opts: [], description: 'Check if address is authorized' },
      'launch queue-status': { args: ['sessionId: string'], opts: [], description: 'Authorization queue info' },
      'launch auth-info': { args: ['issuer: string', 'currency: string'], opts: [], description: 'Token auth info' },
      'launch claim':     { args: ['sessionId: string'], opts: [], description: 'Claim dev/bundle token allocation via CheckCash' },
      'launch debug':     { args: [], opts: [], description: 'List active launches (admin)' },
      'launch history':   { args: [], opts: [], description: 'Launch history (admin)' },
      'launch cleanup':   { args: [], opts: ['--force'], description: 'Clean failed sessions (admin)' },
      // Keys
      'keys list':        { args: ['wallet?: string (uses config if omitted)'], opts: [] },
      'keys create':      { args: [], opts: ['--name <name>'], description: 'Create new API key (requires keypair)' },
      'keys revoke':      { args: ['keyId: string'], opts: [], description: 'Revoke an API key' },
      'keys usage':       { args: ['wallet?: string'], opts: [] },
      'keys credits':     { args: ['wallet?: string'], opts: [] },
      'keys subscription': { args: ['wallet?: string'], opts: [] },
      'keys tiers':       { args: [], opts: [], description: 'Available pricing tiers with XRP prices' },
      'keys packages':    { args: [], opts: [], description: 'Credit packages for purchase' },
      'keys costs':       { args: [], opts: [], description: 'Endpoint credit costs' },
      'keys purchase':    { args: [], opts: ['--tier <developer|business|professional>', '--package <starter|standard|bulk|mega>', '--billing <monthly|yearly>'] },
      'keys verify-payment': { args: ['txHash: string'], opts: [] },
      'health':           { args: [], opts: [] }
    };

    if (cmd && schemas[cmd]) {
      out.success({ command: cmd, ...schemas[cmd] });
    } else {
      // Group by category for agent discovery
      const grouped = {};
      for (const [name, schema] of Object.entries(schemas)) {
        const cat = name.includes(' ') ? name.split(' ')[0] : name;
        if (!grouped[cat]) grouped[cat] = [];
        grouped[cat].push({ command: name, description: schema.description || null });
      }
      out.success({
        commands: Object.keys(schemas),
        grouped,
        usage: 'xrpl schema "token info" --json',
        agent_workflow: [
          '1. xrpl keygen --json',
          '2. xrpl signup --json',
          '3. xrpl token list --json',
          '4. xrpl keys credits --json',
          '5. xrpl upgrade --json (when ready to upgrade)'
        ]
      });
    }
  });

program.parse();
