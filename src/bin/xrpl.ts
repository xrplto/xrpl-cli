import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import * as config from '../lib/config';
import * as api from '../lib/api';
import * as out from '../lib/output';
import * as wallet from '../lib/wallet';
import type { Keypair } from '../lib/types';
import { validateBaseUrl, isPrivateOrBlockedHost } from '../lib/types';
import dns from 'dns';
import * as x402 from '../lib/x402';

const program = new Command();

program
  .name('xrpl')
  .version('1.0.0')
  .description('Official CLI for xrpl.to — XRPL token analytics & market data')
  .option('--json', 'Output as JSON (for LLM agents)')
  .hook('preAction', (thisCommand) => {
    if (thisCommand.optsWithGlobals().json) out.setJsonMode(true);
  });

// ─── Helpers ──────────────────────────────────────────────────
function requireKeypair(opts?: { keypair?: string }): Keypair {
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

// ─── SSRF-safe fetch for external URLs ────────────────────────
async function safeFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const check = validateBaseUrl(url);
  if ('error' in check) out.error(`Invalid URL: ${check.error}`, 1);

  const parsed = new URL(url);
  const hostname = parsed.hostname;
  if (hostname !== 'localhost' && hostname !== '127.0.0.1' && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    try {
      const resolved = await new Promise<string[]>((resolve, reject) => {
        dns.resolve4(hostname, (err, addrs) => err ? reject(err) : resolve(addrs));
      });
      for (const ip of resolved) {
        if (isPrivateOrBlockedHost(ip)) {
          out.error(`Refusing connection: ${hostname} resolves to private IP ${ip}`, 40);
        }
      }
    } catch {}
  }

  const headers: Record<string, string> = {
    'User-Agent': 'xrpl-cli/1.0.0',
    ...(init.headers as Record<string, string> || {})
  };
  try {
    return await fetch(url, {
      ...init,
      headers,
      signal: init.signal || AbortSignal.timeout(30000)
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === 'TimeoutError') out.error('Request timed out (30s)', 40);
    out.error('Network error: could not connect', 40);
  }
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
        `Address: ${existing?.address ?? 'unknown'}. Delete the file to regenerate.`
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

// ─── Wallet ─────────────────────────────────────────────────
program.command('wallet')
  .description('Show wallet address and public key (use --seed to include secret seed)')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .option('--seed', 'Include secret seed in output (CAUTION: exposes private key)')
  .action((opts: { keypair?: string; seed?: boolean }) => {
    const kp = wallet.load(opts?.keypair);
    if (!kp) {
      out.error('No keypair found. Run `xrpl keygen` first.', 11);
    }
    const result: Record<string, unknown> = {
      address: kp.address,
      publicKey: kp.publicKey,
      path: wallet.DEFAULT_KEYPAIR_PATH
    };
    if (opts.seed) {
      result.seed = kp.seed;
    } else {
      result.seed_hint = 'Hidden. Use `xrpl wallet --seed` to reveal.';
    }
    out.success(result);
  });

// ─── Signup ──────────────────────────────────────────────────
program.command('signup')
  .description('Create free account + API key (requires keypair)')
  .option('-n, --name <name>', 'API key name', 'CLI Agent Key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts: { name: string; keypair?: string }) => {
    const kp = requireKeypair(opts);

    const authHeaders = wallet.getAuthHeaders(kp);
    const existing = await api.get<{ count?: number }>(`/keys/${kp.address}`, { rawResponse: true, authHeaders });
    if (existing.status === 200 && existing.data?.count && existing.data.count > 0) {
      out.error(
        `Wallet ${kp.address} already has ${existing.data.count} API key(s).`,
        1,
        'Run `xrpl login` to authenticate, or `xrpl keys` to see existing keys.'
      );
    }
    const result = await api.post<{ success?: boolean; error?: string; apiKey?: string; tier?: string; credits?: number }>('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (!result.success) {
      out.error(result.error || 'Signup failed', 40);
    }

    config.set('apiKey', result.apiKey!);
    config.set('wallet', kp.address);

    out.success({
      status: 'account_created',
      wallet: kp.address,
      apiKey: result.apiKey ? result.apiKey.substring(0, 12) + '***' : null,
      tier: result.tier || 'free',
      credits: result.credits,
      next_steps: [
        'Your full API key has been saved to ~/.xrpl-cli/config.json',
        'Test it: xrpl health',
        'Check usage: xrpl usage',
        'See endpoints: xrpl docs'
      ]
    });
  });

// ─── Login ───────────────────────────────────────────────────
program.command('login')
  .description('Authenticate with existing wallet keypair')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts: { keypair?: string }) => {
    const kp = requireKeypair(opts);

    const authHeaders = wallet.getAuthHeaders(kp);
    const info = await api.get<{ count?: number; tier?: string; credits?: number }>(`/keys/${kp.address}`, { rawResponse: true, authHeaders });
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
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts: { keypair?: string }) => {
    const kp = requireKeypair(opts);
    const authHeaders = wallet.getAuthHeaders(kp);
    const data = await api.get(`/keys/${kp.address}`, { authHeaders });
    out.success(data);
  });

keys.command('create')
  .description('Create a new API key (WARNING: replaces current API key in config)')
  .option('-n, --name <name>', 'Key name', 'CLI Key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .option('--no-save', 'Do not save the new key to config (keep existing key)')
  .action(async (opts: { name: string; keypair?: string; save: boolean }) => {
    const kp = requireKeypair(opts);
    const existingKey = config.get('apiKey');
    const authHeaders = wallet.getAuthHeaders(kp);
    const result = await api.post<{ apiKey?: string; config_saved?: boolean }>('/keys', {
      body: { name: opts.name },
      authHeaders
    });

    if (result.apiKey && opts.save) {
      if (existingKey) {
        (result as Record<string, unknown>).previous_key_overwritten = true;
        (result as Record<string, unknown>).previous_key_prefix = existingKey.substring(0, 8) + '***';
      }
      config.set('apiKey', result.apiKey);
      (result as Record<string, unknown>).config_saved = true;
    } else if (result.apiKey && !opts.save) {
      (result as Record<string, unknown>).config_saved = false;
      (result as Record<string, unknown>).note = 'Key NOT saved to config (--no-save). Save it manually: xrpl config set-key <key>';
    }

    out.success(result);
  });

keys.command('revoke <keyId>')
  .description('Revoke an API key')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (keyId: string, opts: { keypair?: string }) => {
    if (!/^[a-f0-9]{24}$/.test(keyId)) {
      out.error('Invalid key ID format (expected 24-char hex).', 1);
    }
    const kp = requireKeypair(opts);
    const authHeaders = wallet.getAuthHeaders(kp);
    const data = await api.del(`/keys/${kp.address}/${keyId}`, { authHeaders });
    out.success(data);
  });

// ─── Usage ───────────────────────────────────────────────────
program.command('usage')
  .description('Show credits usage and billing info')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts: { keypair?: string }) => {
    const kp = requireKeypair(opts);
    const authHeaders = wallet.getAuthHeaders(kp);
    const [usage, credits] = await Promise.all([
      api.get(`/keys/${kp.address}/usage`, { authHeaders }),
      api.get(`/keys/${kp.address}/credits`, { authHeaders })
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
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (opts: { keypair?: string }) => {
    const kp = wallet.load(opts?.keypair);

    const [tiers, subscription] = await Promise.all([
      api.get<{ tiers?: Array<{ name: string }>; paymentAddress?: string; xrpRate?: number }>('/keys/tiers', { authenticated: false }),
      kp ? api.get<{ subscription?: { tier?: string; credits?: number } }>(`/keys/${kp.address}/subscription`, { rawResponse: true, authHeaders: wallet.getAuthHeaders(kp) }).then(r => r.data) : null
    ]);

    const currentTier = subscription?.subscription?.tier || 'free';

    out.success({
      wallet: kp?.address ?? null,
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

// ─── Launch Token ───────────────────────────────────────────
const launch = program.command('launch').description('Token launch on XRPL mainnet');

launch.command('create')
  .description('Launch a new token (mode 1: simplest)')
  .requiredOption('-c, --currency <code>', 'Token currency code (3-20 chars)')
  .requiredOption('-n, --name <name>', 'Token display name')
  .option('-s, --supply <amount>', 'Token supply', '1000000')
  .option('-x, --xrp <amount>', 'XRP liquidity for AMM pool', '100')
  .option('-u, --user <name>', 'Creator/team name', 'CLI Agent')
  .option('--dev-address <address>', 'Wallet for dev allocation')
  .option('--dev-amount <amount>', 'Token amount for dev allocation', '0')
  .option('--anti-snipe', 'Enable anti-snipe mode')
  .option('--bundle <recipients>', 'Bundle recipients (address:percent,...) e.g. rAddr1:5,rAddr2:3')
  .option('-i, --image <path>', 'Token image file (png/jpg/gif/webp, max 500KB)')
  .option('-d, --description <text>', 'Token description')
  .option('--telegram <url>', 'Telegram link')
  .option('--twitter <url>', 'Twitter link')
  .action(async (opts: {
    currency: string; name: string; supply: string; xrp: string;
    user: string; devAddress?: string; devAmount: string; antiSnipe?: boolean;
    bundle?: string; image?: string; description?: string; telegram?: string; twitter?: string;
  }) => {
    const supplyNum = Number(opts.supply);
    if (!Number.isFinite(supplyNum) || supplyNum !== Math.floor(supplyNum) || supplyNum <= 0) {
      out.error('Token supply must be a positive whole number.', 1);
    }
    const ammXrp = parseFloat(opts.xrp);
    if (!Number.isFinite(ammXrp) || ammXrp <= 0) {
      out.error('XRP liquidity must be a positive number.', 1);
    }
    const body: Record<string, unknown> = {
      currencyCode: opts.currency,
      name: opts.name,
      tokenSupply: supplyNum,
      ammXrpAmount: ammXrp,
      origin: 'xrpl-cli',
      user: opts.user
    };
    if (opts.devAddress) body.userAddress = opts.devAddress;
    if (opts.devAmount !== '0') {
      const devAmt = Number(opts.devAmount);
      if (!Number.isFinite(devAmt) || devAmt <= 0) {
        out.error('Dev amount must be a positive number.', 1);
      }
      body.userCheckAmount = opts.devAmount;
    }
    if (opts.antiSnipe) body.antiSnipe = true;
    if (opts.bundle) {
      body.bundleRecipients = opts.bundle.split(',').map(entry => {
        const [address, pct] = entry.trim().split(':');
        if (!address || !pct) out.error('Bundle format: address:percent,address:percent,...', 1);
        const percent = parseFloat(pct);
        if (!Number.isFinite(percent) || percent <= 0 || percent > 100) {
          out.error(`Invalid bundle percent "${pct}" for ${address}. Must be between 0 and 100.`, 1);
        }
        return { address, percent };
      });
    }
    if (opts.description) body.description = opts.description;
    if (opts.telegram) body.telegram = opts.telegram;
    if (opts.twitter) body.twitter = opts.twitter;
    if (opts.image) {
      const imgPath = path.resolve(opts.image);
      if (!fs.existsSync(imgPath)) out.error(`Image file not found: ${imgPath}`, 1);
      const stat = fs.statSync(imgPath);
      if (stat.size > 512000) out.error('Image too large (max 500KB)', 1);
      const ext = path.extname(imgPath).toLowerCase().replace('.', '');
      const mimeMap: Record<string, string> = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp' };
      const mime = mimeMap[ext];
      if (!mime) out.error(`Unsupported image format: ${ext}. Use png, jpg, gif, or webp.`, 1);
      const data = fs.readFileSync(imgPath);
      body.imageData = `data:${mime};base64,${data.toString('base64')}`;
    }

    const data = await api.post<{
      success?: boolean; error?: string; sessionId?: string;
      issuerAddress?: string; requiredFunding?: number; statusUrl?: string;
    }>('/launch-token', { body });

    if (!data.success) out.error(data.error || 'Launch failed', 40);
    out.success(data);
  });

launch.command('status <sessionId>')
  .description('Check token launch status (polls until complete)')
  .option('--poll', 'Poll until completion')
  .action(async (sessionId: string, opts: { poll?: boolean }) => {
    if (!/^[a-f0-9]{32}$/.test(sessionId)) {
      out.error('Invalid session ID format (expected 32-char hex).', 1);
    }

    type StatusResponse = {
      success?: boolean; status?: string; progress?: number;
      progressMessage?: string; error?: string | null;
      currentStep?: { step: string; message: string };
      [key: string]: unknown;
    };

    const check = async (): Promise<StatusResponse> => {
      return api.get<StatusResponse>(`/launch-token/status/${encodeURIComponent(sessionId)}`);
    };

    if (!opts.poll) {
      const data = await check();
      out.success(data);
      return; // success() exits
    }

    // Polling mode — keep checking until terminal state
    out.setExitOnOutput(false);
    let lastProgress = -1;
    const terminal = new Set(['success', 'completed', 'failed', 'cancelled', 'funding_timeout', 'error']);

    for (let i = 0; i < 200; i++) { // max ~10 min at 3s intervals
      const data = await check();
      const progress = data.progress ?? 0;
      const status = data.status ?? 'unknown';

      if (progress !== lastProgress) {
        out.status(`[${progress}%] ${data.progressMessage || status}`);
        lastProgress = progress;
      }

      if (terminal.has(status)) {
        out.setExitOnOutput(true);
        out.success(data);
        return;
      }

      await new Promise(r => setTimeout(r, 3000));
    }

    out.setExitOnOutput(true);
    out.error('Polling timed out after 10 minutes', 40);
  });

launch.command('claim <sessionId>')
  .description('Claim allocated tokens (dev check or bundle check) from a completed launch')
  .option('--all', 'Claim all unclaimed checks for your wallet at once')
  .option('--check-id <id>', 'Specific check ID to claim (if multiple checks match)')
  .option('--seed <seed>', 'Wallet seed for signing (overrides keypair.json)')
  .action(async (sessionId: string, opts: { all?: boolean; checkId?: string; seed?: string }) => {
    if (!/^[a-f0-9]{32}$/.test(sessionId)) {
      out.error('Invalid session ID format (expected 32-char hex).', 1);
    }
    if (opts.checkId && !/^[A-Fa-f0-9]{64}$/.test(opts.checkId)) {
      out.error('Invalid check ID format (expected 64-char hex).', 1);
    }

    // 1. Load wallet
    const xrpl = require('xrpl');
    let signingWallet: InstanceType<typeof xrpl.Wallet>;

    if (opts.seed) {
      const algorithm = opts.seed.startsWith('sEd') ? 'ed25519' : 'secp256k1';
      signingWallet = xrpl.Wallet.fromSeed(opts.seed, { algorithm });
    } else {
      const kp = wallet.load();
      if (!kp?.seed) {
        out.error('No keypair found. Run `xrpl keygen` or use --seed.', 11);
      }
      const algorithm = kp.seed.startsWith('sEd') ? 'ed25519' : 'secp256k1';
      signingWallet = xrpl.Wallet.fromSeed(kp.seed, { algorithm });
    }

    const walletAddress = signingWallet.address;

    // 2. Fetch launch status
    type BundleCheck = { address: string; checkId: string; amount: string | number; percent: number; claimed: boolean };
    type StatusResponse = {
      success?: boolean; error?: string; status?: string;
      currencyCode?: string; originalCurrencyCode?: string; issuer?: string;
      network?: string; tokenSupply?: number;
      userCheckId?: string; userCheckClaimed?: boolean;
      bundleCheckIds?: BundleCheck[];
      antiSnipe?: boolean;
      authWindow?: { open?: boolean; remainingMs?: number } | null;
    };

    const status = await api.get<StatusResponse>(`/launch-token/status/${encodeURIComponent(sessionId)}`);
    if (!status.success) out.error(status.error || 'Failed to fetch launch status', 40);

    if (status.status !== 'success' && status.status !== 'completed') {
      out.error(`Launch is not complete (status: ${status.status}). Wait until launch succeeds before claiming.`, 1);
    }

    // 3. Identify which check(s) to claim
    const checks: Array<{ type: string; checkId: string; amount: string; address: string }> = [];

    // Dev check
    if (status.userCheckId && !status.userCheckClaimed) {
      checks.push({
        type: 'dev',
        checkId: status.userCheckId,
        amount: '', // resolved on-chain below
        address: '' // dev check destination isn't in status — match by --check-id or sole match
      });
    }

    // Bundle checks
    for (const b of (status.bundleCheckIds || [])) {
      if (b.checkId && !b.claimed) {
        checks.push({
          type: 'bundle',
          checkId: b.checkId,
          amount: String(b.amount),
          address: b.address
        });
      }
    }

    if (checks.length === 0) {
      out.error('No unclaimed checks found for this launch.', 1,
        'All checks may already be claimed. Run `xrpl launch status <sessionId>` to verify.');
    }

    // 4. Build list of targets to claim
    let targets: typeof checks;

    if (opts.all) {
      // --all: claim every unclaimed check that belongs to this wallet (+ dev if present)
      const walletChecks = checks.filter(c => c.address === walletAddress);
      const devCheck = checks.find(c => c.type === 'dev');
      // Include dev check if it exists and wasn't already matched by address
      if (devCheck && !walletChecks.some(c => c.checkId === devCheck.checkId)) {
        walletChecks.unshift(devCheck);
      }
      if (walletChecks.length === 0) {
        out.error(`No unclaimed checks found for wallet ${walletAddress}.`, 1, {
          wallet: walletAddress,
          available_checks: checks.map(c => ({ type: c.type, checkId: c.checkId, address: c.address || 'dev' }))
        });
      }
      targets = walletChecks;
    } else if (opts.checkId) {
      const target = checks.find(c => c.checkId === opts.checkId);
      if (!target) {
        out.error(`Check ID ${opts.checkId} not found or already claimed.`, 1, {
          available_checks: checks.map(c => ({ type: c.type, checkId: c.checkId, address: c.address || 'dev' }))
        });
      }
      targets = [target!];
    } else {
      // Auto-match: find checks that belong to this wallet address
      const matched = checks.filter(c => c.address === walletAddress);

      if (matched.length === 1) {
        targets = [matched[0]];
      } else if (matched.length > 1) {
        out.error('Multiple checks match your wallet. Use --all to claim all, or --check-id to specify one.', 1, {
          matching_checks: matched.map(c => ({ type: c.type, checkId: c.checkId, amount: c.amount }))
        });
      } else {
        // No bundle match — if there's a dev check and it's the only unclaimed check, use it
        if (checks.length === 1 && checks[0].type === 'dev') {
          targets = [checks[0]];
        } else {
          out.error(`No checks found for wallet ${walletAddress}. Use --check-id to specify.`, 1, {
            wallet: walletAddress,
            available_checks: checks.map(c => ({ type: c.type, checkId: c.checkId, address: c.address || 'dev' }))
          });
        }
      }
    }

    // 5. Resolve currency code and validate issuer address
    if (!status.currencyCode || !status.issuer) {
      out.error('Launch status missing currency code or issuer address.', 40);
    }
    if (!xrpl.isValidClassicAddress(status.issuer)) {
      out.error(`Invalid issuer address from API: ${status.issuer}`, 40);
    }
    const currencyCode = status.currencyCode;
    const issuerAddr = status.issuer;

    // 6. Connect to XRPL
    const wsUrl = status.network === 'mainnet'
      ? 'wss://xrplcluster.com'
      : 'wss://s.altnet.rippletest.net:51233';

    out.setExitOnOutput(false);
    out.status(`Connecting to XRPL (${status.network || 'testnet'})...`);

    const client = new xrpl.Client(wsUrl);
    try {
      await client.connect();
    } catch (err: unknown) {
      out.setExitOnOutput(true);
      out.error(`Failed to connect to XRPL: ${err instanceof Error ? err.message : String(err)}`, 40);
    }

    // 7. Set trustline once (shared across all claims)
    let trustlineSet = false;

    // 8. Claim each target
    const results: Array<{ claimed: boolean; type: string; checkId: string; amount: string; txHash?: string; error?: string }> = [];

    for (let i = 0; i < targets!.length; i++) {
      const target = targets![i];
      const label = targets!.length > 1 ? `[${i + 1}/${targets!.length}] ` : '';

      // Resolve amount on-chain if missing (dev checks)
      let claimAmount = target.amount;
      if (!claimAmount) {
        try {
          out.status(`${label}Looking up check amount on-chain...`);
          const ledgerEntry = await client.request({
            command: 'ledger_entry',
            check: target.checkId
          });
          const sendMax = ledgerEntry.result?.node?.SendMax;
          if (sendMax && typeof sendMax === 'object') {
            claimAmount = sendMax.value;
          } else {
            results.push({ claimed: false, type: target.type, checkId: target.checkId, amount: '0', error: 'Could not determine check amount' });
            continue;
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          results.push({ claimed: false, type: target.type, checkId: target.checkId, amount: '0', error: msg.includes('entryNotFound') ? 'Check not found (already claimed?)' : msg });
          continue;
        }
      }

      out.status(`${label}Claiming ${Number(claimAmount).toLocaleString()} tokens (${target.type} check)...`);

      // TrustSet (only once per claim session)
      if (!trustlineSet) {
        try {
          out.status(`${label}Setting trustline...`);
          const trustSetTx = {
            TransactionType: 'TrustSet',
            Account: walletAddress,
            LimitAmount: {
              currency: currencyCode,
              issuer: issuerAddr,
              value: claimAmount
            }
          };
          const trustResult = await client.submitAndWait(trustSetTx, {
            autofill: true,
            wallet: signingWallet
          });
          const trustTxResult = trustResult.result?.meta?.TransactionResult;
          if (trustTxResult !== 'tesSUCCESS') {
            try { await client.disconnect(); } catch {}
            out.setExitOnOutput(true);
            out.error(`TrustSet failed: ${trustTxResult}`, 40);
          }
          trustlineSet = true;
        } catch (err: unknown) {
          try { await client.disconnect(); } catch {}
          out.setExitOnOutput(true);
          out.error(`TrustSet error: ${err instanceof Error ? err.message : String(err)}`, 40);
        }
      }

      // CheckCash
      try {
        out.status(`${label}Cashing check...`);
        const checkCashTx = {
          TransactionType: 'CheckCash',
          Account: walletAddress,
          CheckID: target.checkId,
          Amount: {
            currency: currencyCode,
            issuer: issuerAddr,
            value: claimAmount
          }
        };
        const cashResult = await client.submitAndWait(checkCashTx, {
          autofill: true,
          wallet: signingWallet
        });

        const cashTxResult = cashResult.result?.meta?.TransactionResult;
        if (cashTxResult === 'tesSUCCESS') {
          results.push({ claimed: true, type: target.type, checkId: target.checkId, amount: claimAmount, txHash: cashResult.result?.hash });
        } else {
          results.push({ claimed: false, type: target.type, checkId: target.checkId, amount: claimAmount, error: `CheckCash failed: ${cashTxResult}` });
        }
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        results.push({ claimed: false, type: target.type, checkId: target.checkId, amount: claimAmount, error: msg.includes('tecNO_ENTRY') ? 'Check already claimed or does not exist' : msg });
      }
    }

    try { await client.disconnect(); } catch {}
    out.setExitOnOutput(true);

    // 9. Output results
    if (results.length === 1) {
      const r = results[0];
      if (r.claimed) {
        out.success({
          claimed: true,
          type: r.type,
          checkId: r.checkId,
          amount: r.amount,
          currency: status.originalCurrencyCode || currencyCode,
          issuer: issuerAddr,
          wallet: walletAddress,
          txHash: r.txHash
        });
      } else {
        out.error(r.error || 'Claim failed', 1);
      }
    } else {
      const allClaimed = results.every(r => r.claimed);
      const summary = {
        allClaimed,
        currency: status.originalCurrencyCode || currencyCode,
        issuer: issuerAddr,
        wallet: walletAddress,
        results: results.map(r => ({
          claimed: r.claimed,
          type: r.type,
          checkId: r.checkId,
          amount: r.amount,
          ...(r.txHash ? { txHash: r.txHash } : {}),
          ...(r.error ? { error: r.error } : {})
        }))
      };
      if (allClaimed) {
        out.success(summary);
      } else {
        // Partial failure — output as JSON and exit with error
        if (out.isJson()) {
          console.log(JSON.stringify(summary, null, 2));
        } else {
          console.log(summary);
        }
        process.exit(1);
      }
    }
  });

launch.command('my-launches')
  .description('Show your token launch history')
  .action(async () => {
    const data = await api.get<{ count?: number; launches?: unknown[]; error?: string }>('/launch-token/my-launches');
    if (data.error) out.error(data.error, 40);
    out.success(data);
  });

// ─── Submit / Transaction ───────────────────────────────────
const tx = program.command('tx').description('Submit and inspect transactions on XRPL mainnet');

tx.command('submit')
  .description('Submit a signed transaction to the XRPL')
  .requiredOption('-b, --blob <hex>', 'Signed transaction blob (hex)')
  .option('--fail-hard', 'Fail immediately if not applied to open ledger')
  .action(async (opts: { blob: string; failHard?: boolean }) => {
    if (!/^[A-Fa-f0-9]+$/.test(opts.blob)) out.error('tx_blob must be a valid hex string.', 1);
    if (opts.blob.length > 262144) out.error('tx_blob exceeds max size (128 KB).', 1);
    const data = await api.post('/submit', {
      body: { tx_blob: opts.blob, fail_hard: opts.failHard || false }
    });
    out.success(data);
  });

tx.command('simulate')
  .description('Dry-run a transaction without submitting (preview result)')
  .option('-b, --blob <hex>', 'Signed transaction blob (hex)')
  .option('-j, --tx-json <json>', 'Transaction JSON object')
  .action(async (opts: { blob?: string; txJson?: string }) => {
    if (!opts.blob && !opts.txJson) out.error('Provide --blob or --tx-json.', 1);
    const body: Record<string, unknown> = {};
    if (opts.blob) {
      if (!/^[A-Fa-f0-9]+$/.test(opts.blob)) out.error('tx_blob must be a valid hex string.', 1);
      body.tx_blob = opts.blob;
    } else {
      try { body.tx_json = JSON.parse(opts.txJson!); } catch { out.error('Invalid JSON in --tx-json.', 1); }
    }
    const data = await api.post('/submit/simulate', { body });
    out.success(data);
  });

tx.command('fee')
  .description('Get current network transaction fee')
  .action(async () => {
    const data = await api.get('/submit/fee', { authenticated: false });
    out.success(data);
  });

tx.command('sequence <address>')
  .description('Get account sequence number and balance')
  .action(async (address: string) => {
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(address)) out.error('Invalid XRPL address.', 1);
    const data = await api.get(`/submit/account/${encodeURIComponent(address)}/sequence`, { authenticated: false });
    out.success(data);
  });

tx.command('types')
  .description('List valid XRPL transaction types')
  .action(async () => {
    const data = await api.get('/submit/types', { authenticated: false });
    out.success(data);
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
          'POST /submit                         - Submit signed transaction',
          'POST /submit/simulate                - Dry-run transaction preview',
          'GET /submit/fee                      - Current network fee',
          'GET /submit/account/{addr}/sequence  - Account sequence + balance',
          'GET /submit/types                    - Valid transaction types'
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
        ],
        launch: [
          'POST /launch-token                   - Create token launch session',
          'GET /launch-token/status/{sessionId} - Poll launch progress',
          'POST /launch-token/authorize         - Authorize trustline (anti-snipe)',
          'GET /launch-token/calculate-funding  - Estimate launch cost',
          'GET /launch-token/my-launches        - Your launch history (API key auth)'
        ]
      },
      antiSnipeBuyFlow: {
        description: 'When buying tokens during anti-snipe auth window, steps MUST be in this exact order. Wrong order = tecPATH_DRY.',
        step1_trustline: 'Create TrustSet to issuer for the token currency (XRPL on-chain)',
        step2_authorize: 'POST /launch-token/authorize { sessionId, userAddress } — retry if "Authorization not ready"',
        step3_buy: 'Payment (self-payment) with Amount=token, SendMax=XRP to swap via AMM',
        devCheckCash: 'Dev wallet: create TrustSet to issuer, then CheckCash with checkId from status step "user_check_created"',
        note: 'Dev address MUST be funded on-ledger before launch or CheckCreate fails with tecNO_DST'
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

// ─── x402 Protocol ──────────────────────────────────────────
const x402Cmd = program.command('x402').description('x402 payment protocol — pay for HTTP resources with XRP');

x402Cmd.command('discover <url>')
  .description('Probe a URL for x402 payment requirements (no payment made)')
  .option('-m, --method <method>', 'HTTP method', 'GET')
  .action(async (url: string, opts: { method: string }) => {
    const res = await safeFetch(url, { method: opts.method.toUpperCase() });

    if (res.status !== 402) {
      out.success({
        x402: false,
        status: res.status,
        message: 'No x402 payment required for this resource'
      });
      return;
    }

    const payReq = x402.parsePaymentRequired(res.headers);
    if (!payReq) {
      out.error('Server returned 402 but no valid x402 payment header found', 40);
    }

    const xrplOption = x402.findXrplRequirement(payReq);

    out.success({
      x402: true,
      version: payReq.x402Version,
      xrplSupported: !!xrplOption,
      requirements: payReq.accepts.map(a => ({
        scheme: a.scheme,
        network: a.network,
        amount: a.maxAmountRequired,
        amountFormatted: a.network.startsWith('xrpl:')
          ? `${x402.dropsToXrp(a.maxAmountRequired)} XRP`
          : a.maxAmountRequired,
        asset: a.asset || 'native',
        payTo: a.payTo,
        description: a.description || null,
        resource: a.resource
      })),
      hint: xrplOption
        ? `Pay with: xrpl x402 pay "${url}"`
        : 'No XRPL payment option. Server accepts: ' + payReq.accepts.map(a => a.network).join(', ')
    });
  });

x402Cmd.command('pay <url>')
  .description('Request a resource and auto-pay with XRP if x402 payment required')
  .option('-m, --method <method>', 'HTTP method', 'GET')
  .option('--max <xrp>', 'Maximum payment in XRP (safety limit)', '1')
  .option('-d, --data <json>', 'Request body (JSON)')
  .option('-H, --header <headers...>', 'Extra headers (Key:Value)')
  .option('-k, --keypair <path>', 'Path to keypair file')
  .action(async (url: string, opts: {
    method: string; max: string; data?: string; header?: string[]; keypair?: string;
  }) => {
    const maxDrops = Math.floor(parseFloat(opts.max) * 1_000_000);
    if (isNaN(maxDrops) || maxDrops <= 0) out.error('--max must be a positive number (XRP)', 1);

    // Build request headers
    const reqHeaders: Record<string, string> = {};
    if (opts.header) {
      for (const h of opts.header) {
        const idx = h.indexOf(':');
        if (idx === -1) out.error(`Invalid header format: "${h}". Use Key:Value`, 1);
        reqHeaders[h.substring(0, idx).trim()] = h.substring(idx + 1).trim();
      }
    }

    const fetchInit: RequestInit = { method: opts.method.toUpperCase(), headers: reqHeaders };
    if (opts.data && opts.method.toUpperCase() !== 'GET') {
      try { JSON.parse(opts.data); } catch { out.error('Invalid JSON in --data', 1); }
      reqHeaders['Content-Type'] = 'application/json';
      fetchInit.body = opts.data;
    }

    // 1. Initial request
    const res = await safeFetch(url, fetchInit);

    // 2. No payment needed
    if (res.status !== 402) {
      let body: unknown;
      try { body = await res.json(); } catch { body = await res.text(); }
      out.success({ status: res.status, paid: false, body });
      return;
    }

    // 3. Parse x402 payment requirements
    const payReq = x402.parsePaymentRequired(res.headers);
    if (!payReq) out.error('Server returned 402 but no valid x402 payment header', 40);

    // 4. Find XRPL-compatible requirement
    const requirement = x402.findXrplRequirement(payReq);
    if (!requirement) {
      out.error('No XRPL payment option available', 1, {
        availableNetworks: payReq.accepts.map(a => a.network),
        hint: 'This server does not accept XRPL payments'
      });
    }

    // 5. Validate payTo address and check spending limit
    if (!/^r[1-9A-HJ-NP-Za-km-z]{24,34}$/.test(requirement.payTo)) {
      out.error(`Invalid payment destination from server: ${requirement.payTo}`, 40);
    }
    const requiredDrops = Number(requirement.maxAmountRequired);
    if (isNaN(requiredDrops) || requiredDrops <= 0) out.error('Invalid payment amount from server', 40);
    if (requiredDrops > maxDrops) {
      out.error(
        `Payment ${x402.dropsToXrp(requirement.maxAmountRequired)} XRP exceeds limit of ${opts.max} XRP`,
        1,
        'Increase with --max <xrp>'
      );
    }

    // 6. Load wallet
    out.setExitOnOutput(false);
    out.status(`Payment required: ${x402.dropsToXrp(requirement.maxAmountRequired)} XRP to ${requirement.payTo}`);

    const kp = wallet.load(opts.keypair);
    if (!kp?.seed) {
      out.setExitOnOutput(true);
      out.error('Keypair required for x402 payment. Run `xrpl keygen` or use -k.', 11);
    }

    // 7. Connect to XRPL and sign payment
    const xrpl = require('xrpl');
    const algorithm = kp.seed.startsWith('sEd') ? 'ed25519' : 'secp256k1';
    const signingWallet = xrpl.Wallet.fromSeed(kp.seed, { algorithm });

    const wsUrl = x402.XRPL_NETWORKS[requirement.network];
    if (!wsUrl) {
      out.setExitOnOutput(true);
      out.error(`Unknown XRPL network: ${requirement.network}`, 1);
    }

    out.status(`Connecting to XRPL (${requirement.network})...`);
    const client = new xrpl.Client(wsUrl);

    try {
      await client.connect();
    } catch (err: unknown) {
      out.setExitOnOutput(true);
      out.error(`Failed to connect to XRPL: ${err instanceof Error ? err.message : String(err)}`, 40);
    }

    let txBlob: string;
    let txHash: string;

    try {
      out.status('Signing payment transaction...');
      const paymentTx: Record<string, unknown> = {
        TransactionType: 'Payment',
        Account: signingWallet.address,
        Destination: requirement.payTo,
        Amount: String(requiredDrops),
      };

      const prepared = await client.autofill(paymentTx);
      // Extend LastLedgerSequence to give server time to submit
      prepared.LastLedgerSequence = (prepared.LastLedgerSequence || 0) + 20;

      const signed = signingWallet.sign(prepared);
      txBlob = signed.tx_blob;
      txHash = signed.hash;

      await client.disconnect();
    } catch (err: unknown) {
      try { await client.disconnect(); } catch {}
      out.setExitOnOutput(true);
      out.error(`Failed to sign payment: ${err instanceof Error ? err.message : String(err)}`, 40);
    }

    // 8. Retry with payment signature
    out.status('Sending payment to server...');
    const payload: x402.XrplPaymentPayload = {
      x402Version: payReq.x402Version || 1,
      scheme: requirement.scheme,
      network: requirement.network,
      payload: { txBlob, txHash }
    };

    const paymentHeader = x402.encodePaymentSignature(payload);
    reqHeaders['Payment-Signature'] = paymentHeader;
    reqHeaders['X-PAYMENT'] = paymentHeader;

    const paidRes = await safeFetch(url, {
      ...fetchInit,
      headers: reqHeaders,
      signal: AbortSignal.timeout(60000)
    });

    out.setExitOnOutput(true);

    // 9. Parse response
    const settlement = x402.parsePaymentResponse(paidRes.headers);
    let body: unknown;
    try { body = await paidRes.json(); } catch {
      try { body = await paidRes.text(); } catch { body = null; }
    }

    if (!paidRes.ok) {
      out.error(`Payment failed (HTTP ${paidRes.status})`, 40, {
        settlement: settlement || undefined,
        body: body || undefined
      });
    }

    out.success({
      status: paidRes.status,
      paid: true,
      payment: {
        amount: x402.dropsToXrp(requirement.maxAmountRequired) + ' XRP',
        to: requirement.payTo,
        network: requirement.network,
        txHash,
        settlement: settlement || null
      },
      body
    });
  });

// ─── Config ──────────────────────────────────────────────────
const cfg = program.command('config').description('Manage CLI configuration');

cfg.command('show', { isDefault: true })
  .description('Show current configuration (use --reveal to show full API key)')
  .option('--reveal', 'Show full API key (not truncated)')
  .action((opts: { reveal?: boolean }) => {
    const c = config.load();
    out.success({
      baseUrl: c.baseUrl,
      apiKey: c.apiKey ? (opts.reveal ? c.apiKey : c.apiKey.substring(0, 8) + '***') : null,
      wallet: c.wallet,
      keypair: wallet.keypairExists() ? wallet.DEFAULT_KEYPAIR_PATH : null,
      configFile: config.CONFIG_FILE
    });
  });

cfg.command('set-key <apiKey>')
  .description('Set API key (overwrites existing key in config)')
  .action((apiKey: string) => {
    if (!apiKey.startsWith('xrpl_') || apiKey.length < 37) {
      out.error('Invalid API key format. Keys start with xrpl_ and are 37+ chars.', 1);
    }
    if (apiKey.length > 256) {
      out.error('API key too long (max 256 characters).', 1);
    }
    const existingKey = config.get('apiKey');
    config.set('apiKey', apiKey);
    const result: Record<string, unknown> = { saved: true, keyPrefix: apiKey.substring(0, 8) + '***' };
    if (existingKey) {
      result.previous_key_overwritten = true;
      result.previous_key_prefix = existingKey.substring(0, 8) + '***';
    }
    out.success(result);
  });

cfg.command('set-url <url>')
  .description('Set API base URL')
  .action((url: string) => {
    const result = validateBaseUrl(url);
    if ('error' in result) out.error(result.error, 1);
    config.set('baseUrl', url);
    out.success({ saved: true, baseUrl: url });
  });

cfg.command('reset')
  .description('Reset all configuration (WARNING: deletes API key and wallet from config)')
  .action(() => {
    const existing = config.load();
    const hadKey = !!existing.apiKey;
    const hadWallet = !!existing.wallet;
    config.save({ baseUrl: 'https://api.xrpl.to/v1', apiKey: null, wallet: null, format: 'human' });
    const result: Record<string, unknown> = { reset: true };
    if (hadKey || hadWallet) {
      result.erased = {
        apiKey: hadKey,
        wallet: hadWallet
      };
      result.recovery = 'Keypair is NOT deleted. Run `xrpl login` then `xrpl keys create` to get a new API key.';
    }
    out.success(result);
  });

program.parse();
