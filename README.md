# xrpl-cli

Official command-line interface for [xrpl.to](https://xrpl.to) — the leading XRPL token analytics and market data provider. Designed for LLM agents and automation.

## Quick Start for Agents

```bash
# 1. Generate a keypair
xrpl keygen

# 2. Create free account + API key (no funding required)
xrpl signup

# 3. Start using the API
curl -H "X-Api-Key: YOUR_KEY" https://api.xrpl.to/v1/tokens?limit=10

# 4. Check your usage
xrpl usage
```

## Installation

```bash
npm install -g xrpl-cli
```

Requires Node.js >= 18.

## Commands

| Command | Description |
|---------|-------------|
| `xrpl keygen` | Generate a new XRPL keypair |
| `xrpl wallet` | Show wallet address and public key |
| `xrpl signup` | Create free account + API key |
| `xrpl login` | Authenticate with existing wallet |
| `xrpl keys` | List API keys |
| `xrpl keys create` | Create a new API key |
| `xrpl keys revoke <keyId>` | Revoke an API key |
| `xrpl usage` | Show credits usage and billing |
| `xrpl tiers` | Show available pricing tiers |
| `xrpl upgrade` | Show upgrade options and payment info |
| `xrpl docs` | Show API endpoints |
| `xrpl health` | Check API health status |
| `xrpl config` | Show current configuration |
| `xrpl config set-key <key>` | Set API key |
| `xrpl config set-url <url>` | Set API base URL |
| `xrpl config reset` | Reset all configuration |
| `xrpl tx submit -b <hex>` | Submit signed transaction |
| `xrpl tx simulate -b <hex>` | Dry-run transaction preview |
| `xrpl tx fee` | Get current network fee |
| `xrpl tx sequence <addr>` | Get account sequence + balance |
| `xrpl tx types` | List valid transaction types |
| `xrpl launch create` | Launch a new token on mainnet |
| `xrpl launch status <id>` | Check launch status (use `--poll`) |
| `xrpl launch claim <id>` | Claim allocated tokens (dev/bundle check) |
| `xrpl launch my-launches` | Show your launch history |
| `xrpl x402 discover <url>` | Probe a URL for x402 payment requirements |
| `xrpl x402 pay <url>` | Request a resource and auto-pay with XRP |

## Keypair Management

### Generate Keypair

```bash
xrpl keygen
```

Output:
```
address: rN7n3473SaZBCG4dFL83w7p1W9cganksPc
publicKey: ED2B8...
path: /home/user/.xrpl-cli/keypair.json

next_steps:
  Run `xrpl signup` to create a free account and get an API key.
  No funding required for free tier (1M credits/month).
```

### Default Keypair Path

All commands use `~/.xrpl-cli/keypair.json` by default. Override with `-k`:

```bash
xrpl login -k /path/to/other/keypair.json
```

### Show Wallet Info

```bash
xrpl wallet          # address + public key
xrpl wallet --seed   # also reveals secret seed (CAUTION)
```

### Keypair Not Found

```
Error: Keypair not found
  Run `xrpl keygen` to generate a keypair first.
```

## Signup Flow

```bash
xrpl signup
```

1. Signs a message with your XRPL keypair
2. Creates account and API key on xrpl.to
3. Saves API key to `~/.xrpl-cli/config.json`

Free tier includes **1M credits/month** — no payment required.

## JSON Output Mode

Add `--json` flag for machine-readable output:

```bash
xrpl keys --json
xrpl usage --json
xrpl tiers --json
```

Example:
```json
{
  "status": "logged_in",
  "wallet": "rN7n3473SaZBCG4dFL83w7p1W9cganksPc",
  "tier": "free",
  "credits": 1000000,
  "apiKeys": 1
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 10 | Not logged in |
| 11 | Keypair not found |
| 20 | Not found |
| 30-39 | Rate limit / credits |
| 40 | API error |

## API Endpoints

Run `xrpl docs` to see all available API endpoints, or visit the full documentation:

```bash
curl https://api.xrpl.to/v1/tokens?limit=10
```

**Authentication:** `X-Api-Key` header or `?apiKey=` query parameter.

| Category | Example Endpoint |
|----------|-----------------|
| Tokens | `GET /tokens`, `GET /token/{id}`, `GET /search` |
| Charts | `GET /ohlc/{id}`, `GET /sparkline/{id}` |
| Trading | `GET /history`, `GET /orderbook`, `POST /submit` |
| Account | `GET /account/balance/{address}`, `GET /account/tx/{address}` |
| Traders | `GET /traders/{address}`, `GET /traders/portfolio/{address}` |
| NFTs | `GET /nft/{id}`, `GET /nft/collections` |
| Analytics | `GET /creator-activity/{id}`, `GET /tx/explain/{hash}` |

## Token Launch

### Mode 1: Simple Launch (no anti-snipe)

```bash
xrpl launch create \
  --name "MYTOKEN" \
  --currency "MYTOKEN" \
  --supply 1000000 \
  --xrp 100 \
  --description "My token" \
  --image ./logo.png \
  --json
```

Fund the issuer address returned with XRP, then poll:
```bash
xrpl launch status <sessionId> --poll --json
```

### Mode 2: Anti-Snipe Launch

Adds RequireAuth on the issuer. Only authorized wallets can trade during a 3-minute window. After the window closes, RequireAuth is removed and the token trades freely. Both issuer and holder are blackholed.

```bash
xrpl launch create \
  --name "SAFETOKEN" \
  --currency "SAFETOKEN" \
  --supply 1000000 \
  --xrp 100 \
  --anti-snipe \
  --dev-address rYourDevWallet... \
  --dev-amount 100000 \
  --json
```

### Launch Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --name` | Token display name | (required) |
| `-c, --currency` | Currency code (3-20 chars) | (required) |
| `-s, --supply` | Token supply | 1000000 |
| `-x, --xrp` | XRP liquidity for AMM pool (min 10) | 50 |
| `-u, --user` | Creator/team name | CLI Agent |
| `--anti-snipe` | Enable anti-snipe mode | false |
| `--dev-address` | Wallet for dev allocation | none |
| `--dev-amount` | Token amount for dev check | 0 |
| `--bundle` | Bundle recipients (`address:percent,...`) | none |
| `-i, --image` | Token image (png/jpg/gif/webp, max 500KB) | none |
| `-d, --description` | Token description | none |
| `--telegram` | Telegram link | none |
| `--twitter` | Twitter link | none |

### Anti-Snipe Buy Flow (CRITICAL for LLM agents)

When a token launches with `--anti-snipe`, buyers MUST follow this exact sequence during the 3-minute auth window. Getting this wrong results in `tecPATH_DRY`.

**Correct order: Trustline → Authorize → Buy**

```
Step 1: Create trustline to issuer (XRPL TrustSet)
Step 2: Request authorization via POST /api/launch-token/authorize
Step 3: Buy tokens via AMM (XRPL Payment with SendMax)
```

**Detailed flow:**

```javascript
// 1. FIRST: Create trustline to the issuer
const trustTx = {
  TransactionType: 'TrustSet',
  Account: buyerWallet.address,
  LimitAmount: {
    currency: currencyCode,    // hex-encoded currency from launch response
    issuer: issuerAddress,      // issuer address from launch response
    value: '1000000'
  }
};
await client.submitAndWait(buyerWallet.sign(await client.autofill(trustTx)).tx_blob);

// 2. THEN: Request authorization from the launch server
const authRes = await fetch('https://api.xrpl.to/v1/launch-token/authorize', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    sessionId: '<launch-session-id>',
    userAddress: buyerWallet.address
  })
});
// Retry if "Authorization not ready" (tickets still being created)

// 3. FINALLY: Buy tokens via AMM swap
const swapTx = {
  TransactionType: 'Payment',
  Account: buyerWallet.address,
  Destination: buyerWallet.address,  // self-payment for AMM swap
  Amount: {
    currency: currencyCode,
    issuer: issuerAddress,
    value: '5000'                    // tokens to receive
  },
  SendMax: xrpToDrops(10)            // max XRP to spend
};
await client.submitAndWait(buyerWallet.sign(await client.autofill(swapTx)).tx_blob);
```

**Common errors:**
- `tecPATH_DRY` — Trustline not authorized. Either skipped step 1 (no trustline), skipped step 2 (no auth), or tried to buy before auth was confirmed.
- `"No trustline found"` from `/authorize` — Must create trustline (step 1) before requesting auth (step 2).
- `"Authorization not ready"` from `/authorize` — Tickets still being created. Retry after 3 seconds.

**Unauthorized wallets are blocked** — any wallet that doesn't go through the auth flow gets `tecPATH_DRY` on swap attempts during the auth window. After the 3-minute window closes, RequireAuth is removed and anyone can trade freely.

### Dev Allocation (CheckCash)

If `--dev-address` and `--dev-amount` are specified, a CheckCreate is issued from the holder wallet to the dev address. The dev wallet must cash it:

```javascript
// Dev wallet cashes the check AFTER launch completes
// 1. Create trustline to issuer
// 2. CheckCash with the checkId from launch status
const cashTx = {
  TransactionType: 'CheckCash',
  Account: devWallet.address,
  CheckID: checkId,  // from launch status: steps[].checkId where step === 'user_check_created'
  Amount: {
    currency: currencyCode,
    issuer: issuerAddress,
    value: '100000'  // must match the dev-amount
  }
};
```

**Important:** The dev address MUST exist on the XRPL ledger (be funded) before launch. If the address doesn't exist, the CheckCreate will fail with `tecNO_DST`.

### Bundle Recipients

Allocate tokens to multiple recipients (e.g., marketing, advisors) via `--bundle`:

```bash
xrpl launch create \
  --name "MYTOKEN" \
  --currency "MYTOKEN" \
  --supply 1000000 \
  --xrp 100 \
  --bundle "rAddr1:5,rAddr2:3" \
  --json
```

Format: `address:percent,address:percent,...` — each recipient gets a CheckCreate for that percentage of total supply. Bundle recipient addresses MUST be funded on-ledger before launch.

### Claiming Tokens (CLI)

Use `xrpl launch claim` to claim dev or bundle check allocations after a launch completes:

```bash
# Claim all unclaimed checks for your wallet (dev + bundle) in one go
xrpl launch claim <sessionId> --all --json

# Auto-detect: claims the first unclaimed check matching your wallet
xrpl launch claim <sessionId> --json

# Explicit check ID (useful when multiple wallets have checks)
xrpl launch claim <sessionId> --check-id <64-char-hex> --json

# Use a specific seed instead of keypair.json
xrpl launch claim <sessionId> --seed sEdV... --json
```

The command performs two on-chain transactions per check:
1. **TrustSet** — creates a trustline to the issuer for the token (skipped if already exists)
2. **CheckCash** — redeems the check for the allocated tokens

| Option | Description |
|--------|-------------|
| `--all` | Claim all unclaimed checks for your wallet at once |
| `--check-id <id>` | Specific check ID to claim (64-char hex) |
| `--seed <seed>` | Wallet seed for signing (overrides keypair.json) |

**Error handling:**
- If the check is already claimed, you get `"Check already claimed or does not exist"`
- If the launch is not complete, you get `"Launch is not complete"`
- If no checks match your wallet, available checks are listed

**Tip:** When your wallet has both a dev check and bundle checks, use `--all` to claim everything in one command instead of looking up individual check IDs.

### Token Supply Distribution

For a 1M supply launch with 10% dev + 3% platform retention:
```
Dev allocation:       100,000 tokens (10%) — via CheckCreate
Platform retention:    30,000 tokens (3%)  — direct transfer
AMM pool:            870,000 tokens (87%) — remaining goes to AMM
```

### Fee Structure

| Component | Amount |
|-----------|--------|
| Base platform fee | 2 XRP |
| Dev allocation surcharge | 0-3 XRP (scales with %) |
| AMM liquidity | User-specified (default 50 XRP, min 10) |
| Account reserves | ~0.8 XRP |
| Transaction fees | ~1 XRP |
| Anti-snipe tickets | Funded by platform (no user cost) |

## x402 Payment Protocol

The CLI supports the [x402](https://www.x402.org/) open payment protocol, enabling pay-per-request access to HTTP resources using XRP. When a server returns HTTP 402 with x402 headers, the CLI can automatically sign and submit an XRPL payment.

### Discover Payment Requirements

Probe any URL to see if it requires x402 payment (no wallet needed):

```bash
xrpl x402 discover https://api.example.com/premium-data --json
```

Output:
```json
{
  "x402": true,
  "version": 1,
  "xrplSupported": true,
  "requirements": [
    {
      "scheme": "exact",
      "network": "xrpl:0",
      "amount": "1000000",
      "amountFormatted": "1 XRP",
      "asset": "native",
      "payTo": "rServerWallet...",
      "description": "Premium data access"
    }
  ]
}
```

### Pay for a Resource

Request a URL and auto-pay with XRP if the server requires x402 payment:

```bash
# Basic GET request (default 1 XRP safety limit)
xrpl x402 pay https://api.example.com/premium-data --json

# POST with body and higher spending limit
xrpl x402 pay https://api.example.com/query \
  -m POST \
  -d '{"query":"market data"}' \
  --max 5 \
  --json

# With custom headers
xrpl x402 pay https://api.example.com/data \
  -H "Accept:text/csv" \
  --json
```

### x402 Options

| Option | Description | Default |
|--------|-------------|---------|
| `-m, --method` | HTTP method | GET |
| `--max <xrp>` | Maximum payment in XRP (safety limit) | 1 |
| `-d, --data <json>` | Request body (JSON) | none |
| `-H, --header <Key:Value>` | Extra headers (repeatable) | none |
| `-k, --keypair <path>` | Path to keypair file | default |

### How It Works

1. CLI sends the HTTP request to the target URL
2. If server returns **HTTP 402** with a `PAYMENT-REQUIRED` header, the CLI decodes the x402 payment requirements
3. CLI finds an XRPL-compatible option (`xrpl:0` mainnet, `xrpl:1` testnet)
4. If within the `--max` spending limit, CLI connects to XRPL, signs a Payment transaction, and sends the signed blob back in a `Payment-Signature` header
5. Server submits the transaction, confirms settlement, and returns the resource

### XRPL Network Identifiers

| Network ID | Description |
|------------|-------------|
| `xrpl:0` | XRPL Mainnet |
| `xrpl:1` | XRPL Testnet |

### Safety

- **Spending limit**: The `--max` flag (default 1 XRP) prevents overspending. Payment is rejected if the server asks for more.
- **URL validation**: SSRF protections block private IPs, metadata endpoints, and DNS rebinding.
- **Wallet required**: The `pay` command requires a funded keypair. `discover` works without one.

## Configuration

Config stored in `~/.xrpl-cli/`:

```
~/.xrpl-cli/
├── config.json    # API key, base URL, wallet
└── keypair.json   # XRPL keypair (encrypted, chmod 600)
```

## Example: Full Agent Workflow

```bash
# Step 1: Check if keypair exists
xrpl login --json
# If "Keypair not found" error:

# Step 2: Generate keypair
xrpl keygen --json
# Note the wallet address

# Step 3: Create account (free, no funding needed)
xrpl signup --json
# Returns API key

# Step 4: Check your keys
xrpl keys --json

# Step 5: Use the API
curl -H "X-Api-Key: YOUR_KEY" https://api.xrpl.to/v1/tokens?limit=10

# Step 6: Check usage
xrpl usage --json
```

## License

MIT
