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
