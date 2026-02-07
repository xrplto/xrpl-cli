# xrpl-cli

Command-line interface for XRPL token analytics, market data, and trading — built for LLM agents and automation.

Connects to the [xrpl.to](https://xrpl.to) API for real-time XRP Ledger data including tokens, NFTs, AMM pools, trader analytics, and token launches.

## Install

```bash
npm install -g xrpl-cli
```

Requires Node.js >= 18.

## Quick Start

```bash
# 1. Generate an XRPL keypair
xrpl keygen

# 2. Create a free account (1M credits/month)
xrpl signup

# 3. Start querying
xrpl token list
xrpl token info SOLO
xrpl account balance rN7n3473SaZBCG4dFL83w7p1W9cganksPc
```

## LLM Agent Mode

Pass `--json` to any command for structured JSON output. Exit codes indicate error categories:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 10-19 | Auth errors |
| 20-29 | Not found |
| 30-39 | Rate limit / credits |
| 40-49 | API / network errors |

```bash
xrpl token info SOLO --json
xrpl schema "token info" --json   # parameter schema for agent self-discovery
```

## Commands

### Onboarding

| Command | Description |
|---------|-------------|
| `xrpl keygen` | Generate XRPL keypair (`~/.xrpl-cli/keypair.json`) |
| `xrpl signup` | Create free account + API key |
| `xrpl login` | Authenticate with existing keypair |
| `xrpl upgrade` | Show tier upgrades and payment instructions |

### Token Data

| Command | Description |
|---------|-------------|
| `xrpl token list` | List tokens (sort by volume, market cap, trustlines, age) |
| `xrpl token info <id>` | Token details by md5, slug, name, or issuer_currency |
| `xrpl token review <id>` | Safety review and risk assessment |
| `xrpl token flow <id>` | Creator token flow analysis |
| `xrpl search <query>` | Search tokens, NFTs, collections, accounts |

### Account

| Command | Description |
|---------|-------------|
| `xrpl account balance <address>` | XRP balance with reserves and ranking |
| `xrpl account tx <address>` | Transaction history |
| `xrpl account trustlines <address>` | Trust lines |
| `xrpl account info <address>` | Account info (live from node + DB) |
| `xrpl account offers <address>` | Trading offers |
| `xrpl account objects <address>` | Escrows, checks, etc. |
| `xrpl account ancestry <address>` | Account genealogy |
| `xrpl account nfts <address>` | Account NFTs |
| `xrpl account token-stats <address> <md5>` | Per-token trading stats |

### Market Data

| Command | Description |
|---------|-------------|
| `xrpl price ohlc <id>` | OHLC candlestick data (1m, 5m, 15m, 1h, 4h, 1D, 1W) |
| `xrpl price sparkline <id>` | Lightweight price sparkline |

### Trading

| Command | Description |
|---------|-------------|
| `xrpl trade history <md5>` | Trade history for a token |
| `xrpl trade orderbook --quote <md5>` | DEX orderbook |
| `xrpl trade quote <from> <to> <amount>` | DEX swap quote |
| `xrpl submit <tx_blob>` | Submit signed transaction to XRPL |

### Trader Analytics

| Command | Description |
|---------|-------------|
| `xrpl traders profile <address>` | Trader profile with tokens traded |
| `xrpl traders token <md5>` | Top traders for a token |
| `xrpl traders portfolio <address>` | Trader portfolio holdings |

### NFTs

| Command | Description |
|---------|-------------|
| `xrpl nft info <nftId>` | NFT details |
| `xrpl nft collections` | List collections |
| `xrpl nft collection <slug>` | Collection details |
| `xrpl nft offers <nftId>` | Buy/sell offers |
| `xrpl nft history <nftId>` | NFT transaction history |

### Token Launch

| Command | Description |
|---------|-------------|
| `xrpl launch create` | Initialize a new token launch |
| `xrpl launch status <sessionId>` | Poll launch progress |
| `xrpl launch cancel <sessionId>` | Cancel and refund |
| `xrpl launch calculate` | Calculate funding requirements |
| `xrpl launch claim <sessionId>` | Claim dev/bundle allocation via CheckCash |
| `xrpl launch image <sessionId>` | Upload token image |
| `xrpl launch authorize <sessionId> <address>` | Authorize for anti-snipe |

### Other

| Command | Description |
|---------|-------------|
| `xrpl creator <id>` | Creator activity with risk signals |
| `xrpl explain <hash>` | Explain a transaction in natural language |
| `xrpl web-search <query>` | Web search via SearXNG |
| `xrpl amm` | List AMM pools |
| `xrpl holders <md5>` | Token holders / richlist |
| `xrpl health` | API health status |
| `xrpl docs` | Full API documentation |
| `xrpl schema [command]` | Parameter schema (agent self-discovery) |

### API Key Management

| Command | Description |
|---------|-------------|
| `xrpl keys list [wallet]` | List API keys |
| `xrpl keys create` | Create new API key |
| `xrpl keys revoke <keyId>` | Revoke an API key |
| `xrpl keys usage [wallet]` | Usage stats |
| `xrpl keys credits [wallet]` | Credit balance |
| `xrpl keys subscription [wallet]` | Current subscription |
| `xrpl keys tiers` | Available pricing tiers |
| `xrpl keys packages` | Credit packages |
| `xrpl keys costs` | Endpoint credit costs |
| `xrpl keys purchase` | Initiate tier upgrade or credit purchase |
| `xrpl keys verify-payment <txHash>` | Verify XRP payment |

### Configuration

| Command | Description |
|---------|-------------|
| `xrpl config show` | Show current config |
| `xrpl config set-key <apiKey>` | Set API key |
| `xrpl config set-url <url>` | Set API base URL |
| `xrpl config set-wallet <wallet>` | Set default wallet |
| `xrpl config reset` | Reset all config |

## Examples

```bash
# Top tokens by 24h volume
xrpl token list --sort vol24hxrp --limit 10

# Get OHLC candles for a token
xrpl price ohlc SOLO --interval 1h --from 1706745600000

# Check trader P&L
xrpl traders profile rN7n3473SaZBCG4dFL83w7p1W9cganksPc

# Explain a transaction
xrpl explain 9B2D3C4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C

# Launch a token
xrpl launch create --currency MYTOKEN --supply 1000000 --amm-xrp 100 --name "My Token"

# Agent workflow (all JSON)
xrpl keygen --json
xrpl signup --json
xrpl token list --json --fields name,slug,price,vol24hxrp
xrpl keys credits --json
```

## Config Files

| File | Purpose |
|------|---------|
| `~/.xrpl-cli/config.json` | API key, base URL, default wallet |
| `~/.xrpl-cli/keypair.json` | XRPL keypair (chmod 600) |

## API

Powered by [xrpl.to API](https://api.xrpl.to/v1/docs). Free tier includes 1M credits/month.

## License

MIT
