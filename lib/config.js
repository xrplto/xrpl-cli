const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

const ALLOWED_KEYS = new Set(['baseUrl', 'apiKey', 'wallet', 'format']);

const DEFAULTS = {
  baseUrl: 'https://api.xrpl.to/v1',
  apiKey: null,
  wallet: null,
  format: 'human'
};

// ─── API key obfuscation ─────────────────────────────────────
// Light obfuscation so the key isn't sitting in plaintext JSON.
// Uses machine-bound key (same approach as wallet.js).
function getObfuscationKey() {
  const material = `${require('os').hostname()}:${process.getuid?.() ?? 0}:xrpl-cli-config-v1`;
  return crypto.scryptSync(material, 'xrpl-cli-config-salt', 32);
}

function obfuscateApiKey(apiKey) {
  if (!apiKey) return null;
  const key = getObfuscationKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(apiKey, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function deobfuscateApiKey(stored) {
  if (!stored) return null;
  // Support legacy plaintext keys
  if (!stored.startsWith('enc:')) return stored;
  const [, ivHex, tagHex, dataHex] = stored.split(':');
  const key = getObfuscationKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
  return decrypted.toString('utf8');
}

function load() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const fileData = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
      const raw = { ...DEFAULTS, ...fileData };
      // Decrypt API key on load
      raw.apiKey = deobfuscateApiKey(raw.apiKey);
      // Auto-migrate legacy plaintext API keys to encrypted
      if (raw.apiKey && fileData.apiKey && !fileData.apiKey.startsWith('enc:')) {
        save(raw);
      }
      return raw;
    }
  } catch {}
  return { ...DEFAULTS };
}

function save(config) {
  // Encrypt API key before writing
  const toWrite = { ...config };
  if (toWrite.apiKey) {
    toWrite.apiKey = obfuscateApiKey(toWrite.apiKey);
  }
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(toWrite, null, 2) + '\n', { mode: 0o600 });
}

function set(key, value) {
  if (!ALLOWED_KEYS.has(key)) {
    throw new Error(`Invalid config key: ${key}. Allowed: ${[...ALLOWED_KEYS].join(', ')}`);
  }
  const config = load();
  config[key] = value;
  save(config);
  return config;
}

function get(key) {
  return load()[key];
}

module.exports = { load, save, set, get, CONFIG_FILE };
