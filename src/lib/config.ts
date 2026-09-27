import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import type { Config, ConfigKey } from './types';

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
export const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

const ALLOWED_KEYS = new Set<ConfigKey>(['baseUrl', 'apiKey', 'wallet', 'format']);

const DEFAULTS: Config = {
  baseUrl: 'https://api.xrpl.to/v1',
  apiKey: null,
  wallet: null,
  format: 'human'
};

// ─── API key obfuscation ─────────────────────────────────────
function getObfuscationKey(): Buffer {
  const material = `${os.hostname()}:${process.getuid?.() ?? 0}:xrpl-cli-config-v1`;
  return crypto.scryptSync(material, 'xrpl-cli-config-salt', 32, { N: 16384, r: 8, p: 2 });
}

function obfuscateApiKey(apiKey: string | null): string | null {
  if (!apiKey) return null;
  const key = getObfuscationKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(apiKey, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function deobfuscateApiKey(stored: string | null): string | null {
  if (!stored) return null;
  // Encrypted format only — reject plaintext keys
  if (!stored.startsWith('enc:')) return null;
  const [, ivHex, tagHex, dataHex] = stored.split(':');
  const key = getObfuscationKey();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
  return decrypted.toString('utf8');
}

export function load(): Config {
  if (!fs.existsSync(CONFIG_FILE)) return { ...DEFAULTS };
  try {
    const fileData = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) as Partial<Config>;
    const raw: Config = { ...DEFAULTS, ...fileData };
    // Decrypt API key on load (encrypted format only)
    raw.apiKey = deobfuscateApiKey(raw.apiKey);
    return raw;
  } catch {
    // Config file exists but is corrupted — warn and fall back to defaults
    process.stderr.write(`Warning: Config file ${CONFIG_FILE} is corrupted. Using defaults.\n`);
    return { ...DEFAULTS };
  }
}

export function save(config: Config): void {
  // Encrypt API key before writing
  const toWrite = { ...config };
  if (toWrite.apiKey) {
    toWrite.apiKey = obfuscateApiKey(toWrite.apiKey);
  }
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(CONFIG_DIR, 0o700); } catch {}
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(toWrite, null, 2) + '\n', { mode: 0o600 });
}

export function set<K extends ConfigKey>(key: K, value: Config[K]): Config {
  if (!ALLOWED_KEYS.has(key)) {
    throw new Error(`Invalid config key: ${key}. Allowed: ${[...ALLOWED_KEYS].join(', ')}`);
  }
  const config = load();
  config[key] = value;
  save(config);
  return config;
}

export function get<K extends ConfigKey>(key: K): Config[K] {
  return load()[key];
}
