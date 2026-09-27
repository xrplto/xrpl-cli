import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import { sign, deriveKeypair, deriveAddress } from 'ripple-keypairs';
import type { Keypair, EncryptionEnvelope, AuthHeaders, SignResult } from './types';

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
export const DEFAULT_KEYPAIR_PATH = path.join(CONFIG_DIR, 'keypair.json');

// ─── Encryption helpers ──────────────────────────────────────
function getMachineKey(): Buffer {
  const material = `${os.hostname()}:${process.getuid?.() ?? 0}:xrpl-cli-v1`;
  return crypto.scryptSync(material, 'xrpl-cli-keypair-salt', 32, { N: 16384, r: 8, p: 2 });
}

function encryptData(plaintext: string): EncryptionEnvelope {
  const key = getMachineKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    iv: iv.toString('hex'),
    tag: tag.toString('hex'),
    data: encrypted.toString('hex')
  };
}

function decryptData(envelope: EncryptionEnvelope): string {
  if (!envelope.v || envelope.v !== 1) {
    throw new Error('Unknown keypair format version');
  }
  const key = getMachineKey();
  const iv = Buffer.from(envelope.iv, 'hex');
  const tag = Buffer.from(envelope.tag, 'hex');
  const encrypted = Buffer.from(envelope.data, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

// ─── Path validation ─────────────────────────────────────────
function getKeypairPath(custom?: string): string {
  if (!custom) return DEFAULT_KEYPAIR_PATH;
  const resolved = path.resolve(custom);
  // Restrict to within ~/.xrpl-cli/ to prevent path traversal
  if (!resolved.startsWith(CONFIG_DIR + path.sep) && resolved !== DEFAULT_KEYPAIR_PATH) {
    throw new Error(`Keypair path must be within ${CONFIG_DIR}/`);
  }
  return resolved;
}

export function keypairExists(customPath?: string): boolean {
  try {
    return fs.existsSync(getKeypairPath(customPath));
  } catch {
    return false;
  }
}

export function generate(): Keypair {
  const xrpl = require('xrpl');
  const wallet = xrpl.Wallet.generate();
  const data: Keypair = {
    address: wallet.address,
    publicKey: wallet.publicKey,
    seed: wallet.seed
  };

  // Encrypt before writing — use 'wx' flag for exclusive create (prevents TOCTOU race)
  const envelope = encryptData(JSON.stringify(data));
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  try { fs.chmodSync(CONFIG_DIR, 0o700); } catch {}
  fs.writeFileSync(DEFAULT_KEYPAIR_PATH, JSON.stringify(envelope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });

  return data;
}

export function load(customPath?: string): Keypair | null {
  let p: string;
  try {
    p = getKeypairPath(customPath);
  } catch {
    return null;
  }
  if (!fs.existsSync(p)) return null;

  // Block symlinks to prevent reading arbitrary files
  try {
    const stat = fs.lstatSync(p);
    if (stat.isSymbolicLink()) return null;
  } catch {
    return null;
  }

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch {
    // Corrupted or non-JSON file — return null instead of leaking file content in stack trace
    return null;
  }

  // Encrypted format (v1) only — no plaintext fallback
  try {
    if (raw.v === 1 && raw.data) {
      const decrypted = decryptData(raw as unknown as EncryptionEnvelope);
      return JSON.parse(decrypted) as Keypair;
    }
  } catch {
    // Decryption or parse failure — return null
    return null;
  }

  return null;
}

export function signMessage(message: string, keypair: Keypair): SignResult {
  const messageHex = Buffer.from(message).toString('hex');
  const { privateKey, publicKey } = deriveKeypair(keypair.seed);
  const signature = sign(messageHex, privateKey);
  return { signature, publicKey, address: deriveAddress(publicKey) };
}

export function getAuthHeaders(keypair: Keypair, method?: string, path?: string): AuthHeaders {
  const timestamp = String(Date.now());
  // Include method+path in signature to prevent cross-endpoint replay
  const message = method && path
    ? `${keypair.address}:${timestamp}:${method}:${path}`
    : `${keypair.address}:${timestamp}`;
  const signed = signMessage(message, keypair);
  return {
    'X-Wallet': keypair.address,
    'X-Timestamp': timestamp,
    'X-Signature': signed.signature,
    'X-Public-Key': signed.publicKey
  };
}
