const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { sign, deriveKeypair, deriveAddress } = require('ripple-keypairs');

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
const DEFAULT_KEYPAIR_PATH = path.join(CONFIG_DIR, 'keypair.json');

// ─── Encryption helpers ──────────────────────────────────────
// Derive a machine-bound key so the file is useless if copied elsewhere.
// Uses hostname + uid + a fixed salt. Not a substitute for a passphrase,
// but prevents casual exfiltration via backup/disk recovery.
function getMachineKey() {
  const material = `${require('os').hostname()}:${process.getuid?.() ?? 0}:xrpl-cli-v1`;
  return crypto.scryptSync(material, 'xrpl-cli-keypair-salt', 32);
}

function encryptData(plaintext) {
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

function decryptData(envelope) {
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
function getKeypairPath(custom) {
  if (!custom) return DEFAULT_KEYPAIR_PATH;
  const resolved = path.resolve(custom);
  // Restrict to within ~/.xrpl-cli/ to prevent path traversal
  if (!resolved.startsWith(CONFIG_DIR + path.sep) && resolved !== DEFAULT_KEYPAIR_PATH) {
    throw new Error(`Keypair path must be within ${CONFIG_DIR}/`);
  }
  return resolved;
}

function keypairExists(customPath) {
  try {
    return fs.existsSync(getKeypairPath(customPath));
  } catch {
    return false;
  }
}

function generate() {
  const xrpl = require('xrpl');
  const wallet = xrpl.Wallet.generate();
  const data = {
    address: wallet.address,
    publicKey: wallet.publicKey,
    seed: wallet.seed
    // privateKey deliberately omitted — derivable from seed
  };

  // Encrypt before writing
  const envelope = encryptData(JSON.stringify(data));
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(DEFAULT_KEYPAIR_PATH, JSON.stringify(envelope, null, 2) + '\n', { mode: 0o600 });

  return data;
}

function load(customPath) {
  let p;
  try {
    p = getKeypairPath(customPath);
  } catch {
    return null;
  }
  if (!fs.existsSync(p)) return null;

  const raw = JSON.parse(fs.readFileSync(p, 'utf8'));

  // Support encrypted (v1) and legacy plaintext formats
  if (raw.v === 1 && raw.data) {
    const decrypted = decryptData(raw);
    return JSON.parse(decrypted);
  }

  // Legacy plaintext — migrate to encrypted on load
  if (raw.seed && raw.address) {
    const data = { address: raw.address, publicKey: raw.publicKey, seed: raw.seed };
    const envelope = encryptData(JSON.stringify(data));
    fs.writeFileSync(p, JSON.stringify(envelope, null, 2) + '\n', { mode: 0o600 });
    return data;
  }

  return null;
}

function signMessage(message, keypair) {
  const messageHex = Buffer.from(message).toString('hex');
  const { privateKey, publicKey } = deriveKeypair(keypair.seed);
  const signature = sign(messageHex, privateKey);
  return { signature, publicKey, address: deriveAddress(publicKey) };
}

function getAuthHeaders(keypair, method, path) {
  const timestamp = String(Date.now());
  const nonce = crypto.randomBytes(16).toString('hex');
  // Bind signature to method + path + nonce to prevent replay
  const message = `${keypair.address}:${timestamp}:${nonce}:${method || ''}:${path || ''}`;
  const signed = signMessage(message, keypair);
  return {
    'X-Wallet': keypair.address,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Signature': signed.signature,
    'X-Public-Key': signed.publicKey
  };
}

module.exports = { generate, load, keypairExists, getKeypairPath, signMessage, getAuthHeaders, DEFAULT_KEYPAIR_PATH };
