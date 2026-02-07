const fs = require('fs');
const path = require('path');
const { sign, deriveKeypair, deriveAddress } = require('ripple-keypairs');

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
const DEFAULT_KEYPAIR_PATH = path.join(CONFIG_DIR, 'keypair.json');

function getKeypairPath(custom) {
  return custom || DEFAULT_KEYPAIR_PATH;
}

function keypairExists(customPath) {
  return fs.existsSync(getKeypairPath(customPath));
}

function generate() {
  const xrpl = require('xrpl');
  const wallet = xrpl.Wallet.generate();
  const data = {
    address: wallet.address,
    publicKey: wallet.publicKey,
    privateKey: wallet.privateKey,
    seed: wallet.seed
  };
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(DEFAULT_KEYPAIR_PATH, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  return data;
}

function load(customPath) {
  const p = getKeypairPath(customPath);
  if (!fs.existsSync(p)) return null;
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function signMessage(message, keypair) {
  const messageHex = Buffer.from(message).toString('hex');
  // deriveKeypair from seed to get proper format
  const { privateKey, publicKey } = deriveKeypair(keypair.seed);
  const signature = sign(messageHex, privateKey);
  return { signature, publicKey, address: deriveAddress(publicKey) };
}

function getAuthHeaders(keypair) {
  const timestamp = String(Date.now());
  const message = `${keypair.address}:${timestamp}`;
  const signed = signMessage(message, keypair);
  return {
    'X-Wallet': keypair.address,
    'X-Timestamp': timestamp,
    'X-Signature': signed.signature,
    'X-Public-Key': signed.publicKey
  };
}

module.exports = { generate, load, keypairExists, getKeypairPath, signMessage, getAuthHeaders, DEFAULT_KEYPAIR_PATH };
