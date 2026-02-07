const fs = require('fs');
const path = require('path');

const CONFIG_DIR = path.join(process.env.HOME || '/root', '.xrpl-cli');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');

const DEFAULTS = {
  baseUrl: 'https://api.xrpl.to/v1',
  apiKey: null,
  wallet: null,
  format: 'human'
};

function load() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      return { ...DEFAULTS, ...JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch {}
  return { ...DEFAULTS };
}

function save(config) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

function set(key, value) {
  const config = load();
  config[key] = value;
  save(config);
  return config;
}

function get(key) {
  return load()[key];
}

module.exports = { load, save, set, get, CONFIG_FILE };
