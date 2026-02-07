/**
 * Structured output for LLM agent consumption.
 *
 * Exit codes (Helius-inspired):
 *   0     success
 *   1     general error
 *   10-19 auth errors
 *   20-29 not found
 *   30-39 rate limit / credits
 *   40-49 API / network errors
 */

let jsonMode = false;

function setJsonMode(enabled) { jsonMode = enabled; }
function isJson() { return jsonMode; }

function success(data) {
  if (jsonMode) {
    process.stdout.write(JSON.stringify(data, null, 2) + '\n');
  } else {
    prettyPrint(data);
  }
  process.exit(0);
}

function error(message, code = 1, details = null) {
  const payload = { error: message };
  if (details) payload.details = details;

  if (jsonMode) {
    process.stderr.write(JSON.stringify(payload, null, 2) + '\n');
  } else {
    process.stderr.write(`Error: ${message}\n`);
    if (details) process.stderr.write(`  ${typeof details === 'string' ? details : JSON.stringify(details)}\n`);
  }
  process.exit(code);
}

function prettyPrint(data, indent = 0) {
  if (data === null || data === undefined) return;

  if (Array.isArray(data)) {
    if (data.length === 0) { process.stdout.write('[]\n'); return; }
    // Table-like output for arrays of objects
    if (typeof data[0] === 'object' && data[0] !== null) {
      const keys = Object.keys(data[0]);
      // Header
      process.stdout.write(keys.map(k => k.padEnd(18)).join('') + '\n');
      process.stdout.write(keys.map(() => '─'.repeat(17) + ' ').join('') + '\n');
      for (const row of data.slice(0, 50)) {
        process.stdout.write(keys.map(k => String(row[k] ?? '').substring(0, 17).padEnd(18)).join('') + '\n');
      }
      if (data.length > 50) process.stdout.write(`... and ${data.length - 50} more\n`);
    } else {
      data.forEach(item => process.stdout.write(`  ${item}\n`));
    }
    return;
  }

  if (typeof data === 'object') {
    const pad = '  '.repeat(indent);
    for (const [key, val] of Object.entries(data)) {
      if (val === null || val === undefined) continue;
      if (typeof val === 'object' && !Array.isArray(val)) {
        process.stdout.write(`${pad}${key}:\n`);
        prettyPrint(val, indent + 1);
      } else if (Array.isArray(val) && val.length > 0 && typeof val[0] === 'object') {
        process.stdout.write(`${pad}${key}: (${val.length} items)\n`);
        prettyPrint(val, indent + 1);
      } else {
        process.stdout.write(`${pad}${key}: ${Array.isArray(val) ? val.join(', ') : val}\n`);
      }
    }
    return;
  }

  process.stdout.write(String(data) + '\n');
}

module.exports = { setJsonMode, isJson, success, error };
