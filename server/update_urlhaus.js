/**
 * server/update_urlhaus.js
 *
 * Read an existing server/data/urlhaus.csv and extract hostnames into
 * server/data/urlhaus_hosts.txt. By default this script will NOT download
 * the CSV from urlhaus; it only uses the local CSV if present. If you want
 * to download the CSV, pass --download or set environment var DOWNLOAD=1.
 *
 * Usage:
 *   # regenerate hosts from local CSV (no network)
 *   node update_urlhaus.js
 *
 *   # force download the CSV and then regenerate hosts
 *   node update_urlhaus.js --download
 *   # or
 *   DOWNLOAD=1 node update_urlhaus.js
 *
 * Output:
 *   server/data/urlhaus.csv        (raw CSV, only when downloaded or already present)
 *   server/data/urlhaus_hosts.txt  (one hostname per line, lowercased)
 *
 * Notes:
 * - This script is conservative: it avoids network access unless explicitly requested.
 * - It uses a simple URL regex + URL parsing to extract hostnames. If the CSV format changes,
 *   you may need to tweak the extraction logic.
 */

const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const DATA_DIR = path.join(__dirname, 'data');
const CSV_URL = 'https://urlhaus.abuse.ch/downloads/csv/';
const OUT_CSV = path.join(DATA_DIR, 'urlhaus.csv');
const OUT_HOSTS = path.join(DATA_DIR, 'urlhaus_hosts.txt');

const shouldDownload = process.argv.includes('--download') || process.env.DOWNLOAD === '1';

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

async function downloadCsv() {
  console.log('[update_urlhaus] Downloading URLhaus CSV from', CSV_URL);
  const res = await fetch(CSV_URL);
  if (!res.ok) {
    throw new Error(`Failed to download CSV: ${res.status} ${res.statusText}`);
  }
  const txt = await res.text();
  return txt;
}

function extractHostsFromText(txt) {
  // Find all occurrences of http://... or https://... (robust enough for CSV lines)
  const urlRegex = /https?:\/\/[^\s"']+/g;
  const matches = txt.match(urlRegex) || [];
  const hosts = new Set();
  for (const u of matches) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      hosts.add(h.replace(/^\.+/, '')); // strip leading dots if any
    } catch (e) {
      // ignore parse errors
    }
  }
  return Array.from(hosts).sort();
}

function writeFiles(csvText, hosts) {
  ensureDataDir();
  if (csvText != null) {
    fs.writeFileSync(OUT_CSV, csvText, 'utf8');
    console.log(`[update_urlhaus] Wrote CSV -> ${OUT_CSV} (${csvText.length} bytes)`);
  } else {
    console.log('[update_urlhaus] Using existing CSV on disk (no write performed)');
  }
  fs.writeFileSync(OUT_HOSTS, hosts.join('\n') + '\n', 'utf8');
  console.log(`[update_urlhaus] Wrote ${hosts.length} hosts -> ${OUT_HOSTS}`);
}

(async function main() {
  try {
    ensureDataDir();

    const csvExists = fs.existsSync(OUT_CSV);
    const hostsExists = fs.existsSync(OUT_HOSTS);

    if (!csvExists && !hostsExists && !shouldDownload) {
      console.error('[update_urlhaus] No urlhaus.csv and no urlhaus_hosts.txt found.');
      console.error('[update_urlhaus] To download the CSV and generate hosts, run with --download or set DOWNLOAD=1.');
      process.exitCode = 2;
      return;
    }

    let csvText = null;

    if (csvExists) {
      console.log('[update_urlhaus] Found existing CSV at', OUT_CSV, '- regenerating hosts from it.');
      csvText = fs.readFileSync(OUT_CSV, 'utf8');
    } else if (shouldDownload) {
      csvText = await downloadCsv();
    } else if (hostsExists) {
      console.log('[update_urlhaus] urlhaus_hosts.txt already exists at', OUT_HOSTS, 'and --download not set. Nothing to do.');
      return;
    }

    // If csvText is null here, but hosts file exists, we've already returned. Otherwise extract.
    if (csvText != null) {
      const hosts = extractHostsFromText(csvText);
      writeFiles(csvText, hosts);
      console.log('[update_urlhaus] URLhaus update complete.');
      return;
    }

    // Fallback (shouldn't hit)
    console.warn('[update_urlhaus] No action taken.');
  } catch (err) {
    console.error('[update_urlhaus] URLhaus update failed:', err);
    process.exitCode = 1;
  }
})();