const express = require('express');
const { DefaultAzureCredential } = require('@azure/identity');
const QUERIES = require('./queries');

// Read-only data API for the Sentinel SOC dashboard.
//
// Runs on Azure App Service behind Azure Static Web Apps (linked backend).
// Static Web Apps authenticates the user with Microsoft Entra ID and forwards
// /api/* here, injecting an x-ms-client-principal header. This process talks to
// Azure using a managed identity, so no key, SAS token or client secret is ever
// sent to the browser.
//
// Two data modes, selected with the DATA_SOURCE app setting:
//
//   blob          Reads JSON blobs produced by the Logic Apps (upstream design).
//                 Requires network access to the storage account.
//
//   loganalytics  Queries Sentinel directly with the managed identity.
//                 Required in tenants where policy forces
//                 publicNetworkAccess=Disabled on storage accounts, which makes
//                 the blob hop impossible. Also removes the 5-minute staleness.

const MODE      = (process.env.DATA_SOURCE || 'blob').toLowerCase();
const ACCOUNT   = process.env.STORAGE_ACCOUNT;
const CONTAINER = process.env.STORAGE_CONTAINER || 'soc-dashboard';
const WORKSPACE = process.env.WORKSPACE_ID;
const CACHE_SEC = parseInt(process.env.CACHE_SECONDS || '60', 10);
const PORT      = process.env.PORT || 8080;

// Only these names may be served. Without an allow-list this would become a
// generic read primitive over the storage account.
const ALLOWED = new Set(Object.keys(QUERIES));

const credential = new DefaultAzureCredential();

// ── Simple in-process cache ──────────────────────────────────────────────
// Each dashboard load fetches 5 endpoints and several browsers may be open.
// Caching avoids re-running the heavier 30-day trend queries per viewer.
const cache = new Map();
const cacheGet = k => {
  const hit = cache.get(k);
  return hit && (Date.now() - hit.at) < CACHE_SEC * 1000 ? hit.value : null;
};
const cacheSet = (k, v) => cache.set(k, { at: Date.now(), value: v });

// ── Log Analytics ────────────────────────────────────────────────────────
let laToken = null;
async function getLaToken() {
  // Refresh a minute before expiry rather than waiting for a 401.
  if (laToken && laToken.expiresOnTimestamp - Date.now() > 60000) return laToken.token;
  laToken = await credential.getToken('https://api.loganalytics.io/.default');
  if (!laToken) throw new Error('Failed to acquire Log Analytics token');
  return laToken.token;
}

async function runQuery(kql) {
  if (!WORKSPACE) throw new Error('WORKSPACE_ID app setting is not configured');
  const token = await getLaToken();
  const res = await fetch(`https://api.loganalytics.io/v1/workspaces/${WORKSPACE}/query`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: kql })
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`Log Analytics ${res.status}: ${detail.slice(0, 400)}`);
  }
  return res.json();
}

async function fromLogAnalytics(name) {
  const spec = QUERIES[name];

  // Single-query files are returned raw; the dashboard's laToObj() understands
  // the {tables:[...]} shape.
  if (spec.single) return runQuery(spec.single);

  // Composite files (metrics.json, trends.json) hold several named results.
  // Run in parallel; one failing section must not blank the entire page.
  const keys = Object.keys(spec.composite);
  const settled = await Promise.allSettled(keys.map(k => runQuery(spec.composite[k])));

  const out = { generatedAt: new Date().toISOString() };
  const failed = [];
  settled.forEach((r, i) => {
    if (r.status === 'fulfilled') {
      out[keys[i]] = r.value.tables;
    } else {
      out[keys[i]] = [];
      failed.push(`${keys[i]}: ${r.reason.message}`);
    }
  });
  if (failed.length) out.partialErrors = failed;
  return out;
}

// ── Blob ─────────────────────────────────────────────────────────────────
let containerClient = null;
function getContainerClient() {
  if (!containerClient) {
    if (!ACCOUNT) throw new Error('STORAGE_ACCOUNT app setting is not configured');
    const { BlobServiceClient } = require('@azure/storage-blob');
    containerClient = new BlobServiceClient(
      `https://${ACCOUNT}.blob.core.windows.net`, credential
    ).getContainerClient(CONTAINER);
  }
  return containerClient;
}

async function streamToString(readable) {
  if (!readable) return '';
  const chunks = [];
  for await (const c of readable) chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c));
  return Buffer.concat(chunks).toString('utf8');
}

async function fromBlob(name) {
  const dl = await getContainerClient().getBlobClient(name).download();
  return JSON.parse(await streamToString(dl.readableStreamBody));
}

// ── HTTP ─────────────────────────────────────────────────────────────────
const appSrv = express();
appSrv.disable('x-powered-by');

// Unauthenticated on purpose so deployment checks can verify configuration.
// Reports configuration state only - never data.
appSrv.get(['/health', '/api/health'], (_req, res) => {
  res.json({
    status: 'ok',
    mode: MODE,
    workspaceConfigured: !!WORKSPACE,
    storageConfigured: !!ACCOUNT,
    cacheSeconds: CACHE_SEC
  });
});

appSrv.get('/api/data/:name', async (req, res) => {
  // Static Web Apps injects this header after a successful login and strips any
  // client-supplied copy, so its absence means the caller did not arrive through
  // an authenticated SWA session.
  //
  // REQUIRE_AUTH_HEADER=false disables the check for local development only.
  const requireAuth = (process.env.REQUIRE_AUTH_HEADER || 'true') !== 'false';
  if (requireAuth && !req.get('x-ms-client-principal')) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }

  const name = req.params.name;
  if (!ALLOWED.has(name)) {
    console.warn(`Rejected request for disallowed resource: ${name}`);
    return res.status(404).json({ error: 'Not found' });
  }

  const cached = cacheGet(name);
  if (cached) {
    res.set('X-Cache', 'HIT');
    return res.json(cached);
  }

  try {
    const data = MODE === 'loganalytics' ? await fromLogAnalytics(name)
                                         : await fromBlob(name);
    cacheSet(name, data);
    res.set({
      'Cache-Control': 'no-cache, must-revalidate',
      'X-Cache': 'MISS',
      'X-Data-Source': MODE
    });
    return res.json(data);
  } catch (err) {
    // Normal in blob mode before the Logic Apps have run for the first time.
    if (err.statusCode === 404) {
      return res.status(404).json({ error: `${name} has not been generated yet` });
    }
    console.error(`Failed serving ${name} (${MODE}): ${err.message}`);
    return res.status(502).json({ error: 'Upstream data error', detail: err.message });
  }
});

appSrv.listen(PORT, () => {
  console.log(`SOC dashboard API listening on ${PORT} (mode=${MODE})`);
});
