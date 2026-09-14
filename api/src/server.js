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
const IS_PROD   = (process.env.NODE_ENV || 'production') === 'production';

// Tenant pinning. NOTE: Azure Static Web Apps does NOT forward the `claims`
// array to a backend -- Microsoft documents the backend as receiving "the same
// user information as a client application, with the exception of the claims
// array". So a tenant check based on claims can never pass on the SWA path and
// would reject every request.
//
// Tenant restriction for that path is enforced upstream instead, by pinning
// openIdIssuer to the tenant GUID in staticwebapp.config.json. This setting is
// therefore only meaningful where claims ARE present (App Service Easy Auth
// forwarding, or a custom provider), and is skipped when they are absent.
const EXPECTED_TENANT = (process.env.EXPECTED_TENANT_ID || '').toLowerCase();

// Accepted identity providers. SWA's built-in Entra provider reports "aad";
// the config key is spelled azureActiveDirectory, so accept both rather than
// risk locking out every user over a naming difference.
const ALLOWED_PROVIDERS = (process.env.ALLOWED_IDENTITY_PROVIDERS || 'aad,azureactivedirectory')
  .toLowerCase().split(',').map(s => s.trim()).filter(Boolean);

const REQUIRED_ROLE = process.env.REQUIRED_ROLE || 'authenticated';

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
      // Section name only. r.reason.message holds raw Log Analytics detail and
      // this object is returned to the browser on a 200.
      console.error(`Composite section "${keys[i]}" failed: ${r.reason.message}`);
      failed.push(keys[i]);
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

// ── Caller identity ──────────────────────────────────────────────────────
//
// Static Web Apps injects x-ms-client-principal after a successful login and
// strips any client-supplied copy. That guarantee only holds for traffic that
// actually arrives THROUGH the Static Web App front door.
//
// This process is an App Service linked backend, so it also has its own
// *.azurewebsites.net hostname. Anything that can reach that hostname directly
// bypasses the Static Web App entirely and can forge this header at will.
// Presence of the header therefore proves nothing on its own, and this service
// holds a managed identity with read access to the Sentinel workspace.
//
// So: decode and check the principal here, AND keep the network-level controls
// described in SETUP.md (App Service authentication + access restrictions
// limiting inbound traffic to the Static Web App). Neither is sufficient alone;
// this function is defence in depth, not the primary boundary.

function parsePrincipal(header) {
  if (!header) return null;
  try {
    const p = JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
    return p && typeof p === 'object' ? p : null;
  } catch {
    return null;   // malformed base64 or JSON -> treat as unauthenticated
  }
}

function claim(principal, ...names) {
  const claims = Array.isArray(principal.claims) ? principal.claims : [];
  for (const c of claims) {
    const key = (c.typ || c.type || '').toLowerCase();
    if (names.some(n => key === n.toLowerCase() || key.endsWith('/' + n.toLowerCase()))) {
      return c.val || c.value;
    }
  }
  return undefined;
}

// Returns null when the caller is acceptable, or a short reason string.
function rejectReason(req) {
  const principal = parsePrincipal(req.get('x-ms-client-principal'));
  if (!principal) return 'missing or malformed principal';

  const provider = (principal.identityProvider || '').toLowerCase();
  if (!ALLOWED_PROVIDERS.includes(provider)) {
    return `unexpected identity provider: ${principal.identityProvider}`;
  }

  const roles = Array.isArray(principal.userRoles) ? principal.userRoles : [];
  if (!roles.includes(REQUIRED_ROLE)) {
    return `missing required role: ${REQUIRED_ROLE}`;
  }

  // Only enforceable when claims were actually forwarded -- see the comment on
  // EXPECTED_TENANT. Absent claims means the SWA path, where the tenant is
  // already pinned at the issuer, so this is not a bypass.
  const claims = Array.isArray(principal.claims) ? principal.claims : [];
  if (EXPECTED_TENANT && claims.length) {
    const tid = (claim(principal, 'tid', 'http://schemas.microsoft.com/identity/claims/tenantid') || '').toLowerCase();
    if (tid !== EXPECTED_TENANT) return 'tenant mismatch';
  }

  return null;
}

const appSrv = express();
appSrv.disable('x-powered-by');

// Liveness only. Deliberately reports nothing about configuration: this
// endpoint is reachable by anything that can reach the host, and mode /
// workspace / storage state is reconnaissance, not health.
appSrv.get(['/health', '/api/health'], (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ status: 'ok' });
});

appSrv.get('/api/data/:name', async (req, res) => {
  // REQUIRE_AUTH_HEADER=false is a local-development escape hatch only. It is
  // ignored in production so that a stale app setting cannot silently turn this
  // into an anonymous Sentinel read API.
  const authDisabled = (process.env.REQUIRE_AUTH_HEADER || 'true') === 'false';
  if (authDisabled && IS_PROD) {
    console.warn('REQUIRE_AUTH_HEADER=false ignored because NODE_ENV is production');
  }
  if (!authDisabled || IS_PROD) {
    const reason = rejectReason(req);
    if (reason) {
      console.warn(`Rejected /api/data/${req.params.name}: ${reason}`);
      return res.status(401).json({ error: 'Unauthenticated' });
    }
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
    // err.message carries up to 400 characters of the raw Log Analytics error
    // body (workspace IDs, table names, KQL diagnostics, managed-identity
    // authorization failures). Log it, never return it.
    return res.status(502).json({ error: 'Upstream data error' });
  }
});

appSrv.listen(PORT, () => {
  console.log(`SOC dashboard API listening on ${PORT} (mode=${MODE})`);
  // State the effective policy at boot so a misconfiguration is visible in the
  // log stream rather than only as mysterious 401s.
  console.log(`  auth: providers=[${ALLOWED_PROVIDERS.join(',')}] role=${REQUIRED_ROLE} ` +
              `tenantCheck=${EXPECTED_TENANT ? 'when claims present' : 'off'} prod=${IS_PROD}`);
});
