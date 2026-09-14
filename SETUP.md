# SOC Dashboard — Deployment Guide

## Prerequisites

- Microsoft Sentinel workspace (Log Analytics)
- Azure Storage Account with a Blob container
- Azure Logic Apps (Consumption or Standard)
- Managed Identity enabled on both Logic Apps

---

## Step 1 — Storage Account

> **Only needed for `DATA_SOURCE=blob`.** If you deploy the Static Web App +
> API described in Step 6, the browser never touches storage and you can skip
> this section entirely. That is the recommended path.

1. Create a Storage Account in Azure (or use existing)
2. Create a Blob container, e.g. `soc-dashboard`
3. Set container access to **Private (no anonymous access)**
4. Note your storage account name and container name

> ⚠️ **Do not make the container publicly readable.** The blobs written here
> (`incidents.json`, `open-incidents.json`, `age-distribution.json`,
> `metrics.json`) contain live incident titles, severities, statuses, analyst
> UPNs and email addresses, and SLA breach state. The container and file names
> are fixed and guessable, so "public read for blobs" means anyone who can
> construct the URL can read your organisation's current SOC posture — which
> detections fired, which are unowned, and which are past SLA. That is a
> roadmap for an attacker already inside the environment.
>
> Earlier revisions of this guide recommended public-read plus a `*` CORS rule
> so the static page could `fetch()` the blobs directly. **If you followed that,
> audit the container now:** set anonymous access to Private, and remove any
> wildcard CORS rule.

Serve the data through the authenticated API instead (Step 6). It reads the
blobs — or queries Log Analytics directly — using a managed identity, so no
storage key, SAS token or anonymous endpoint is ever exposed to the browser,
and the data inherits the dashboard's Entra sign-in requirement.

**CORS** — not required when the API proxies the data, because the browser only
ever calls the dashboard's own origin. If you are running the legacy direct-to-blob
mode, scope the origin to your exact dashboard URL rather than `*`:

| Allowed origins | Allowed methods | Allowed headers | Max age |
|---|---|---|---|
| `https://<your-dashboard-host>` | `GET` | `*` | `86400` |

---

## Step 2 — Logic App: Incidents

This Logic App runs every 5 minutes and writes three JSON files to blob:
- `incidents.json` — last 24h incidents
- `open-incidents.json` — all open assigned incidents
- `age-distribution.json` — open Medium/High/Critical incidents for age chart

**Deploy:**
1. Create a new Logic App (Consumption, West Europe recommended)
2. Enable **System Assigned Managed Identity**
3. Go to **Logic App Designer → Code view**
4. Paste the contents of `logicapps/logicapp-incidents.json`
5. Replace all placeholder values:
   - `YOUR_WORKSPACE_ID` → your Log Analytics workspace ID
   - `YOUR_STORAGE_ACCOUNT` → your storage account name
   - `YOUR_CONTAINER_NAME` → your blob container name
6. Save and run manually to test

**Role assignments needed (IAM):**
- Logic App MI → **Log Analytics Reader** on the Log Analytics workspace
- Logic App MI → **Microsoft Sentinel Reader** on the workspace
- Logic App MI → **Storage Blob Data Contributor** on the storage account

---

## Step 3 — Logic App: Metrics

This Logic App runs every 5 minutes and writes `metrics.json` with:
- Ingestion by table (24h)
- 7-day ingestion trend
- Agent heartbeat status
- Top firing alerts
- Sign-in summary
- Audit highlights

**Deploy:** same steps as above using `logicapps/logicapp-metrics.json`

---

## Step 4 — Dashboard

1. Open `dashboard.html` in a text editor
2. Find the `CONFIG` block near the top of the `<script>` section
3. Replace:
   ```js
   const BLOB = 'https://YOUR_STORAGE_ACCOUNT.blob.core.windows.net/YOUR_CONTAINER_NAME';
   ```
   with your actual blob URL
4. Optionally add your own logo — replace the `SOC DASHBOARD` placeholder text with an `<img>` tag
5. Open `dashboard.html` in Chrome and press **F11** for fullscreen on your TV/screen

---

## Architecture

```
Microsoft Sentinel (Log Analytics)
        │
        │  KQL queries via HTTP + Managed Identity
        ▼
Logic Apps (every 5 min)
        │
        │  PUT JSON results
        ▼
Azure Blob Storage
  ├── incidents.json          (24h incidents)
  ├── open-incidents.json     (all assigned open)
  ├── age-distribution.json   (open M/H/C for age chart)
  └── metrics.json            (ingestion, health, alerts)
        │
        │  fetch() every 5 min
        ▼
dashboard.html (browser, any device)
```

---

## SLA Thresholds

The dashboard flags SLA breaches based on:

| Severity | Threshold |
|---|---|
| Critical | > 2 hours open |
| High | > 8 hours open |

To change thresholds, find `isSLABreached` in `dashboard.html` and update the hours.

---

## Ingestion Color Thresholds (daily GB)

| Color | Threshold |
|---|---|
| 🟢 Green | < 250 GB |
| 🟡 Yellow | ≥ 250 GB |
| 🟠 Orange | ≥ 300 GB |
| 🔴 Red | ≥ 350 GB |

Adjust in `dashboard.html` → `gbColor()` function.

---

## NCSC Threat Feed

The scrolling ticker pulls live from `feeds.ncsc.nl/nieuws.rss` via the `rss2json.com` free API proxy (needed for CORS). It refreshes every 30 minutes.

To use a different feed, find `fetchNCSCFeed()` and replace the RSS URL.

---

## Troubleshooting

**Dashboard shows no data**
- Check browser console for CORS errors
- Verify Logic Apps ran successfully (green in run history)
- In blob mode, confirm the API's managed identity can read the container
- If the API returns 401, check the "Azure Static Web Apps (Linked)" identity
  provider still exists on the App Service (see *Securing the App Service
  backend*), and that no network access restriction has been added

**Logic App fails on LA query**
- Verify Managed Identity has Log Analytics Reader role
- Check workspace ID is correct

**Logic App fails on blob write**
- Verify Managed Identity has Storage Blob Data Contributor role
- Check storage account name and container name are correct

---

## Securing the App Service backend

The API is attached to the Static Web App as a **linked backend**. Understanding
how that is secured matters, because two reasonable-looking hardening steps will
break it.

### What protects the backend today

Linking the backend causes Static Web Apps to create an identity provider named
**"Azure Static Web Apps (Linked)"** in the App Service's authentication
settings. It is configured to accept requests only when they arrive through the
SWA proxy, which is what makes direct calls to
`https://<app>.azurewebsites.net` return `401` instead of serving data.

Verify it is on:

```bash
az webapp auth show --name <app> --resource-group <rg> --query enabled
# expect: true
curl -s -o /dev/null -w '%{http_code}' https://<app>.azurewebsites.net/health
# expect: 401
```

> ⚠️ **Do not delete that identity provider.** Removing it is the documented way
> to make a linked backend publicly reachable — which, for this app, means
> anonymous access to an API that reads Sentinel with a managed identity.

### ⚠️ Do NOT add network access restrictions or a private endpoint

The SWA proxy runs outside your virtual network, so it cannot reach a
network-isolated backend. Microsoft states that network-isolated backends are
**not supported** with the bring-your-own-API feature: enabling IP restrictions,
service-tag rules, VNet integration or a private endpoint on the App Service
stops the SWA proxy from reaching it and the dashboard goes blank.

The access restriction on this App Service must stay **Allow all**. That is not
an oversight; the authentication layer above is the control.

### Application-level checks

`api/src/server.js` independently validates the caller as defence in depth. It
decodes `x-ms-client-principal` and requires a known `identityProvider` and the
`authenticated` role. Relevant app settings:

| Setting | Value | Notes |
|---|---|---|
| `NODE_ENV` | `production` | Makes `REQUIRE_AUTH_HEADER=false` be ignored, so a stale dev setting cannot expose the API. Defaults to production when unset. |
| `ALLOWED_IDENTITY_PROVIDERS` | *(unset)* | Defaults to `aad,azureactivedirectory`. |
| `REQUIRED_ROLE` | *(unset)* | Defaults to `authenticated`. |
| `EXPECTED_TENANT_ID` | **leave unset** | See below. |

> ⚠️ **`EXPECTED_TENANT_ID` does nothing on the SWA path — do not rely on it.**
> Static Web Apps does not forward the `claims` array to a backend. Microsoft
> documents the backend as receiving *"the same user information as a client
> application, with the exception of the `claims` array"*. `identityProvider`,
> `userId`, `userDetails` and `userRoles` do arrive; `claims` do not, so there is
> no `tid` to compare. The code therefore skips the tenant check when claims are
> absent rather than rejecting everyone.
>
> Tenant restriction is enforced instead by pinning `openIdIssuer` to the tenant
> GUID in `public/staticwebapp.config.json`. That is what stops arbitrary
> Microsoft accounts — including personal ones — from signing in.

### Deploying the API

The GitHub Action has `api_location: ""`, so it deploys **only `public/`**.
Changes under `api/` require a separate deploy:

```bash
cd api && zip -r ../api.zip package.json src
az webapp deploy --name <app> --resource-group <rg> --src-path ../api.zip --type zip
```

`SCM_DO_BUILD_DURING_DEPLOYMENT=true` makes App Service run `npm install`, so
`node_modules` does not need to be in the zip.
