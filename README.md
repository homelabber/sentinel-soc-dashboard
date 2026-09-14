# Building a Live SOC Dashboard with Microsoft Sentinel, Logic Apps & plain HTML

> A real-time security operations dashboard that runs in any browser, costs almost nothing to operate, and fits on a 50-inch screen.

**Forked from [Jeroenvdbroek/sentinel-soc-dashboard](https://github.com/Jeroenvdbroek/sentinel-soc-dashboard)** ([GitHub Pages blog](https://jeroenvdbroek.github.io/sentinel-soc-dashboard)), which is the origin of the architecture described below.

This fork adds:

- **Azure Static Web Apps hosting with Entra ID authentication** — the blob container no longer needs public read access.
- **A direct-query API** — an App Service backend querying Log Analytics over managed identity (`DATA_SOURCE=loganalytics`), so the dashboard can run without the Logic App and blob hop. Blob mode still works; both modes return the same shape.
- **A Teams alerting Logic App** — adaptive cards for new Critical/High incidents and for SLA breaches as they cross the threshold.
- **30-day trend queries** — incident volume, MTTR, SLA compliance, open backlog.
- **Microsoft Defender portal deep links** — incident links resolve to `security.microsoft.com` via `AdditionalData.providerIncidentUrl` instead of the Azure portal Sentinel blade, which is unsupported after 2027-03-31.

---

## The Problem

Every SOC has the same challenge: too many places to look. Sentinel has its own workbooks. Defenders has its own portal. Analysts live in different tools. When something is happening, something is always happening — the team needs a single view they can glance at from across the room.

We wanted a dashboard that:
- Shows **live data** without requiring anyone to click around
- Works on a **big screen** mounted on the wall
- Is **easy to maintain** — no Node.js server, no database, no backend to babysit
- Costs **as little as possible** to run

The result is this: a static HTML file that reads JSON from Azure Blob Storage, updated every 5 minutes by two Logic Apps.

---

## How It Works

The architecture is intentionally simple:

```
Microsoft Sentinel (Log Analytics)
        │
        │  KQL via Managed Identity
        ▼
Logic Apps (every 5 min)
        │
        │  Write JSON to blob
        ▼
Azure Blob Storage
        │
        │  fetch() in browser
        ▼
dashboard.html
```

No servers. No APIs. No authentication headaches. The Logic Apps write fresh JSON every 5 minutes. The browser fetches it and renders it. That's it.

---

## What It Shows

The dashboard is designed to fill a single screen with everything that matters:

**Top row — 6 tiles**
Total incidents, New, Active, Closed, MTTR average, and SLA breaches — all from the last 24 hours.

**High & Critical feed**
A live table of only High and Critical incidents, with SLA breach warnings highlighted in red.

**Severity distribution**
Bar chart of all 24h incidents by severity.

**Data ingestion (color-coded)**
A 7-day sparkline with color thresholds — green under 250GB/day, yellow at 250+, orange at 300+, red at 350+. Useful for spotting ingestion anomalies at a glance.

**Analyst workload**
One row per analyst showing their open tickets today and over 90 days, with color coding per person and oldest open ticket age.

**Open incident age distribution**
How long have your Medium/High/Critical incidents been sitting open? Bucketed into `<1d`, `1–3d`, `3–7d`, `1–2w`, `2w–1m`, `>1 month` with a green-to-red gradient.

**Full incident feed**
Filterable table of all 24h incidents with All / Critical / High / New / SLA filters.

**Threat ticker**
A scrolling news bar at the top pulling live from the NCSC RSS feed — so the team always has current threat context visible.

---

## Logic Apps — the Engine

Two Logic Apps do all the work:

**logicapp-incidents** (every 5 minutes)
Runs three KQL queries against Sentinel and writes the results as JSON blobs:
- `incidents.json` — all incidents created in the last 24h
- `open-incidents.json` — every open assigned incident (no time limit)
- `age-distribution.json` — open Medium/High/Critical incidents for the age chart

**logicapp-metrics** (every 5 minutes)
Queries ingestion stats, agent heartbeats, top alerts, sign-in summary and writes them all to `metrics.json`.

Both Logic Apps use **Managed Identity** to authenticate to Log Analytics and Blob Storage — no secrets, no API keys, no expiry dates to manage.

---

## The KQL That Makes It Work

The trickiest part was getting the queries right. A few lessons learned:

**Always filter `TimeGenerated` before `summarize arg_max`**

This is the most important performance fix. Without it, the query scans all history:

```kql
-- Slow (scans everything):
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where TimeGenerated > ago(24h)

-- Fast (pre-filters first):
SecurityIncident
| where TimeGenerated > ago(24h)
| where CreatedTime > ago(24h)
| summarize arg_max(TimeGenerated, *) by IncidentNumber
```

**Use `CreatedTime` not `TimeGenerated` for "new incidents today"**

`TimeGenerated` is updated every time an incident is touched — by playbooks, correlation rules, analysts. Filtering on it gives you incidents *modified* today, not *created* today. For the 24h feed, use `CreatedTime > ago(24h)`.

**For the "all open" analyst workload query, use no time filter at all**

```kql
SecurityIncident
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != 'Closed'
| where isnotempty(Owner.userPrincipalName)
```

This gives you the true current state of every open assigned incident, regardless of when it was created.

**Owner field**

In our environment, `Owner.userPrincipalName` is the right field. `Owner.assignedTo` was empty for most incidents. Check which field your Sentinel uses — they differ by configuration.

---

## Deployment

See [SETUP.md](SETUP.md) for full step-by-step instructions.

Quick summary:
1. Create a Storage Account + Blob container
2. Deploy two Logic Apps from the JSON files in `/logicapps`
3. Assign Managed Identity roles (Log Analytics Reader + Storage Blob Data Contributor)
4. Edit the `BLOB` constant in `dashboard.html` to point to your storage account
5. Open in Chrome, press F11, mount on wall

Total Azure cost: Logic Apps Consumption runs at ~$0.000025 per action. At 5-minute intervals with ~10 actions each run, that's roughly **$1–2/month**.

---

## What We Would Do Differently

**Serve via App Service or Static Web App instead of public blob**
Currently the blob container needs public read access for the browser to fetch data. A better architecture serves the JSON through a proxy or uses Azure Static Web Apps with authentication.

**Add alerting**
A third Logic App that sends a Teams message when a Critical incident has been open for more than 2 hours without an owner.

**Historical trending**
The current setup only keeps the latest snapshot. Appending to a timeseries blob would enable 30/90-day trending charts.

---

## Files in This Repo

```
├── dashboard.html              # The TV dashboard (single HTML file)
├── SETUP.md                    # Deployment guide
├── README.md                   # This file
├── logicapps/
│   ├── logicapp-incidents.json # Logic App for incident queries
│   └── logicapp-metrics.json   # Logic App for metrics queries
└── queries/
    ├── incidents-24h.kql
    ├── open-incidents-assigned.kql
    ├── open-incidents-age-distribution.kql
    ├── ingestion-by-table.kql
    └── ingestion-trend-7d.kql
```

---

## Contributing

PRs welcome. Especially interested in:
- Support for other SIEM platforms
- Dark/light theme toggle
- Mobile-responsive layout

---

*Built for a SOC running Microsoft Sentinel. Adapt freely.*
