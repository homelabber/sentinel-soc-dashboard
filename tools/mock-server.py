#!/usr/bin/env python
"""Serve the dashboard with synthetic data, for screenshots.

The live dashboard renders real incident titles, real analyst identities and
the organisation's actual SOC posture. None of that belongs in a public
repository, so the screenshots in README.md are taken against fabricated data
instead.

    python tools/mock-server.py          # http://127.0.0.1:8750/index.html

Everything below is invented. Any resemblance to a real detection, person or
tenant is coincidental. The seed is fixed so screenshots are reproducible.
"""
from __future__ import annotations

import http.server
import json
import random
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
PUBLIC = ROOT / "public"
PORT = 8750

rng = random.Random(20261031)
# Anchor to real "now": the dashboard computes incident age against the
# browser's clock, so a fixed timestamp here would make every incident appear
# to be in the future and the SLA logic would never fire.
NOW = datetime.now(timezone.utc)

ANALYSTS = [
    "a.okonkwo@contoso.com", "j.lindqvist@contoso.com", "m.delacroix@contoso.com",
    "r.venkatesan@contoso.com", "s.holloway@contoso.com",
]

TITLES = [
    ("Suspicious sign-in from unfamiliar location", "InitialAccess", "Entra ID Protection"),
    ("Multiple failed sign-ins followed by success", "CredentialAccess", "Entra ID Protection"),
    ("Possible AS-REP roasting against domain accounts", "CredentialAccess", "Defender for Identity"),
    ("Mailbox forwarding rule created to external address", "Exfiltration", "Defender for Office 365"),
    ("Anomalous mass download from SharePoint", "Collection", "Defender for Cloud Apps"),
    ("Encoded PowerShell launched from Office process", "Execution", "Defender for Endpoint"),
    ("LSASS memory access by untrusted binary", "CredentialAccess", "Defender for Endpoint"),
    ("Impossible travel detected for privileged account", "InitialAccess", "Defender for Cloud Apps"),
    ("Scheduled task created for persistence", "Persistence", "Defender for Endpoint"),
    ("Suspicious inbox rule hiding security alerts", "DefenseEvasion", "Defender for Office 365"),
    ("Sign-in from anonymised IP address", "InitialAccess", "Entra ID Protection"),
    ("Unusual addition to privileged directory role", "PrivilegeEscalation", "Entra ID Protection"),
    ("Conditional Access policy modified out of hours", "DefenseEvasion", "Microsoft Sentinel"),
    ("Suspected Kerberoasting enumeration", "CredentialAccess", "Defender for Identity"),
    ("Malicious URL clicked in phishing campaign", "InitialAccess", "Defender for Office 365"),
    ("Registry run key persistence created", "Persistence", "Defender for Endpoint"),
    ("Data staged in unusual archive location", "Collection", "Defender for Endpoint"),
    ("Service principal credential added by non-admin", "Persistence", "Microsoft Sentinel"),
    ("Suspicious DNS queries to newly registered domain", "CommandAndControl", "Defender for Endpoint"),
    ("Brute force against VPN gateway", "CredentialAccess", "Microsoft Sentinel"),
]

TENANT = "00000000-0000-0000-0000-000000000000"
SEV_MIX = ["Critical"] * 3 + ["High"] * 9 + ["Medium"] * 14 + ["Low"] * 11 + ["Informational"] * 5


def la(columns, rows):
    return {"tables": [{
        "name": "PrimaryResult",
        "columns": [{"name": c, "type": "string"} for c in columns],
        "rows": rows,
    }]}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


INC_COLS = ["IncidentNumber", "Title", "Severity", "Status", "CreatedTime", "ClosedTime",
            "LastModifiedTime", "Owner", "Classification", "ClassificationReason",
            "IncidentUrl", "IncidentLink", "LinkTarget", "Tactics", "AlertProductNames"]


def build_incidents_24h():
    rows = []
    for i in range(42):
        num = 4100 + i
        created = NOW - timedelta(hours=rng.uniform(0.2, 23.5))
        title, tactic, product = TITLES[num % len(TITLES)]
        status = rng.choice(["New"] * 3 + ["Active"] * 3 + ["Closed"] * 4)
        sev = rng.choice(SEV_MIX)

        # Guarantee a couple of visible SLA breaches (Critical open >2h, High
        # open >8h) so the red warning state appears in screenshots rather than
        # depending on the dice.
        if i in (2, 9):
            sev, status = ("Critical", "Active") if i == 2 else ("High", "New")
            created = NOW - timedelta(hours=4.5 if i == 2 else 11.2)

        owner = rng.choice(ANALYSTS) if status != "New" and rng.random() > 0.25 else ""
        closed = iso(created + timedelta(hours=rng.uniform(0.5, 9))) if status == "Closed" else ""
        rows.append([
            num, title, sev, status, iso(created), closed,
            iso(created + timedelta(minutes=rng.randint(5, 240))), owner,
            "BenignPositive" if status == "Closed" else "",
            "SuspiciousButExpected" if status == "Closed" else "",
            f"https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/{num}",
            f"https://security.microsoft.com/incident2/{8000 + num}/overview?tid={TENANT}",
            "defender", json.dumps([tactic]), json.dumps([product]),
        ])
    rows.sort(key=lambda r: r[4], reverse=True)
    return la(INC_COLS, rows)


OPEN_COLS = ["IncidentNumber", "Title", "Severity", "Status", "CreatedTime", "LastModifiedTime",
             "Owner", "OwnerEmail", "IncidentUrl", "IncidentLink", "LinkTarget",
             "Tactics", "AlertProductNames"]


def build_open_incidents():
    rows = []
    for i in range(28):
        num = 4050 + i
        age_h = rng.choice([0.4, 0.9, 1.5, 2.6, 3.2, 5.0, 7.5, 9.1, 14.0, 26.0, 48.0, 71.0])
        created = NOW - timedelta(hours=age_h)
        title, tactic, product = TITLES[num % len(TITLES)]
        owner = rng.choice(ANALYSTS) if rng.random() > 0.3 else ""
        rows.append([
            num, title, rng.choice(["Critical"] * 2 + ["High"] * 5 + ["Medium"] * 6 + ["Low"] * 3),
            rng.choice(["New", "Active"]), iso(created),
            iso(created + timedelta(minutes=rng.randint(10, 300))),
            owner, owner,
            f"https://portal.azure.com/#asset/Microsoft_Azure_Security_Insights/Incident/{num}",
            f"https://security.microsoft.com/incident2/{8000 + num}/overview?tid={TENANT}",
            "defender", json.dumps([tactic]), json.dumps([product]),
        ])
    rows.sort(key=lambda r: r[4])
    return la(OPEN_COLS, rows)


def build_age_distribution():
    cols = ["IncidentNumber", "Title", "Severity", "Status", "CreatedTime", "LastModifiedTime", "Owner"]
    rows = []
    for i in range(22):
        num = 4020 + i
        created = NOW - timedelta(hours=rng.choice([1, 3, 6, 10, 18, 30, 50, 80, 120, 200]))
        title, _, _ = TITLES[num % len(TITLES)]
        rows.append([num, title, rng.choice(["Critical", "High", "Medium"]),
                     rng.choice(["New", "Active"]), iso(created),
                     iso(created + timedelta(hours=1)),
                     rng.choice(ANALYSTS) if rng.random() > 0.35 else ""])
    return la(cols, rows)


def build_metrics():
    tables = [("SecurityEvent", 41.2), ("CommonSecurityLog", 28.7), ("Syslog", 16.4),
              ("SigninLogs", 9.8), ("DeviceEvents", 7.1), ("AuditLogs", 4.3),
              ("DeviceNetworkEvents", 3.6), ("OfficeActivity", 2.9),
              ("AzureActivity", 1.4), ("DeviceProcessEvents", 0.9)]
    by_table = la(["DataType", "TotalGB"], [[n, v] for n, v in tables])
    trend = la(["Day", "DailyGB"], [
        [(NOW - timedelta(days=6 - d)).strftime("%Y-%m-%d"), round(rng.uniform(104, 131), 1)]
        for d in range(7)])
    return {"generatedAt": iso(NOW),
            "ingestionByTable": by_table["tables"],
            "ingestionTrend": trend["tables"]}


def build_trends():
    vol_rows = []
    for d in range(30):
        day = (NOW - timedelta(days=29 - d)).strftime("%Y-%m-%d")
        for sev, base in (("Critical", 1), ("High", 4), ("Medium", 7), ("Low", 5)):
            vol_rows.append([day, sev, max(0, base + rng.randint(-1, 3))])
    volume = la(["Day", "Severity", "Count"], vol_rows)

    mttr = la(["Day", "AvgHours", "MedianHours", "Closed"], [
        [(NOW - timedelta(days=29 - d)).strftime("%Y-%m-%d"),
         round(rng.uniform(2.4, 7.8), 2), round(rng.uniform(1.6, 5.2), 2),
         rng.randint(6, 19)] for d in range(30)])

    sla_rows = []
    for d in range(30):
        total = rng.randint(5, 14)
        breaches = rng.randint(0, 2)
        sla_rows.append([(NOW - timedelta(days=29 - d)).strftime("%Y-%m-%d"),
                         total, breaches, round(100.0 * (total - breaches) / total, 1)])
    sla = la(["Day", "Total", "Breaches", "CompliancePct"], sla_rows)

    backlog = la(["Day", "OpenCount", "Critical", "High"], [
        [(NOW - timedelta(days=29 - d)).strftime("%Y-%m-%d"),
         rng.randint(18, 34), rng.randint(0, 3), rng.randint(2, 8)] for d in range(30)])

    return {"generatedAt": iso(NOW), "incidentVolume": volume["tables"],
            "mttr": mttr["tables"], "slaCompliance": sla["tables"],
            "openBacklog": backlog["tables"]}


DATA = {
    "incidents.json": build_incidents_24h,
    "open-incidents.json": build_open_incidents,
    "age-distribution.json": build_age_distribution,
    "metrics.json": build_metrics,
    "trends.json": build_trends,
}

CSP = json.loads((PUBLIC / "staticwebapp.config.json").read_text(encoding="utf-8"))[
    "globalHeaders"]["Content-Security-Policy"]


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(PUBLIC), **kw)

    def _json(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/api/data/"):
            name = path.rsplit("/", 1)[-1]
            return self._json(DATA[name]()) if name in DATA else self._json({"error": "Not found"}, 404)
        if path == "/.auth/me":
            return self._json({"clientPrincipal": {
                "identityProvider": "aad", "userId": "0" * 32,
                "userDetails": "analyst@contoso.com",
                "userRoles": ["anonymous", "authenticated"]}})
        return super().do_GET()

    def end_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()

    def log_message(self, *a):
        pass


def main():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"mock dashboard on http://127.0.0.1:{PORT}/index.html  (synthetic data)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
