// KQL used by the dashboard when DATA_SOURCE=loganalytics.
//
// These are the same queries the Logic Apps run in blob mode, kept here so the
// two modes return identical shapes to the browser.
//
// Keep SLA thresholds in sync with SLA_HOURS in dashboard.html and with
// logicapp-teams-alerts.json.
//
// NOTE: 'latest' is a reserved token in KQL and must not be used as a let name.

const EXCLUDE_CORRELATION =
  "| where ModifiedBy <> 'Microsoft Defender XDR - alert correlation'";

// Resolve the best incident link.
//
// IncidentUrl points at the Azure portal Sentinel blade, which is on a clock:
// Sentinel in the Azure portal is unsupported after 2027-03-31. Once a
// workspace is onboarded to the unified Defender portal, Sentinel populates
// AdditionalData.providerIncidentUrl with the Defender deep link
// (https://security.microsoft.com/incident2/{id}/overview?tid={tenant}).
//
// DO NOT build this URL from IncidentNumber. The Defender XDR incident ID is a
// separate ID space -- measured in this workspace, IncidentNumber 2673 maps to
// Defender incident 8754. Constructing from IncidentNumber sends analysts to a
// DIFFERENT INCIDENT, which is worse than a dead link.
//
// ProviderIncidentId does match the Defender ID (verified 511/511 rows), so it
// is a safe fallback if providerIncidentUrl is ever absent -- e.g. rows created
// before onboarding, when ProviderName was 'Azure Sentinel'.
const DEFENDER_LINK = `
| extend _DefenderUrl = tostring(AdditionalData.providerIncidentUrl)
| extend _DefenderUrl = iff(isnotempty(_DefenderUrl), _DefenderUrl,
    iff(ProviderName == 'Microsoft XDR' and isnotempty(ProviderIncidentId),
        strcat('https://security.microsoft.com/incident2/', ProviderIncidentId, '/overview'),
        ''))
| extend IncidentLink = iff(isnotempty(_DefenderUrl), _DefenderUrl, IncidentUrl)
| extend LinkTarget = iff(isnotempty(_DefenderUrl), 'defender', 'azure')`;

const INCIDENTS_24H = `
SecurityIncident
| where TimeGenerated > ago(24h)
| where CreatedTime > ago(24h)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
${DEFENDER_LINK}
| project IncidentNumber, Title, Severity, Status, CreatedTime, ClosedTime, LastModifiedTime,
    Owner = tostring(Owner.userPrincipalName),
    Classification, ClassificationReason,
    IncidentUrl, IncidentLink, LinkTarget,
    Tactics = tostring(AdditionalData.tactics),
    AlertProductNames = tostring(AdditionalData.alertProductNames)
| order by CreatedTime desc`;

const OPEN_INCIDENTS = `
SecurityIncident
| where TimeGenerated > ago(90d)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != 'Closed'
${DEFENDER_LINK}
| project IncidentNumber, Title, Severity, Status, CreatedTime, LastModifiedTime,
    Owner = tostring(Owner.userPrincipalName),
    OwnerEmail = tostring(Owner.email),
    IncidentUrl, IncidentLink, LinkTarget,
    Tactics = tostring(AdditionalData.tactics),
    AlertProductNames = tostring(AdditionalData.alertProductNames)
| order by CreatedTime asc`;

const AGE_DISTRIBUTION = `
SecurityIncident
| where TimeGenerated > ago(90d)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status != 'Closed'
| where Severity !in ('Informational', 'Low')
| project IncidentNumber, Title, Severity, Status, CreatedTime, LastModifiedTime,
    Owner = tostring(Owner.userPrincipalName)
| order by LastModifiedTime desc`;

const INGESTION_BY_TABLE = `
Usage
| where TimeGenerated > ago(24h)
| where IsBillable == true
| summarize TotalGB = round(sum(Quantity) / 1024, 3) by DataType
| order by TotalGB desc`;

const INGESTION_TREND = `
Usage
| where TimeGenerated > ago(7d)
| where IsBillable == true
| summarize DailyGB = round(sum(Quantity) / 1024, 2)
    by Day = format_datetime(startofday(TimeGenerated), 'yyyy-MM-dd')
| order by Day asc`;

const TREND_VOLUME = `
SecurityIncident
| where TimeGenerated > ago(30d)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime > ago(30d)
| summarize Count = count()
    by Day = format_datetime(startofday(CreatedTime), 'yyyy-MM-dd'), Severity
| order by Day asc`;

const TREND_MTTR = `
SecurityIncident
| where TimeGenerated > ago(30d)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where Status == 'Closed' and isnotempty(ClosedTime)
| where ClosedTime > ago(30d)
| extend HoursToClose = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0
| where HoursToClose >= 0
| summarize AvgHours = round(avg(HoursToClose), 2),
            MedianHours = round(percentile(HoursToClose, 50), 2),
            Closed = count()
    by Day = format_datetime(startofday(ClosedTime), 'yyyy-MM-dd')
| order by Day asc`;

const TREND_SLA = `
SecurityIncident
| where TimeGenerated > ago(30d)
${EXCLUDE_CORRELATION}
| summarize arg_max(TimeGenerated, *) by IncidentNumber
| where CreatedTime > ago(30d)
| where Severity in ('Critical', 'High')
| extend SLAHours = iff(Severity == 'Critical', 2.0, 8.0)
| extend EndTime = iff(Status == 'Closed' and isnotempty(ClosedTime), ClosedTime, now())
| extend HoursOpen = datetime_diff('minute', EndTime, CreatedTime) / 60.0
| extend Breached = HoursOpen > SLAHours
| summarize Total = count(), Breaches = countif(Breached)
    by Day = format_datetime(startofday(CreatedTime), 'yyyy-MM-dd')
| extend CompliancePct = round(100.0 * (Total - Breaches) / Total, 1)
| order by Day asc`;

const TREND_BACKLOG = `
let inc = SecurityIncident
    | where TimeGenerated > ago(30d)
    ${EXCLUDE_CORRELATION}
    | summarize arg_max(TimeGenerated, *) by IncidentNumber
    | project CreatedTime, ClosedTime, Status, Severity
    | extend k = 1;
range Offset from 0 to 29 step 1
| extend Day = startofday(now()) - (29 - Offset) * 1d
| extend k = 1
| join kind=inner inc on k
| extend EndOfDay = Day + 1d
| where CreatedTime < EndOfDay
| where Status != 'Closed' or isnull(ClosedTime) or ClosedTime >= EndOfDay
| summarize OpenCount = count(),
            Critical = countif(Severity == 'Critical'),
            High = countif(Severity == 'High')
    by Day = format_datetime(Day, 'yyyy-MM-dd')
| order by Day asc`;

// Each dashboard file maps either to a single query (returned as the raw
// Log Analytics response) or to several named queries combined into one object.
module.exports = {
  'incidents.json':        { single: INCIDENTS_24H },
  'open-incidents.json':   { single: OPEN_INCIDENTS },
  'age-distribution.json': { single: AGE_DISTRIBUTION },
  'metrics.json': {
    composite: {
      ingestionByTable: INGESTION_BY_TABLE,
      ingestionTrend:   INGESTION_TREND
    }
  },
  'trends.json': {
    composite: {
      incidentVolume: TREND_VOLUME,
      mttr:           TREND_MTTR,
      slaCompliance:  TREND_SLA,
      openBacklog:    TREND_BACKLOG
    }
  }
};
