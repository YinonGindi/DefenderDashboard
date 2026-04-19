const express = require('express');
const path = require('path');
const { DefaultAzureCredential } = require('@azure/identity');

const app = express();
const PORT = process.env.PORT || 8080;

let credential;
const GRAPH_SCOPE = 'https://graph.microsoft.com/.default';
const HUNTING_URL = 'https://graph.microsoft.com/v1.0/security/runHuntingQuery';

function getCredential() {
    if (!credential) credential = new DefaultAzureCredential();
    return credential;
}

// ── Run a KQL hunting query via Graph Security API ──
async function runKQL(query) {
    const token = await getCredential().getToken(GRAPH_SCOPE);
    const res = await fetch(HUNTING_URL, {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${token.token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ Query: query }),
    });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`Hunting API ${res.status}: ${text.slice(0, 400)}`);
    }
    const data = await res.json();
    const cols = data.schema.map(c => c.name);
    return (data.results || []).map(row => {
        const obj = {};
        cols.forEach(col => { obj[col] = row[col]; });
        return obj;
    });
}

// ── Timeframe → KQL ago() string ──
function kqlAgo(tf) {
    const map = { '1h':'1h','4h':'4h','12h':'12h','24h':'24h','3d':'3d','7d':'7d','30d':'30d' };
    return map[tf] || '24h';
}

// ══════════════════════════════════════════════════════════
//  GET /api/dashboard?timeframe=24h
// ══════════════════════════════════════════════════════════
app.get('/api/dashboard', async (req, res) => {
    try {
        const tf = req.query.timeframe || '24h';
        const ago = kqlAgo(tf);

        // Run each query independently so one failure doesn't block others
        async function safeKQL(query) {
            try { return await runKQL(query); }
            catch (e) { console.error('KQL query failed:', e.message.slice(0, 200)); return []; }
        }

        const [
            cloudIdentityRows,
            hybridIdentityRows,
            onpremIdentityRows,
            deviceRows,
            cloudAppRows,
            oauthAppRows,
            emailRows,
            sentinelRows,
            aiAgentRows,
            alertRows,
            incidentRows,
            openIncidentRows,
            alertIncidentRows,
            workspaceRows,
            mttaRows,
            mttrRows,
        ] = await Promise.all([
            // 1a. Cloud Identities
            safeKQL(`
                IdentityInfo
                | summarize arg_max(Timestamp, *) by AccountObjectId, OnPremSid, CloudSid
                | where Timestamp > ago(14d)
                | where SourceProvider == 'AzureActiveDirectory'
                | summarize Count = dcount(AccountUpn)
            `),

            // 1b. Hybrid Identities
            safeKQL(`
                IdentityInfo
                | summarize arg_max(Timestamp, *) by AccountObjectId, OnPremSid, CloudSid
                | where Timestamp > ago(14d)
                | where SourceProvider == 'Hybrid'
                | summarize Count = dcount(AccountUpn)
            `),

            // 1c. On-Prem Identities
            safeKQL(`
                IdentityInfo
                | summarize arg_max(Timestamp, *) by AccountObjectId, OnPremSid, CloudSid
                | where Timestamp > ago(14d)
                | where SourceProvider == 'ActiveDirectory'
                | summarize Count = dcount(AccountUpn)
            `),

            // 2. Devices — distinct devices seen
            safeKQL(`
                DeviceInfo
                | where Timestamp > ago(${ago})
                | summarize Count = dcount(DeviceId)
            `),

            // 3. Cloud Apps — distinct apps observed
            safeKQL(`
                CloudAppEvents
                | where Timestamp > ago(${ago})
                | summarize Count = dcount(Application)
            `),

            // 3b. OAuth Apps
            safeKQL(`
                OAuthAppInfo
                | where TimeGenerated > ago(14d)
                | summarize Count = dcount(OAuthAppId)
            `),

            // 4. Email — distinct email events
            safeKQL(`
                EmailEvents
                | where Timestamp > ago(${ago})
                | summarize Count = count()
            `),

            // 5. Sentinel ingestion volume (GB)
            safeKQL(`
                Usage
                | where TimeGenerated > ago(${ago})
                | summarize GB = round(sum(Quantity) / 1024, 1)
            `),

            // 6. AI Agents — distinct agents (always 14d, not timeframe-dependent)
            safeKQL(`
                AIAgentsInfo
                | where TimeGenerated > ago(14d)
                | summarize arg_max(TimeGenerated,*) by AIAgentId
                | summarize Count = dcount(AIAgentId)
            `),

            // 6. Total alerts count and alerts by severity
            safeKQL(`
                AlertInfo
                | where Timestamp > ago(${ago})
                | summarize
                    TotalAlerts = dcount(AlertId),
                    High = dcountif(AlertId, Severity == "High"),
                    Medium = dcountif(AlertId, Severity == "Medium"),
                    Low = dcountif(AlertId, Severity == "Low"),
                    Informational = dcountif(AlertId, Severity == "Informational")
            `),

            // 7. Incidents by severity (all incidents)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | summarize Incidents = dcount(IncidentName) by Severity
            `),

            // 8. Open incidents (not closed/resolved, all incidents)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | where Status != "Closed"
                | summarize OpenCount = dcount(IncidentNumber)
            `),

            // 8b. Incidents with alerts (for noise reduction calc)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | where array_length(AlertIds) > 0
                | summarize Count = dcount(IncidentName)
            `),

            // 9. Workspace name
            safeKQL(`
                Usage
                | limit 1
                | project Workspace=split(ResourceUri,'/')[-1]
            `),

            // 10. MTTA — avg minutes from detection to assignment (last 7d, only with alerts)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(7d)
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | where array_length(AlertIds) > 0
                | where Status != "New"
                | where isnotempty(FirstModifiedTime)
                | extend MTTA_min = datetime_diff('minute', CreatedTime, FirstModifiedTime)
                | where MTTA_min >= 0
                | summarize AvgMTTA = avg(MTTA_min)
            `),

            // 11. MTTR — avg minutes from creation to closure (last 7d, only with alerts)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(7d)
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | where array_length(AlertIds) > 0
                | where Status == "Closed"
                | where isnotempty(ClosedTime)
                | extend MTTR_min = datetime_diff('minute', CreatedTime, ClosedTime)
                | where MTTR_min >= 0
                | summarize AvgMTTR = avg(MTTR_min)
            `),
        ]);

        const cloudIdentities  = parseInt(cloudIdentityRows[0]?.Count) || 0;
        const hybridIdentities = parseInt(hybridIdentityRows[0]?.Count) || 0;
        const onpremIdentities = parseInt(onpremIdentityRows[0]?.Count) || 0;
        const devices    = parseInt(deviceRows[0]?.Count) || 0;
        const cloudApps  = parseInt(cloudAppRows[0]?.Count) || 0;
        const oauthApps  = parseInt(oauthAppRows[0]?.Count) || 0;
        const email      = parseInt(emailRows[0]?.Count) || 0;
        const sentinelGB = parseFloat(sentinelRows[0]?.GB) || 0;
        const aiAgents   = parseInt(aiAgentRows[0]?.Count) || 0;

        const a = alertRows[0] || {};
        const totalAlerts = parseInt(a.TotalAlerts) || 0;
        const highAlerts  = parseInt(a.High) || 0;
        const medAlerts   = parseInt(a.Medium) || 0;
        const lowAlerts   = parseInt(a.Low) || 0;
        const infoAlerts  = parseInt(a.Informational) || 0;

        const sevMap = {};
        for (const row of incidentRows) {
            const sev = (row.Severity || '').toLowerCase();
            sevMap[sev] = parseInt(row.Incidents) || 0;
        }
        const totalIncidents = Object.values(sevMap).reduce((s, v) => s + v, 0);
        const incidentsWithAlerts = parseInt(alertIncidentRows[0]?.Count) || 0;
        const openIncidents  = parseInt(openIncidentRows[0]?.OpenCount) || 0;
        const workspaceName  = workspaceRows[0]?.Workspace || '';

        // Noise reduction: uses only incidents that have alerts
        const noiseReduction = totalAlerts > 0
            ? Math.max(0, Math.min(100, Math.round((1 - incidentsWithAlerts / totalAlerts) * 100)))
            : 0;
        // MTTA & MTTR in minutes (clamped to >= 0)
        const mttaMinutes = Math.max(0, parseFloat(mttaRows[0]?.AvgMTTA) || 0);
        const mttrMinutes = Math.max(0, parseFloat(mttrRows[0]?.AvgMTTR) || 0);

        res.json({
            sources: { cloudIdentities, hybridIdentities, onpremIdentities, devices, email, cloudApps, oauthApps, sentinelGB, aiAgents },
            header:  { totalAlerts, totalIncidents, openIncidents, workspaceName },
            stats:   { noiseReduction, mttaMinutes, mttrMinutes },
            incidents: {
                high:          { incidents: sevMap.high || 0,          alerts: highAlerts },
                medium:        { incidents: sevMap.medium || 0,        alerts: medAlerts },
                low:           { incidents: sevMap.low || 0,           alerts: lowAlerts },
                informational: { incidents: sevMap.informational || 0, alerts: infoAlerts },
            },
        });
    } catch (err) {
        console.error('Dashboard API error:', err.message);
        // Return zeros so the frontend still renders
        res.json({
            sources: { cloudIdentities: 0, hybridIdentities: 0, onpremIdentities: 0, devices: 0, email: 0, cloudApps: 0, oauthApps: 0, sentinelGB: 0, aiAgents: 0 },
            header:  { totalAlerts: 0, totalIncidents: 0, openIncidents: 0, workspaceName: '' },
            stats:   { noiseReduction: 0, mttaMinutes: 0, mttrMinutes: 0 },
            incidents: {
                high:          { incidents: 0, alerts: 0 },
                medium:        { incidents: 0, alerts: 0 },
                low:           { incidents: 0, alerts: 0 },
                informational: { incidents: 0, alerts: 0 },
            },
            error: err.message,
        });
    }
});

// Serve static frontend
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
    console.log(`Defender Dashboard → http://localhost:${PORT}`);
});
