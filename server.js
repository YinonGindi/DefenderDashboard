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
            identityRows,
            deviceRows,
            cloudAppRows,
            emailRows,
            sentinelRows,
            aiAgentRows,
            alertRows,
            incidentRows,
            openIncidentRows,
        ] = await Promise.all([
            // 1. Identities — distinct users
            safeKQL(`
                IdentityInfo
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

            // 6. AI Agents — distinct agents
            safeKQL(`
                AIAgentsInfo
                | where TimeGenerated > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by AIAgentId
                | summarize Count = dcount(AIAgentId)
            `),

            // 6. Alerts summary by severity
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

            // 7. Incidents by severity
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | summarize Incidents = dcount(IncidentNumber) by Severity
            `),

            // 8. Open incidents (not closed/resolved)
            safeKQL(`
                SecurityIncident
                | where CreatedTime > ago(${ago})
                | summarize arg_max(TimeGenerated,*) by IncidentName
                | where Status != "Closed"
                | summarize OpenCount = dcount(IncidentNumber)
            `),
        ]);

        const identities = parseInt(identityRows[0]?.Count) || 0;
        const devices    = parseInt(deviceRows[0]?.Count) || 0;
        const cloudApps  = parseInt(cloudAppRows[0]?.Count) || 0;
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
        const openIncidents  = parseInt(openIncidentRows[0]?.OpenCount) || 0;

        // Noise reduction: % of alerts reduced to incidents
        const noiseReduction = totalAlerts > 0
            ? Math.round((1 - totalIncidents / totalAlerts) * 100)
            : 0;
        // Correlation: % of alerts that are correlated into incidents
        const correlation = totalAlerts > 0
            ? Math.round((totalIncidents / totalAlerts) * 100)
            : 0;

        res.json({
            sources: { identities, devices, email, cloudApps, sentinelGB, aiAgents },
            header:  { totalAlerts, totalIncidents, openIncidents },
            stats:   { noiseReduction, correlation },
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
            sources: { identities: 0, devices: 0, email: 0, cloudApps: 0, sentinelGB: 0, aiAgents: 0 },
            header:  { totalAlerts: 0, totalIncidents: 0, openIncidents: 0 },
            stats:   { noiseReduction: 0, correlation: 0 },
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
