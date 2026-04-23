const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const PORT = 80;
const STATIC_DIR = path.join(__dirname, 'public');
const SCORES_FILE = '/data/scores.json';

const MIME = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
};

// ── Scores ──
function loadScores() {
    try {
        return JSON.parse(fs.readFileSync(SCORES_FILE, 'utf8'));
    } catch {
        return { alltime: [], daily: {} };
    }
}

function saveScores(data) {
    fs.mkdirSync(path.dirname(SCORES_FILE), { recursive: true });
    fs.writeFileSync(SCORES_FILE, JSON.stringify(data));
}

function todayKey() {
    return new Date().toISOString().slice(0, 10);
}

function cleanOldDays(daily) {
    const keys = Object.keys(daily).sort();
    while (keys.length > 7) delete daily[keys.shift()];
}

function handleScoresGet(res) {
    const data = loadScores();
    const today = todayKey();
    const body = JSON.stringify({
        alltime: (data.alltime || []).slice(0, 20),
        today: ((data.daily || {})[today] || []).slice(0, 10),
    });
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' });
    res.end(body);
}

function handleScoresPost(req, res) {
    let raw = '';
    req.on('data', c => { raw += c; if (raw.length > 1024) req.destroy(); });
    req.on('end', () => {
        try {
            const { name, score } = JSON.parse(raw);
            if (typeof score !== 'number' || score < 0 || score > 1e9) throw new Error('bad score');
            const safeName = String(name || 'φ operator').slice(0, 16).replace(/[<>&"']/g, '');
            const today = todayKey();
            const entry = { name: safeName, score: Math.floor(score), date: today };

            const data = loadScores();
            if (!data.alltime) data.alltime = [];
            if (!data.daily) data.daily = {};
            if (!data.daily[today]) data.daily[today] = [];

            data.alltime.push(entry);
            data.alltime.sort((a, b) => b.score - a.score);
            data.alltime = data.alltime.slice(0, 20);

            data.daily[today].push(entry);
            data.daily[today].sort((a, b) => b.score - a.score);
            data.daily[today] = data.daily[today].slice(0, 10);

            cleanOldDays(data.daily);
            saveScores(data);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true }));
        } catch {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'bad request' }));
        }
    });
}

// ── Static files ──
function serveStatic(req, res) {
    let urlPath = req.url.split('?')[0];
    if (urlPath === '/') urlPath = '/index.html';

    const ext = path.extname(urlPath);
    const filePath = path.join(STATIC_DIR, urlPath);

    // Prevent directory traversal
    if (!filePath.startsWith(STATIC_DIR)) {
        res.writeHead(403); res.end(); return;
    }

    fs.readFile(filePath, (err, data) => {
        if (err) {
            // SPA fallback
            fs.readFile(path.join(STATIC_DIR, 'index.html'), (err2, fallback) => {
                if (err2) { res.writeHead(404); res.end('not found'); return; }
                sendWithGzip(req, res, fallback, 'text/html');
            });
            return;
        }
        const mime = MIME[ext] || 'application/octet-stream';
        sendWithGzip(req, res, data, mime, ext === '.html' || ext === '.css' || ext === '.js');
    });
}

function sendWithGzip(req, res, data, mime, compressible) {
    const headers = { 'Content-Type': mime };
    if (mime !== 'text/html') headers['Cache-Control'] = 'public, max-age=3600';

    if (compressible && data.length > 256 && (req.headers['accept-encoding'] || '').includes('gzip')) {
        zlib.gzip(data, (err, compressed) => {
            if (err) { res.writeHead(200, headers); res.end(data); return; }
            headers['Content-Encoding'] = 'gzip';
            res.writeHead(200, headers);
            res.end(compressed);
        });
    } else {
        res.writeHead(200, headers);
        res.end(data);
    }
}

// ── Server ──
const server = http.createServer((req, res) => {
    // CORS for API
    if (req.url.startsWith('/api/')) {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
        if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    }

    if (req.url === '/api/scores' && req.method === 'GET') return handleScoresGet(res);
    if (req.url === '/api/scores' && req.method === 'POST') return handleScoresPost(req, res);

    serveStatic(req, res);
});

server.listen(PORT, () => console.log(`wfl-www listening on :${PORT}`));
