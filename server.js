const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// CONFIGURATION
// ============================================
const LOADER_SCRIPT_URL = "https://raw.githubusercontent.com/trianaq765-cmd/ultimate-hub/refs/heads/main/Protected_8691028334350802.lua.txt";
const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";
const DB_FILE = './keyDatabase.json';
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');

// ... (rate limiting, cors, security headers sama seperti sebelumnya)

// ============================================
// Rate Limiting
// ============================================
const rateLimitStore = {};
const blockedIPs = {};
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const BLOCK_DURATION = 5 * 60 * 1000;

function getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
}

function rateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    if (blockedIPs[ip] && blockedIPs[ip] > now) {
        const remainingTime = Math.ceil((blockedIPs[ip] - now) / 1000);
        return res.status(429).json({ error: "Too many requests", blocked: true, retryAfter: remainingTime });
    } else if (blockedIPs[ip]) {
        delete blockedIPs[ip];
    }
    
    if (!rateLimitStore[ip] || rateLimitStore[ip].resetTime < now) {
        rateLimitStore[ip] = { count: 1, resetTime: now + RATE_LIMIT_WINDOW };
    } else {
        rateLimitStore[ip].count++;
    }
    
    if (rateLimitStore[ip].count > RATE_LIMIT_MAX_REQUESTS) {
        blockedIPs[ip] = now + BLOCK_DURATION;
        return res.status(429).json({ error: "Rate limit exceeded", blocked: true, retryAfter: Math.ceil(BLOCK_DURATION / 1000) });
    }
    
    next();
}

// ============================================
// Middleware
// ============================================
app.use(cors({ origin: '*', methods: ['GET', 'POST'], allowedHeaders: ['Content-Type', 'UH-Executor', 'UH-Version', 'X-Executor', 'Authorization'] }));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimiter);
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// Database
// ============================================
let keyDatabase = {};

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            keyDatabase = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
            console.log(`[DB] Loaded ${Object.keys(keyDatabase).length} keys`);
        }
    } catch (error) {
        keyDatabase = {};
    }
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(keyDatabase, null, 2));
    } catch (error) {
        console.error('[DB] Save error:', error.message);
    }
}

loadDatabase();
setInterval(saveDatabase, 5 * 60 * 1000);
process.on('SIGINT', () => { saveDatabase(); process.exit(0); });
process.on('SIGTERM', () => { saveDatabase(); process.exit(0); });

// ============================================
// Helpers
// ============================================
function sanitizeString(str, maxLength = 100) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>\"'&]/g, '').substring(0, maxLength).trim();
}

function validateKey(key) {
    if (!key || typeof key !== 'string') return false;
    if (key.length < 5 || key.length > 100) return false;
    return /^[a-zA-Z0-9\-_]+$/.test(key);
}

function validateHWID(hwid) {
    if (!hwid || typeof hwid !== 'string') return false;
    if (hwid.length < 5 || hwid.length > 200) return false;
    return true;
}

function isRobloxExecutor(req) {
    const customHeaders = ['uh-executor', 'uh-version', 'x-executor'];
    for (const header of customHeaders) {
        if (req.headers[header]) return true;
    }
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    if (!userAgent) return true;
    const acceptHeader = req.headers['accept'] || '';
    if (acceptHeader.includes('text/html') && userAgent.includes('mozilla')) return false;
    return true;
}

// ============================================
// HTML - Not Authorized
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html><head><title>Unauthorized</title>
<style>*{margin:0;padding:0}body{background:#000;color:#fff;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;text-align:center}h1{font-size:2rem;margin-bottom:10px}p{color:#888}</style>
</head><body><div><h1>⛔ Not Authorized</h1><p>You are not allowed to view these files.</p></div></body></html>`;

// ============================================
// ROUTES
// ============================================

// Health
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

// Root
app.get('/', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).send(NOT_AUTHORIZED_HTML);
    }
    res.json({ status: 'online', service: 'Ultimate Hub', version: '9.2' });
});

// ============================================
// SCRIPT ENDPOINT - Fetch Loader dari GitHub
// ============================================
const scriptPaths = ['/script', '/api/script', '/loader', '/load', '/s'];

scriptPaths.forEach(path => {
    app.get(path, async (req, res) => {
        if (!isRobloxExecutor(req)) {
            return res.status(401).send(NOT_AUTHORIZED_HTML);
        }
        
        try {
            const response = await axios.get(LOADER_SCRIPT_URL, {
                timeout: 15000,
                headers: { 'User-Agent': 'UltimateHub/9.2' }
            });
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.send(response.data);
            
        } catch (error) {
            // Fallback jika fetch gagal
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(`loadstring(game:HttpGet("${LOADER_SCRIPT_URL}"))()`);
        }
    });
});

// ============================================
// API: Validate Key
// ============================================
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;

        if (!validateKey(key)) {
            return res.json({ valid: false, message: "Invalid key format!" });
        }
        
        if (!validateHWID(hwid)) {
            return res.json({ valid: false, message: "Invalid device!" });
        }

        // Cek di Work.ink
        let isValidKey = false;
        try {
            const workinkResponse = await axios.get(WORKINK_API + encodeURIComponent(key), { timeout: 10000 });
            if (workinkResponse.data?.valid === true) {
                isValidKey = true;
            }
        } catch (err) {
            console.log("[Work.ink] Error:", err.message);
        }

        if (!isValidKey) {
            return res.json({ valid: false, message: "Invalid key!" });
        }

        // Cek binding
        if (keyDatabase[key]) {
            if (keyDatabase[key].hwid !== hwid) {
                return res.json({
                    valid: false,
                    bound_to_other: true,
                    bound_user: keyDatabase[key].userName,
                    message: "Key bound to: " + keyDatabase[key].userName
                });
            }
            
            keyDatabase[key].lastUsed = Date.now();
            keyDatabase[key].useCount = (keyDatabase[key].useCount || 0) + 1;
            saveDatabase();
            
            return res.json({ valid: true, returning_user: true, message: "Welcome back!" });
        }

        // New binding
        keyDatabase[key] = {
            hwid,
            userId: sanitizeString(String(userId), 20),
            userName: sanitizeString(userName, 50),
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            ip: getRealIP(req)
        };
        saveDatabase();
        
        return res.json({ valid: true, new_binding: true, message: "Key registered!" });

    } catch (error) {
        return res.json({ valid: false, message: "Server error!" });
    }
});

// ============================================
// API: Check Key
// ============================================
app.post('/api/check', (req, res) => {
    const { key, hwid } = req.body;
    
    if (!validateKey(key)) {
        return res.json({ status: "error" });
    }

    if (keyDatabase[key]) {
        if (keyDatabase[key].hwid === hwid) {
            return res.json({ status: "verified", userName: keyDatabase[key].userName });
        }
        return res.json({ status: "bound_other", userName: keyDatabase[key].userName });
    }
    return res.json({ status: "new" });
});

// ============================================
// API: Bind Key
// ============================================
app.post('/api/bind', (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    
    if (!validateKey(key) || !validateHWID(hwid)) {
        return res.json({ success: false });
    }

    if (keyDatabase[key] && keyDatabase[key].hwid !== hwid) {
        return res.json({ success: false, message: "Already bound" });
    }

    keyDatabase[key] = { 
        hwid, 
        userId: sanitizeString(String(userId), 20), 
        userName: sanitizeString(userName, 50), 
        boundAt: Date.now(), 
        lastUsed: Date.now(), 
        useCount: 1,
        ip: getRealIP(req)
    };
    saveDatabase();
    
    return res.json({ success: true });
});

// ============================================
// API: Stats (Protected)
// ============================================
app.get('/api/stats', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    res.json({ totalKeys: Object.keys(keyDatabase).length, uptime: process.uptime() });
});

// Catch all
app.use('*', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found" });
});

// Cleanup
setInterval(() => {
    const now = Date.now();
    for (const ip in rateLimitStore) {
        if (rateLimitStore[ip].resetTime < now) delete rateLimitStore[ip];
    }
    for (const ip in blockedIPs) {
        if (blockedIPs[ip] < now) delete blockedIPs[ip];
    }
}, 10 * 60 * 1000);

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📜 Loader: ${LOADER_SCRIPT_URL}`);
});
