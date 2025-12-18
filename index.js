const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// ⚠️ GANTI URL INI SESUAI MILIKMU!
// ============================================
const CONFIG = {
    // URL GitHub Raw untuk loader.lua (SETELAH DI-OBFUSCATE)
    LOADER_URL: "https://raw.githubusercontent.com/trianaq765-cmd/ultimate-hub/main/loader.lua",
    
    // Versi
    VERSION: "9.3",
    
    // Secret keys
    SECRET_KEY: process.env.SECRET_KEY || crypto.randomBytes(64).toString('hex'),
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    ADMIN_SECRET: process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex')
};

// ============================================
// CRYPTO UTILS
// ============================================
class CryptoUtils {
    static hash(text) { 
        return crypto.createHash('sha256').update(text).digest('hex'); 
    }
}

// ============================================
// RATE LIMITING
// ============================================
const rateLimitStore = new Map();
const blockedIPs = new Map();
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX = 30;
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
    
    // Check if blocked
    const blockInfo = blockedIPs.get(ip);
    if (blockInfo && blockInfo.until > now) {
        return res.status(429).json({ 
            error: "Blocked", 
            retryAfter: Math.ceil((blockInfo.until - now) / 1000) 
        });
    } else if (blockInfo) {
        blockedIPs.delete(ip);
    }
    
    // Rate limit check
    let entry = rateLimitStore.get(ip);
    if (!entry || entry.windowStart < now - RATE_LIMIT_WINDOW) {
        entry = { count: 0, windowStart: now };
        rateLimitStore.set(ip, entry);
    }
    entry.count++;
    
    if (entry.count > RATE_LIMIT_MAX) {
        blockedIPs.set(ip, { until: now + BLOCK_DURATION });
        return res.status(429).json({ error: "Rate limit exceeded" });
    }
    
    next();
}

// ============================================
// MIDDLEWARE
// ============================================
app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST'], 
    allowedHeaders: ['Content-Type', 'UH-Executor', 'UH-Version', 'X-Executor', 'Authorization'] 
}));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimiter);
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// DATABASE - KEY STORAGE
// ============================================
const DB_FILE = './keyDatabase.json';
let keyDatabase = {};

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const data = fs.readFileSync(DB_FILE, 'utf8');
            keyDatabase = JSON.parse(data);
            console.log(`[DB] Loaded ${Object.keys(keyDatabase).length} keys`);
        }
    } catch (e) { 
        console.error('[DB] Error loading:', e.message);
        keyDatabase = {}; 
    }
}

function saveDatabase() {
    try { 
        fs.writeFileSync(DB_FILE, JSON.stringify(keyDatabase, null, 2)); 
    } catch (e) {
        console.error('[DB] Error saving:', e.message);
    }
}

// Auto-save every 5 minutes
setInterval(saveDatabase, 5 * 60 * 1000);

// Load on startup
loadDatabase();

// Save on shutdown
process.on('SIGINT', () => { saveDatabase(); process.exit(0); });
process.on('SIGTERM', () => { saveDatabase(); process.exit(0); });

// ============================================
// VALIDATION HELPERS
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
    return hwid.length >= 5 && hwid.length <= 300;
}

function hashKey(key) { 
    return CryptoUtils.hash(key).substring(0, 16); 
}

function hashHWID(hwid) { 
    return CryptoUtils.hash(hwid); 
}

// ============================================
// WORK.INK API - KEY VALIDATION
// ============================================
const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";

async function validateWithWorkInk(key) {
    try {
        const response = await axios.get(WORKINK_API + encodeURIComponent(key), { 
            timeout: 10000,
            headers: { 'User-Agent': 'UltimateHub/9.3' }
        });
        return response.data?.valid === true;
    } catch (error) { 
        console.log('[Work.ink] Error:', error.message);
        return false; 
    }
}

// ============================================
// EXECUTOR DETECTION
// ============================================
function isRobloxExecutor(req) {
    const customHeaders = ['uh-executor', 'uh-version', 'x-executor', 'syn-fingerprint', 'krnl-fingerprint', 'fluxus-fingerprint'];
    for (const h of customHeaders) { 
        if (req.headers[h]) return true; 
    }
    
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    if (!ua) return true;
    
    const executors = ['roblox', 'syn', 'krnl', 'fluxus', 'delta', 'scriptware'];
    for (const e of executors) { 
        if (ua.includes(e)) return true; 
    }
    
    const browsers = ['mozilla', 'chrome', 'safari', 'firefox', 'edge'];
    const isBrowser = browsers.some(b => ua.includes(b));
    const acceptHeader = req.headers['accept'] || '';
    
    if (acceptHeader.includes('text/html') && isBrowser) return false;
    return true;
}

// ============================================
// HTML PAGE - NOT AUTHORIZED
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Not Authorized</title>
<style>
*{box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
html{background:#000;min-height:100%}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:radial-gradient(circle at top,#141414 0%,#080808 45%,#000 100%);color:#fff;overflow-x:hidden}
body::before{content:"";position:fixed;inset:0;background:linear-gradient(120deg,transparent 30%,rgba(255,255,255,0.04),transparent 70%);animation:sweep 9s linear infinite;pointer-events:none}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(100%)}}
.container{text-align:center;padding:30px 24px}
.title{font-size:26px;font-weight:600;margin-bottom:18px;color:#ff4b4b}
.message{font-size:22px;font-weight:600;margin-bottom:14px}
.sub{font-size:15px;color:rgba(255,255,255,0.72)}
</style>
</head>
<body>
<div class="container">
<div class="title">⛔ Not Authorized ⛔</div>
<div class="message">You are not allowed to view these files.</div>
<div class="sub">Close this page & proceed.</div>
</div>
</body>
</html>`;

// ============================================
// 🚀 MINI LOADER - Panggil loader.lua dari GitHub
// ============================================
const MINI_LOADER = `loadstring(game:HttpGet("${CONFIG.LOADER_URL}"))()`;

// ============================================
// ROUTES
// ============================================

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: CONFIG.VERSION, 
        timestamp: Date.now(),
        totalKeys: Object.keys(keyDatabase).length
    });
});

// Root
app.get('/', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
    }
    res.json({ status: 'online', service: 'Ultimate Hub', version: CONFIG.VERSION });
});

// ============================================
// SCRIPT ENDPOINT - Return Mini Loader
// ============================================
const scriptPaths = ['/script', '/api/script', '/loader', '/load', '/s'];
scriptPaths.forEach(path => {
    app.get(path, (req, res) => {
        if (!isRobloxExecutor(req)) {
            return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
        }
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.send(MINI_LOADER);
    });
});

// ============================================
// 🔑 KEY VALIDATION API - ENDPOINT UTAMA!
// ============================================

// Validate Key - ENDPOINT INI DIPANGGIL DARI loader.lua
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;
        const ip = getRealIP(req);
        
        console.log(`[VALIDATE] Key attempt from ${userName} (${userId})`);
        
        // Input validation
        if (!validateKey(key)) {
            return res.json({ valid: false, message: "Invalid key format!" });
        }
        
        if (!validateHWID(hwid)) {
            return res.json({ valid: false, message: "Invalid device identifier!" });
        }

        const hashedKey = hashKey(key);
        const hashedHWID = hashHWID(hwid);
        const sanitizedUserName = sanitizeString(userName, 50);
        const sanitizedUserId = sanitizeString(String(userId), 20);

        // Validate with Work.ink API
        const isValid = await validateWithWorkInk(key);
        if (!isValid) {
            console.log(`[VALIDATE] Invalid key from ${userName}`);
            return res.json({ valid: false, message: "Invalid key!" });
        }

        // Check if key already bound to another user
        if (keyDatabase[hashedKey]) {
            const binding = keyDatabase[hashedKey];
            
            // Key bound to different HWID
            if (binding.hwid !== hashedHWID) {
                console.log(`[VALIDATE] Key already bound to ${binding.userName}`);
                return res.json({ 
                    valid: false, 
                    bound_to_other: true, 
                    bound_user: binding.userName, 
                    message: "Key bound to: " + binding.userName 
                });
            }
            
            // Same user returning
            binding.lastUsed = Date.now();
            binding.useCount = (binding.useCount || 0) + 1;
            saveDatabase();
            
            console.log(`[VALIDATE] Welcome back ${userName}`);
            return res.json({ 
                valid: true, 
                returning_user: true, 
                message: "Welcome back!" 
            });
        }

        // New key binding
        keyDatabase[hashedKey] = {
            hwid: hashedHWID,
            userId: sanitizedUserId,
            userName: sanitizedUserName,
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            ip: CryptoUtils.hash(ip)
        };
        
        saveDatabase();
        console.log(`[NEW KEY] ${hashedKey.substring(0, 8)}... -> ${sanitizedUserName}`);
        
        return res.json({ 
            valid: true, 
            new_binding: true, 
            message: "Key registered!" 
        });

    } catch (error) {
        console.error('[VALIDATE] Error:', error.message);
        return res.json({ valid: false, message: "Server error!" });
    }
});

// Check Key Status
app.post('/api/check', (req, res) => {
    try {
        const { key, hwid } = req.body;
        
        if (!validateKey(key)) {
            return res.json({ status: "error", message: "Invalid key format" });
        }
        
        const hashedKey = hashKey(key);
        const hashedHWID = hashHWID(hwid);
        
        if (keyDatabase[hashedKey]) {
            if (keyDatabase[hashedKey].hwid === hashedHWID) {
                return res.json({ 
                    status: "verified", 
                    userName: keyDatabase[hashedKey].userName 
                });
            }
            return res.json({ 
                status: "bound_other", 
                userName: keyDatabase[hashedKey].userName 
            });
        }
        
        return res.json({ status: "new" });
    } catch (error) {
        return res.json({ status: "error", message: "Server error" });
    }
});

// Bind Key
app.post('/api/bind', (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;
        
        if (!validateKey(key) || !validateHWID(hwid)) {
            return res.json({ success: false, message: "Invalid input" });
        }
        
        const hashedKey = hashKey(key);
        const hashedHWID = hashHWID(hwid);
        
        // Check if already bound to different user
        if (keyDatabase[hashedKey] && keyDatabase[hashedKey].hwid !== hashedHWID) {
            return res.json({ success: false, message: "Already bound" });
        }
        
        keyDatabase[hashedKey] = {
            hwid: hashedHWID,
            userId: sanitizeString(String(userId), 20),
            userName: sanitizeString(userName, 50),
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1
        };
        
        saveDatabase();
        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false, message: "Server error" });
    }
});

// ============================================
// ADMIN ENDPOINTS
// ============================================

// Stats (Protected)
app.get('/api/stats', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    res.json({ 
        totalKeys: Object.keys(keyDatabase).length, 
        uptime: process.uptime(),
        version: CONFIG.VERSION,
        loaderUrl: CONFIG.LOADER_URL
    });
});

// List Keys (Protected)
app.get('/api/keys', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    const keys = Object.entries(keyDatabase).map(([hash, data]) => ({
        keyHash: hash.substring(0, 8) + '...',
        userName: data.userName,
        boundAt: new Date(data.boundAt).toISOString(),
        lastUsed: new Date(data.lastUsed).toISOString(),
        useCount: data.useCount
    }));
    
    res.json({ keys });
});

// Delete Key (Protected)
app.delete('/api/keys/:keyHash', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    const { keyHash } = req.params;
    
    // Find and delete key that starts with this hash
    for (const key of Object.keys(keyDatabase)) {
        if (key.startsWith(keyHash)) {
            delete keyDatabase[key];
            saveDatabase();
            return res.json({ success: true, message: "Key deleted" });
        }
    }
    
    return res.json({ success: false, message: "Key not found" });
});

// ============================================
// CATCH ALL
// ============================================
app.use('*', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found" });
});

// ============================================
// CLEANUP INTERVAL
// ============================================
setInterval(() => {
    const now = Date.now();
    
    // Cleanup rate limit store
    for (const [ip, data] of rateLimitStore) {
        if (data.windowStart < now - 120000) {
            rateLimitStore.delete(ip);
        }
    }
    
    // Cleanup expired blocks
    for (const [ip, info] of blockedIPs) {
        if (info.until < now) {
            blockedIPs.delete(ip);
        }
    }
    
    console.log(`[Cleanup] RateLimit: ${rateLimitStore.size}, Blocked: ${blockedIPs.size}`);
}, 10 * 60 * 1000);

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Ultimate Hub Server V${CONFIG.VERSION}`);
    console.log(`📡 Running on port ${PORT}`);
    console.log(`📦 Loader URL: ${CONFIG.LOADER_URL}`);
    console.log(`🔐 Admin secret: ${CONFIG.ADMIN_SECRET.substring(0, 8)}...`);
    console.log(`💾 Database: ${Object.keys(keyDatabase).length} keys loaded`);
});
