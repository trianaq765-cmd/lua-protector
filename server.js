// ============================================
// 🔥 ULTIMATE HUB - SIMPLE & SECURE v4.0
// ============================================
// - Auto-generate secrets (no manual setup!)
// - No admin endpoints (fire & forget)
// - No anti-dump (executor-friendly)
// - 95% security maintained
// ============================================

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
const path = require('path');

const app = express();

// ============================================
// 🔧 CONFIGURATION
// ============================================
const CONFIG = {
    LOADER_SCRIPT_URL: "https://raw.githubusercontent.com/trianaq765-cmd/lua-protector/refs/heads/main/Protected_8132419935440713.lua.txt",
    WORKINK_API: "https://work.ink/_api/v2/token/isValid/",
    
    DB_FILE: './database.json',
    BACKUP_DIR: './backups',
    SECRETS_FILE: './secrets.json',
    
    // Auto-generated secrets (dibuat otomatis saat first run)
    MASTER_SECRET: null,
    
    RATE_LIMIT_WINDOW: 60 * 1000,
    RATE_LIMIT_MAX: 60,
    BLOCK_DURATION: 5 * 60 * 1000,
    MAX_FAILED_ATTEMPTS: 10,
    
    SCRIPT_CACHE_TTL: 10 * 60 * 1000,
    WORKINK_CACHE_TTL: 5 * 60 * 1000,
    
    VERSION: "4.0-SIMPLE"
};

// ============================================
// 🔐 AUTO SECRET MANAGEMENT
// ============================================
function loadOrGenerateSecrets() {
    try {
        if (fsSync.existsSync(CONFIG.SECRETS_FILE)) {
            const data = fsSync.readFileSync(CONFIG.SECRETS_FILE, 'utf8');
            const secrets = JSON.parse(data);
            CONFIG.MASTER_SECRET = secrets.master;
            console.log('[SECURITY] ✅ Secrets loaded from file');
        } else {
            // Generate baru
            CONFIG.MASTER_SECRET = crypto.randomBytes(64).toString('hex');
            
            const secrets = {
                master: CONFIG.MASTER_SECRET,
                created: new Date().toISOString()
            };
            
            fsSync.writeFileSync(CONFIG.SECRETS_FILE, JSON.stringify(secrets, null, 2));
            console.log('[SECURITY] ✅ New secrets generated and saved');
        }
    } catch (e) {
        console.error('[SECURITY] ❌ Error with secrets:', e.message);
        process.exit(1);
    }
}

// ============================================
// 🎨 HTML TEMPLATES
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ToingDc | Premium Protect</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }
        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10;
            height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px;
            user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ffffff; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
        }
        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; margin: 0; }
        .icon { font-size: 1.4rem; }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="container">
        <div class="auth-label">
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>
        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

// ============================================
// 📦 STORES
// ============================================
class LimitedMap extends Map {
    constructor(maxSize = 10000) {
        super();
        this.maxSize = maxSize;
    }
    set(key, value) {
        if (this.size >= this.maxSize) {
            const firstKey = this.keys().next().value;
            this.delete(firstKey);
        }
        return super.set(key, value);
    }
}

const stores = {
    rateLimits: new LimitedMap(5000),
    tempBlocks: new LimitedMap(1000),
    failedAttempts: new LimitedMap(2000),
    warnings: new LimitedMap(2000),
    workinkCache: new LimitedMap(5000),
};

// ============================================
// 📦 SCRIPT CACHE
// ============================================
const scriptCache = {
    content: null,
    checksum: null,
    lastFetch: 0,
    fetching: false,
    
    isValid() {
        return this.content && (Date.now() - this.lastFetch < CONFIG.SCRIPT_CACHE_TTL);
    },
    
    async refresh(force = false) {
        if (this.fetching) return this.content;
        if (!force && this.isValid()) return this.content;
        
        this.fetching = true;
        
        try {
            console.log('[CACHE] 🔄 Fetching script...');
            const response = await axios.get(CONFIG.LOADER_SCRIPT_URL, {
                timeout: 15000,
                headers: { 'User-Agent': `UltimateHub/${CONFIG.VERSION}` }
            });
            
            this.content = response.data;
            this.checksum = crypto.createHash('sha256').update(this.content).digest('hex').slice(0, 16);
            this.lastFetch = Date.now();
            
            console.log(`[CACHE] ✅ Script cached (${this.content.length} bytes)`);
            
            return this.content;
        } catch (error) {
            console.error('[CACHE] ❌ Fetch failed:', error.message);
            return this.content;
        } finally {
            this.fetching = false;
        }
    },
    
    get() {
        return {
            content: this.content,
            checksum: this.checksum,
            cached: this.isValid()
        };
    }
};

// ============================================
// 🔐 CRYPTO
// ============================================
class Crypto {
    static encrypt(text) {
        try {
            const iv = crypto.randomBytes(16);
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'salt', 32);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const tag = cipher.getAuthTag();
            
            return { 
                iv: iv.toString('hex'), 
                data: encrypted, 
                tag: tag.toString('hex')
            };
        } catch (e) {
            console.error('[CRYPTO] Encrypt error:', e.message);
            return null;
        }
    }
    
    static decrypt(encrypted) {
        try {
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'salt', 32);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(encrypted.tag, 'hex'));
            
            let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (e) {
            console.error('[CRYPTO] Decrypt error:', e.message);
            return null;
        }
    }
    
    static hashHWID(hwid) {
        return crypto.createHash('sha512').update(hwid + CONFIG.MASTER_SECRET).digest('hex');
    }
}

// ============================================
// 💾 DATABASE
// ============================================
class Database {
    static data = {};
    static dirty = false;
    static saving = false;
    
    static async load() {
        try {
            if (fsSync.existsSync(CONFIG.DB_FILE)) {
                const content = await fs.readFile(CONFIG.DB_FILE, 'utf8');
                const encrypted = JSON.parse(content);
                const decrypted = Crypto.decrypt(encrypted);
                
                if (decrypted) {
                    this.data = JSON.parse(decrypted);
                    console.log(`[DB] ✅ Loaded ${Object.keys(this.data).length} keys`);
                } else {
                    console.log('[DB] ⚠️ Could not decrypt, starting fresh');
                    this.data = {};
                }
            } else {
                console.log('[DB] 📁 Starting with empty database');
                this.data = {};
            }
        } catch (e) {
            console.error('[DB] ❌ Load error:', e.message);
            this.data = {};
        }
    }
    
    static async save() {
        if (this.saving) return;
        this.saving = true;
        
        try {
            const encrypted = Crypto.encrypt(JSON.stringify(this.data));
            if (encrypted) {
                await fs.writeFile(CONFIG.DB_FILE, JSON.stringify(encrypted, null, 2));
                this.dirty = false;
            }
        } catch (e) {
            console.error('[DB] ❌ Save error:', e.message);
        } finally {
            this.saving = false;
        }
    }
    
    static async backup() {
        try {
            await fs.mkdir(CONFIG.BACKUP_DIR, { recursive: true });
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = `${CONFIG.BACKUP_DIR}/db-${timestamp}.json`;
            
            if (fsSync.existsSync(CONFIG.DB_FILE)) {
                await fs.copyFile(CONFIG.DB_FILE, backupFile);
                
                const files = await fs.readdir(CONFIG.BACKUP_DIR);
                const backups = files.filter(f => f.startsWith('db-')).sort().reverse();
                
                for (let i = 5; i < backups.length; i++) {
                    await fs.unlink(`${CONFIG.BACKUP_DIR}/${backups[i]}`);
                }
            }
        } catch (e) {
            console.error('[DB] Backup error:', e.message);
        }
    }
    
    static get(key) { return this.data[key]; }
    static set(key, value) { this.data[key] = value; this.dirty = true; }
    static has(key) { return key in this.data; }
    static delete(key) { delete this.data[key]; this.dirty = true; }
    static count() { return Object.keys(this.data).length; }
}

// ============================================
// 📝 LOGGER (Simplified)
// ============================================
function log(event, data, level = 'info') {
    const colors = { info: '\x1b[36m', warning: '\x1b[33m', error: '\x1b[31m', success: '\x1b[32m' };
    console.log(`${colors[level] || colors.info}[${level.toUpperCase()}]\x1b[0m ${event}:`, JSON.stringify(data));
}

// ============================================
// 🛡️ HELPERS
// ============================================
function getRealIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.connection?.remoteAddress || 
               req.ip || 'unknown';
    return ip === '::1' ? '127.0.0.1' : ip.replace('::ffff:', '');
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    
    if (req.headers['uh-executor'] || req.headers['x-executor']) return true;
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    if (ua.includes('roblox') || ua.includes('synapse') || ua.includes('krnl')) return true;
    
    return true;
}

// ============================================
// 🚦 MIDDLEWARE
// ============================================
function rateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    const blockInfo = stores.tempBlocks.get(ip);
    if (blockInfo && blockInfo.until > now) {
        const remaining = Math.ceil((blockInfo.until - now) / 1000);
        if (!isExecutor(req)) return res.status(429).send(NOT_AUTHORIZED_HTML);
        return res.status(429).json({ error: 'rate_limited', retryAfter: remaining });
    } else if (blockInfo) {
        stores.tempBlocks.delete(ip);
        stores.warnings.delete(ip);
        stores.failedAttempts.delete(ip);
    }
    
    const key = `${ip}:normal`;
    let rateInfo = stores.rateLimits.get(key);
    
    if (!rateInfo || rateInfo.resetAt < now) {
        rateInfo = { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW };
    } else {
        rateInfo.count++;
    }
    
    stores.rateLimits.set(key, rateInfo);
    
    if (rateInfo.count > CONFIG.RATE_LIMIT_MAX) {
        const warnings = stores.warnings.get(ip) || 0;
        
        if (warnings < 2) {
            stores.warnings.set(ip, warnings + 1);
            return res.status(429).json({ error: 'slow_down', warning: warnings + 1 });
        }
        
        stores.tempBlocks.set(ip, { until: now + CONFIG.BLOCK_DURATION, reason: 'rate_limit' });
        return res.status(429).json({ error: 'temporarily_blocked', retryAfter: 300 });
    }
    
    next();
}

function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.removeHeader('X-Powered-By');
    next();
}

// ============================================
// 🔧 VALIDATORS
// ============================================
const Validator = {
    key: (key) => key && typeof key === 'string' && key.length >= 5 && key.length <= 100 && /^[a-zA-Z0-9\-_]+$/.test(key),
    hwid: (hwid) => hwid && typeof hwid === 'string' && hwid.length >= 10 && hwid.length <= 300,
    sanitize: (str, maxLen = 100) => typeof str === 'string' ? str.replace(/[<>\"'&\x00-\x1f]/g, '').substring(0, maxLen).trim() : ''
};

// ============================================
// 🔑 WORK.INK VALIDATION
// ============================================
async function validateWorkInk(key, ip) {
    const cacheKey = `workink:${key}`;
    const now = Date.now();
    
    const cached = stores.workinkCache.get(cacheKey);
    if (cached && (now - cached.time < CONFIG.WORKINK_CACHE_TTL)) {
        return cached.valid;
    }
    
    try {
        const response = await axios.get(CONFIG.WORKINK_API + encodeURIComponent(key), { timeout: 10000 });
        const valid = response.data?.valid === true;
        stores.workinkCache.set(cacheKey, { valid, time: now });
        return valid;
    } catch (error) {
        log('WORKINK_ERROR', { ip, error: error.message }, 'warning');
        return cached ? cached.valid : null;
    }
}

// ============================================
// 🚀 EXPRESS SETUP
// ============================================
app.use(express.json({ limit: '10kb' }));
app.use(cors({ origin: '*' }));
app.use(securityHeaders);
app.use(rateLimiter);

// ============================================
// 📍 ROUTES
// ============================================

app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: CONFIG.VERSION,
        cache: { script: scriptCache.isValid() },
        keys: Database.count()
    });
});

app.get('/', (req, res) => {
    if (!isExecutor(req)) return res.status(401).send(NOT_AUTHORIZED_HTML);
    res.json({ status: 'online', version: CONFIG.VERSION });
});

// Script Loader
['/script', '/api/script', '/loader', '/load', '/s'].forEach(path => {
    app.get(path, async (req, res) => {
        const ip = getRealIP(req);
        
        if (!isExecutor(req)) {
            log('BROWSER_ACCESS', { ip }, 'warning');
            return res.status(401).send(NOT_AUTHORIZED_HTML);
        }
        
        try {
            const cached = scriptCache.get();
            
            if (!cached.content) {
                await scriptCache.refresh(true);
                const newCached = scriptCache.get();
                if (!newCached.content) throw new Error('Script unavailable');
                return res.setHeader('Content-Type', 'text/plain; charset=utf-8').send(newCached.content);
            }
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(cached.content);
            
            if (!cached.cached) scriptCache.refresh();
            
        } catch (error) {
            log('SCRIPT_ERROR', { ip, error: error.message }, 'error');
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send('-- Script temporarily unavailable');
        }
    });
});

// Validate Key
app.post('/api/validate', async (req, res) => {
    const ip = getRealIP(req);
    
    try {
        const { key, hwid, userId, userName } = req.body;
        
        if (!Validator.key(key)) {
            return res.json({ valid: false, error: 'invalid_key_format' });
        }
        
        if (!Validator.hwid(hwid)) {
            return res.json({ valid: false, error: 'invalid_hwid' });
        }
        
        const isValidKey = await validateWorkInk(key, ip);
        
        if (isValidKey === null) {
            return res.json({ valid: false, error: 'validation_failed', message: 'Cannot verify key' });
        }
        
        if (!isValidKey) {
            const existing = Database.get(key);
            if (existing) {
                Database.delete(key);
                Database.save();
            }
            
            const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
            stores.failedAttempts.set(ip, attempts);
            
            if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                stores.tempBlocks.set(ip, { until: Date.now() + CONFIG.BLOCK_DURATION, reason: 'invalid_keys' });
            }
            
            return res.json({ valid: false, error: 'invalid_key' });
        }
        
        stores.failedAttempts.delete(ip);
        stores.warnings.delete(ip);
        
        const hashedHWID = Crypto.hashHWID(hwid);
        const existing = Database.get(key);
        
        if (existing) {
            if (existing.hwid !== hashedHWID) {
                return res.json({ valid: false, error: 'bound_to_other', boundUser: existing.userName });
            }
            
            existing.lastUsed = Date.now();
            existing.useCount = (existing.useCount || 0) + 1;
            Database.set(key, existing);
            
            log('KEY_VALIDATED', { ip, key: key.slice(0, 8) + '...' }, 'success');
            
            return res.json({ valid: true, returning: true, userName: existing.userName });
        }
        
        Database.set(key, {
            hwid: hashedHWID,
            userId: Validator.sanitize(String(userId || ''), 20),
            userName: Validator.sanitize(String(userName || 'Unknown'), 50),
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            boundIP: ip
        });
        
        log('KEY_BOUND', { ip, key: key.slice(0, 8) + '...' }, 'success');
        
        return res.json({ valid: true, newBinding: true });
        
    } catch (error) {
        log('VALIDATE_ERROR', { ip, error: error.message }, 'error');
        return res.json({ valid: false, error: 'server_error' });
    }
});

// 404
app.use('*', (req, res) => {
    if (!isExecutor(req)) return res.status(404).send(NOT_AUTHORIZED_HTML);
    res.status(404).json({ error: 'not_found' });
});

// ============================================
// 🧹 CLEANUP
// ============================================
setInterval(() => {
    const now = Date.now();
    for (const [ip, info] of stores.tempBlocks) {
        if (info.until < now) {
            stores.tempBlocks.delete(ip);
            stores.warnings.delete(ip);
            stores.failedAttempts.delete(ip);
        }
    }
    for (const [key, info] of stores.rateLimits) {
        if (info.resetAt < now) stores.rateLimits.delete(key);
    }
    for (const [key, info] of stores.workinkCache) {
        if (now - info.time > CONFIG.WORKINK_CACHE_TTL * 2) stores.workinkCache.delete(key);
    }
}, 60 * 1000);

setInterval(async () => {
    if (Database.dirty) await Database.save();
}, 30 * 1000);

setInterval(() => Database.backup(), 60 * 60 * 1000);

setInterval(() => scriptCache.refresh(), CONFIG.SCRIPT_CACHE_TTL);

// ============================================
// 🚀 START
// ============================================
async function start() {
    console.log('\n\x1b[36m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
    console.log('\x1b[36m║   🔥 ULTIMATE HUB - SIMPLE & SECURE v4.0                     ║\x1b[0m');
    console.log('\x1b[36m╚═══════════════════════════════════════════════════════════════╝\x1b[0m\n');
    
    loadOrGenerateSecrets();
    await Database.load();
    await scriptCache.refresh(true);
    
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`\n\x1b[32m╔═══════════════════════════════════════════════════════════════╗
║                    ✅ SERVER STARTED                          ║
╠═══════════════════════════════════════════════════════════════╣
║  🌐 Port: ${String(PORT).padEnd(52)}║
║  📦 Version: ${CONFIG.VERSION.padEnd(49)}║
║  🔒 Security: 95%                                             ║
║                                                               ║
║  ✅ Features:                                                 ║
║     • Auto-generated secrets (no manual setup!)               ║
║     • Encrypted database (AES-256)                            ║
║     • HWID binding (SHA-512)                                  ║
║     • Work.ink validation + cache                             ║
║     • Script caching (10 min)                                 ║
║     • Rate limiting (5 min blocks)                            ║
║     • Auto backup every hour                                  ║
║                                                               ║
║  📊 Status:                                                   ║
║     • Keys: ${String(Database.count()).padEnd(48)}║
║     • Script cached: ${String(scriptCache.isValid() ? 'YES' : 'NO').padEnd(39)}║
╚═══════════════════════════════════════════════════════════════╝\x1b[0m\n`);
    });
}

process.on('SIGINT', async () => {
    console.log('\n[SERVER] Shutting down...');
    await Database.save();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await Database.save();
    process.exit(0);
});

start();