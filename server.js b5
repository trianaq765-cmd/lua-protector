const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// SECURITY CONFIG
// ============================================
const SECURITY_CONFIG = {
    SECRET_KEY: process.env.SECRET_KEY || crypto.randomBytes(64).toString('hex'),
    ENCRYPTION_KEY: process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'),
    REQUEST_TIMEOUT: 30000,
    MAX_REQUESTS_PER_MINUTE: 20,
    BLOCK_DURATION: 10 * 60 * 1000, // 10 menit
    NONCE_EXPIRY: 60 * 1000, // 1 menit
    ENABLE_STRICT_MODE: true
};

// ============================================
// ENCRYPTION UTILITIES
// ============================================
class CryptoUtils {
    static algorithm = 'aes-256-gcm';
    
    static encrypt(text, key = SECURITY_CONFIG.ENCRYPTION_KEY) {
        const iv = crypto.randomBytes(16);
        const keyBuffer = Buffer.from(key.substring(0, 32).padEnd(32, '0'));
        const cipher = crypto.createCipheriv(this.algorithm, keyBuffer, iv);
        
        let encrypted = cipher.update(text, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        return {
            iv: iv.toString('hex'),
            encrypted: encrypted,
            authTag: authTag.toString('hex')
        };
    }
    
    static decrypt(encryptedData, key = SECURITY_CONFIG.ENCRYPTION_KEY) {
        try {
            const keyBuffer = Buffer.from(key.substring(0, 32).padEnd(32, '0'));
            const decipher = crypto.createDecipheriv(
                this.algorithm,
                keyBuffer,
                Buffer.from(encryptedData.iv, 'hex')
            );
            
            decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
            
            let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            
            return decrypted;
        } catch (error) {
            return null;
        }
    }
    
    static hash(text) {
        return crypto.createHash('sha256').update(text).digest('hex');
    }
    
    static hmac(text, key = SECURITY_CONFIG.SECRET_KEY) {
        return crypto.createHmac('sha256', key).update(text).digest('hex');
    }
    
    static generateNonce() {
        return crypto.randomBytes(16).toString('hex') + '_' + Date.now();
    }
    
    static verifyNonce(nonce, maxAge = SECURITY_CONFIG.NONCE_EXPIRY) {
        try {
            const parts = nonce.split('_');
            if (parts.length !== 2) return false;
            
            const timestamp = parseInt(parts[1]);
            if (isNaN(timestamp)) return false;
            
            return (Date.now() - timestamp) < maxAge;
        } catch {
            return false;
        }
    }
}

// ============================================
// ADVANCED RATE LIMITING
// ============================================
const rateLimitStore = new Map();
const blockedIPs = new Map();
const usedNonces = new Set();
const suspiciousActivity = new Map();

function getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
}

function advancedRateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    // Check if IP is blocked
    const blockInfo = blockedIPs.get(ip);
    if (blockInfo && blockInfo.until > now) {
        const remainingTime = Math.ceil((blockInfo.until - now) / 1000);
        console.log(`[BLOCKED] ${ip} - ${blockInfo.reason} - ${remainingTime}s remaining`);
        return res.status(429).json({ 
            error: "Access denied", 
            reason: blockInfo.reason,
            retryAfter: remainingTime 
        });
    } else if (blockInfo) {
        blockedIPs.delete(ip);
    }
    
    // Get or create rate limit entry
    let entry = rateLimitStore.get(ip);
    if (!entry || entry.windowStart < now - 60000) {
        entry = {
            count: 0,
            windowStart: now,
            endpoints: {},
            userAgents: new Set()
        };
        rateLimitStore.set(ip, entry);
    }
    
    entry.count++;
    entry.userAgents.add(req.headers['user-agent'] || 'none');
    
    // Track endpoint usage
    const endpoint = req.path;
    entry.endpoints[endpoint] = (entry.endpoints[endpoint] || 0) + 1;
    
    // Detect suspicious patterns
    let suspicionScore = 0;
    
    // Multiple user agents from same IP
    if (entry.userAgents.size > 3) {
        suspicionScore += 20;
    }
    
    // Too many validation attempts
    if (entry.endpoints['/api/validate'] > 10) {
        suspicionScore += 30;
    }
    
    // Rate exceeded
    if (entry.count > SECURITY_CONFIG.MAX_REQUESTS_PER_MINUTE) {
        suspicionScore += 40;
    }
    
    // Update suspicious activity
    const currentSuspicion = (suspiciousActivity.get(ip) || 0) + suspicionScore;
    suspiciousActivity.set(ip, currentSuspicion);
    
    // Block if too suspicious
    if (currentSuspicion > 100) {
        blockedIPs.set(ip, {
            until: now + SECURITY_CONFIG.BLOCK_DURATION,
            reason: "Suspicious activity detected"
        });
        console.log(`[SECURITY] Blocked ${ip} - Suspicion score: ${currentSuspicion}`);
        return res.status(429).json({ 
            error: "Access denied", 
            reason: "Security violation" 
        });
    }
    
    // Standard rate limit
    if (entry.count > SECURITY_CONFIG.MAX_REQUESTS_PER_MINUTE) {
        blockedIPs.set(ip, {
            until: now + SECURITY_CONFIG.BLOCK_DURATION,
            reason: "Rate limit exceeded"
        });
        return res.status(429).json({ 
            error: "Rate limit exceeded", 
            retryAfter: Math.ceil(SECURITY_CONFIG.BLOCK_DURATION / 1000)
        });
    }
    
    next();
}

// ============================================
// REQUEST SIGNATURE VERIFICATION
// ============================================
function verifyRequestSignature(req, res, next) {
    // Skip for non-API routes
    if (!req.path.startsWith('/api/')) {
        return next();
    }
    
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    
    // Strict mode requires all security headers
    if (SECURITY_CONFIG.ENABLE_STRICT_MODE) {
        if (!signature || !timestamp || !nonce) {
            // Allow fallback for legacy clients
            console.log(`[WARN] Missing security headers from ${getRealIP(req)}`);
            // Continue without signature verification for backward compatibility
            return next();
        }
        
        // Verify timestamp (prevent replay attacks)
        const requestTime = parseInt(timestamp);
        if (isNaN(requestTime) || Math.abs(Date.now() - requestTime) > 300000) { // 5 minutes
            return res.status(401).json({ 
                valid: false, 
                message: "Request expired" 
            });
        }
        
        // Verify nonce hasn't been used
        if (usedNonces.has(nonce)) {
            return res.status(401).json({ 
                valid: false, 
                message: "Duplicate request" 
            });
        }
        
        // Verify signature
        const payload = JSON.stringify(req.body) + timestamp + nonce;
        const expectedSignature = CryptoUtils.hmac(payload);
        
        if (signature !== expectedSignature) {
            console.log(`[SECURITY] Invalid signature from ${getRealIP(req)}`);
            return res.status(401).json({ 
                valid: false, 
                message: "Invalid signature" 
            });
        }
        
        // Store nonce to prevent replay
        usedNonces.add(nonce);
        
        // Clean old nonces periodically
        setTimeout(() => usedNonces.delete(nonce), SECURITY_CONFIG.NONCE_EXPIRY);
    }
    
    next();
}

// ============================================
// CORS & MIDDLEWARE
// ============================================
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: [
        'Content-Type', 
        'UH-Executor', 
        'UH-Version', 
        'X-Executor', 
        'Authorization',
        'X-Signature',
        'X-Timestamp',
        'X-Nonce',
        'X-Client-Hash'
    ],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(advancedRateLimiter);
app.use(verifyRequestSignature);

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// ENCRYPTED DATABASE
// ============================================
const DB_FILE = './keyDatabase.encrypted.json';
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');

let keyDatabase = {};

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const encryptedData = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
            const decrypted = CryptoUtils.decrypt(encryptedData);
            if (decrypted) {
                keyDatabase = JSON.parse(decrypted);
                console.log(`[DB] Loaded ${Object.keys(keyDatabase).length} keys (encrypted)`);
            }
        }
    } catch (error) {
        console.error('[DB] Error loading database:', error.message);
        keyDatabase = {};
    }
}

function saveDatabase() {
    try {
        const jsonData = JSON.stringify(keyDatabase);
        const encryptedData = CryptoUtils.encrypt(jsonData);
        fs.writeFileSync(DB_FILE, JSON.stringify(encryptedData, null, 2));
    } catch (error) {
        console.error('[DB] Error saving database:', error.message);
    }
}

// Auto-save every 5 minutes
setInterval(saveDatabase, 5 * 60 * 1000);

// Load database on startup
loadDatabase();

// Save on shutdown
process.on('SIGINT', () => {
    console.log('[DB] Saving database before shutdown...');
    saveDatabase();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('[DB] Saving database before shutdown...');
    saveDatabase();
    process.exit(0);
});

// ============================================
// INPUT VALIDATION
// ============================================
function sanitizeString(str, maxLength = 100) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>\"'&\x00-\x1F]/g, '').substring(0, maxLength).trim();
}

function validateKey(key) {
    if (!key || typeof key !== 'string') return false;
    if (key.length < 5 || key.length > 100) return false;
    return /^[a-zA-Z0-9\-_]+$/.test(key);
}

function validateHWID(hwid) {
    if (!hwid || typeof hwid !== 'string') return false;
    if (hwid.length < 10 || hwid.length > 300) return false;
    // Basic pattern check
    return /^[a-zA-Z0-9\-_]+$/.test(hwid);
}

function hashKey(key) {
    return CryptoUtils.hash(key).substring(0, 16);
}

function hashHWID(hwid) {
    return CryptoUtils.hash(hwid);
}

// ============================================
// WORK.INK API
// ============================================
const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";

async function validateWithWorkInk(key) {
    try {
        const response = await axios.get(WORKINK_API + encodeURIComponent(key), { 
            timeout: 10000,
            headers: { 'User-Agent': 'UltimateHub/9.3-Secure' }
        });
        return response.data && response.data.valid === true;
    } catch (error) {
        console.log("[Work.ink] Error:", error.message);
        return false;
    }
}

// ============================================
// EXECUTOR DETECTION
// ============================================
function isRobloxExecutor(req) {
    const customHeaders = [
        'uh-executor', 'uh-version', 'x-executor', 'roblox-id',
        'syn-fingerprint', 'exploitid', 'krnl-fingerprint',
        'fluxus-fingerprint', 'delta-fingerprint', 'script-ware-fingerprint',
        'x-client-hash'
    ];
    
    for (const header of customHeaders) {
        if (req.headers[header]) return true;
    }
    
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    
    if (!userAgent || userAgent.trim() === '') return true;
    
    const executorKeywords = [
        'roblox', 'syn', 'krnl', 'fluxus', 'delta', 'scriptware',
        'sentinel', 'jjsploit', 'oxygen', 'electron', 'comet', 'arceus'
    ];
    
    for (const keyword of executorKeywords) {
        if (userAgent.includes(keyword)) return true;
    }
    
    const browserSignatures = [
        'mozilla/5.0', 'chrome/', 'safari/', 'firefox/',
        'edge/', 'opera/', 'msie', 'trident/'
    ];
    
    let isBrowser = browserSignatures.some(sig => userAgent.includes(sig));
    const acceptHeader = req.headers['accept'] || '';
    
    if (acceptHeader.includes('text/html') && isBrowser) return false;
    if (!acceptHeader || !acceptHeader.includes('text/html')) return true;
    
    return !isBrowser;
}

// ============================================
// HTML PAGE: Not Authorized
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Not Authorized</title>
<style>
  * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
  html { background: #000000; min-height: 100%; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(circle at top, #141414 0%, #080808 45%, #000000 100%); color: #ffffff; overflow-x: hidden; }
  body::before { content: ""; position: fixed; inset: 0; background: linear-gradient(120deg, transparent 30%, rgba(255,255,255,0.04), transparent 70%); animation: sweep 9s linear infinite; pointer-events: none; }
  body::after { content: ""; position: fixed; inset: 0; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='120' height='120'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4'/%3E%3C/filter%3E%3Crect width='120' height='120' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E"); pointer-events: none; }
  @keyframes sweep { from { transform: translateX(-100%); } to { transform: translateX(100%); } }
  .container { position: relative; text-align: center; padding: 30px 24px; width: 163.7mm; max-width: 163.7mm; }
  .title { font-size: 26px; font-weight: 600; margin-bottom: 18px; color: #ff4b4b; }
  .title .icon { margin: 0 6px; text-shadow: none; }
  .title .text { text-shadow: 0 6px 24px rgba(255,0,0,0.35); }
  .message { font-size: 22px; font-weight: 600; line-height: 1.45; margin-bottom: 14px; text-shadow: 0 6px 26px rgba(0,0,0,0.75); }
  .sub { font-size: 15px; color: rgba(255,255,255,0.72); letter-spacing: 0.2px; }
</style>
<script>
  document.addEventListener('contextmenu', e => e.preventDefault());
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey && (e.key === 'u' || e.key === 's' || e.key === 'p')) e.preventDefault();
    if (e.key === 'F12') e.preventDefault();
  });
</script>
</head>
<body>
  <div class="container">
    <div class="title"><span class="icon">⛔</span><span class="text">Not Authorized</span><span class="icon">⛔</span></div>
    <div class="message">You are not allowed to view these files.</div>
    <div class="sub">Close this page & proceed.</div>
  </div>
</body>
</html>`;

// ============================================
// OBFUSCATED LOADER SCRIPT
// ============================================
const PROTECTED_LOADER_SCRIPT = `--[[
    Ultimate Hub V9.3 Secure Edition
    Protected with multi-layer security
    DO NOT REDISTRIBUTE
]]

local _0x = {
    _G = _G,
    getgenv = getgenv,
    pcall = pcall,
    loadstring = loadstring,
    game = game,
    task = task,
    os = os,
    string = string,
    table = table,
    type = type,
    tostring = tostring,
    tonumber = tonumber,
    pairs = pairs,
    ipairs = ipairs,
    math = math,
    coroutine = coroutine
}

local function _0xDEC(s)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    s = s:gsub('[^'..b..'=]', '')
    return (s:gsub('.', function(x)
        if x == '=' then return '' end
        local r,f = '', (b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if #x ~= 8 then return '' end
        local c = 0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

local function _0xENC(s)
    local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((s:gsub('.', function(x)
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then return '' end
        local c = 0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({'', '==', '='})[#s%3+1])
end

local function _0xHASH(str)
    local h = 5381
    for i = 1, #str do
        h = ((h * 33) + str:byte(i)) % 4294967296
    end
    return string.format("%08x", h)
end

local function _0xHMAC(str, key)
    local h1 = _0xHASH(key .. str)
    local h2 = _0xHASH(str .. key .. h1)
    return h2 .. _0xHASH(h1 .. h2)
end

if _0x.getgenv().UHLoaded then
    _0x.pcall(function() _0x.getgenv().UH:Destroy() end)
    _0x.pcall(function() _0x.game:GetService("CoreGui"):FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    _0x.pcall(function() _0x.game:GetService("CoreGui"):FindFirstChild("Rayfield"):Destroy() end)
    _0x.getgenv().UH, _0x.getgenv().UHCore, _0x.getgenv().UHLoaded = nil, nil, nil
    _0x.task.wait(0.3)
end
_0x.getgenv().UHLoaded = true

local _CFG = {
    _S = _0xDEC("aHR0cHM6Ly9sdWEtcHJvdGVjdG9yLXByb2R1Y3Rpb24udXAucmFpbHdheS5hcHA="),
    _V = _0xDEC("L2FwaS92YWxpZGF0ZQ=="),
    _C = _0xDEC("L2FwaS9jaGVjaw=="),
    _B = _0xDEC("L2FwaS9iaW5k"),
    _K = _0xDEC("aHR0cHM6Ly93b3JrLmluay8yOXB1L2tleS1zaXN0ZW0tMw=="),
    _U = _0xDEC("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3RyaWFuYXE3NjUtY21kL2xvb3RsYWJzLWtleXN5c3RlbS0vcmVmcy9oZWFkcy9tYWluL1Byb3RlY3RlZF8yMjYwMjQ5MDg2Mjk2MDYwLmx1YSUyMCgxKS50eHQ="),
    _SV = true,
    _KF = "UltimateHubKey.txt",
    _UF = "UltimateHubUser.txt",
    _MA = 5,
    _CT = 60,
    _1K1U = true,
    _VER = "9.3",
    _SK = nil
}

_CFG._SK = _0xHASH(_CFG._S .. _CFG._VER .. "ULTRA_SECRET_KEY_2024")

local _CA, _LAT = 0, 0
local _HS = _0x.game:GetService("HttpService")
local _TS = _0x.game:GetService("TweenService")
local _PL = _0x.game:GetService("Players")
local _CG = _0x.game:GetService("CoreGui")
local _SG = _0x.game:GetService("StarterGui")
local _LP = _PL.LocalPlayer

local function _SF(f, c)
    if writefile then _0x.pcall(writefile, f, c) end
end

local function _RF(f)
    if isfile and readfile then
        local s, r = _0x.pcall(function()
            if isfile(f) then return readfile(f) end
            return nil
        end)
        if s then return r end
    end
    return nil
end

local function _DF(f)
    if isfile and delfile then
        _0x.pcall(function()
            if isfile(f) then delfile(f) end
        end)
    end
end

local function _SC(t)
    if setclipboard then _0x.pcall(setclipboard, t) end
end

local function _GUI()
    local uid
    local funcs = {
        function() return gethwid and gethwid() end,
        function() return getexecutorhwid and getexecutorhwid() end,
        function() return syn and syn.cache_hwid and syn.cache_hwid() end,
        function() return fluxus and fluxus.get_hwid and fluxus.get_hwid() end,
        function() return get_hwid and get_hwid() end,
        function() return HWID and HWID() end,
        function() return getexecutorname and getexecutorname() .. "_" .. _LP.UserId end
    }
    
    for _, f in _0x.ipairs(funcs) do
        local s, r = _0x.pcall(f)
        if s and r and r ~= "" then
            uid = _0x.tostring(r)
            break
        end
    end
    
    if uid then
        return _0xHASH(uid .. "_" .. _LP.UserId)
    else
        return _0xHASH("NH_" .. _LP.UserId .. "_" .. _LP.Name)
    end
end

local function _ISC()
    return _CFG._S ~= "" and _CFG._S ~= nil
end

local function _DR(url, method, headers, body)
    headers = headers or {}
    headers["UH-Executor"] = "true"
    headers["UH-Version"] = _CFG._VER
    headers["X-Client-Hash"] = _0xHASH(_LP.UserId .. _CFG._SK)
    
    local ts = _0x.tostring(_0x.os.time())
    local nonce = _0xHASH(_0x.tostring(_0x.math.random(1000000, 9999999)) .. ts)
    
    headers["X-Timestamp"] = ts
    headers["X-Nonce"] = nonce
    
    if body then
        headers["X-Signature"] = _0xHMAC(body .. ts .. nonce, _CFG._SK)
    end
    
    local rf = (syn and syn.request) or request or http_request or (fluxus and fluxus.request) or (delta and delta.request)
    if rf then
        local s, r = _0x.pcall(function()
            return rf({Url = url, Method = method or "GET", Headers = headers, Body = body})
        end)
        if s and r then return r end
    end
    if method == "GET" or not method then
        local s, r = _0x.pcall(function()
            return _0x.game:HttpGet(url)
        end)
        if s then return {Body = r, StatusCode = 200} end
    end
    return nil
end

local function _CKB(key, uid)
    if not _ISC() then return true, "no_server", nil end
    
    local r = _DR(_CFG._S .. _CFG._C, "POST", {
        ["Content-Type"] = "application/json"
    }, _HS:JSONEncode({
        key = key,
        hwid = uid,
        userId = _LP.UserId,
        userName = _LP.Name,
        ts = _0x.os.time()
    }))
    
    if r and r.Body then
        local s, data = _0x.pcall(function()
            return _HS:JSONDecode(r.Body)
        end)
        
        if s and data then
            if data.status == "verified" then
                return true, "verified", data
            elseif data.status == "bound_other" then
                return false, "bound_other", data
            elseif data.status == "new" then
                return true, "new", nil
            end
        end
    end
    
    return true, "no_server", nil
end

local function _BKU(key, uid)
    if not _ISC() then return true end
    
    local r = _DR(_CFG._S .. _CFG._B, "POST", {
        ["Content-Type"] = "application/json"
    }, _HS:JSONEncode({
        key = key,
        hwid = uid,
        userId = _LP.UserId,
        userName = _LP.Name,
        boundAt = _0x.os.time(),
        boundDate = _0x.os.date("%Y-%m-%d %H:%M:%S")
    }))
    
    return r and (r.StatusCode == 200 or r.StatusCode == 201)
end

local function _OU(u)
    if not u or u == "" then return false end
    local funcs = {"openurl", "OpenURL", "open_url", "browseurl", "BrowseURL", "browse_url"}
    for _, n in _0x.ipairs(funcs) do
        local f = _0x.getgenv()[n] or getfenv()[n] or _G[n]
        if f and _0x.type(f) == "function" and _0x.pcall(f, u) then
            return true
        end
    end
    _0x.pcall(function() if syn and syn.open_browser then syn.open_browser(u) end end)
    _0x.pcall(function() if fluxus and fluxus.open_browser then fluxus.open_browser(u) end end)
    return false
end

local function _SN(t, x, d)
    _0x.pcall(function()
        _SG:SetCore("SendNotification", {Title = t or "Ultimate Hub", Text = x or "", Duration = d or 5})
    end)
end

local _KC = {}

local function _VK(k)
    if not k or k == "" then
        return false, "Please enter a key!"
    end
    k = k:gsub("^%s*(.-)%s*$", "%1")
    if #k < 5 then
        return false, "Key too short!"
    end
    
    if _KC[k] and (_0x.os.time() - _KC[k].time) < 300 then
        return _KC[k].valid, _KC[k].msg
    end
    
    local uid = _GUI()
    
    local s, r = _0x.pcall(function()
        local response = _DR(_CFG._S .. _CFG._V, "POST", {
            ["Content-Type"] = "application/json"
        }, _HS:JSONEncode({
            key = k,
            hwid = uid,
            userId = _LP.UserId,
            userName = _LP.Name,
            ts = _0x.os.time(),
            clientHash = _0xHASH(_LP.UserId .. _CFG._SK)
        }))
        
        if response and response.Body then
            return _HS:JSONDecode(response.Body)
        end
        return nil
    end)
    
    if s and r then
        if r.valid == true or r.success == true then
            if r.bound_to_other then
                local boundName = r.bound_user or "Unknown"
                _KC[k] = {valid = false, msg = "Key bound to: " .. boundName, time = _0x.os.time()}
                return false, "Key bound to: " .. boundName
            end
            
            local msg = r.message or "Key Valid!"
            if r.new_binding then
                msg = "Key Registered!"
            elseif r.returning_user then
                msg = "Welcome back!"
            end
            
            _KC[k] = {valid = true, msg = msg, time = _0x.os.time()}
            return true, msg
        else
            local errMsg = r.message or "Invalid key!"
            _KC[k] = {valid = false, msg = errMsg, time = _0x.os.time()}
            return false, errMsg
        end
    end
    
    local fallbackValid = false
    s, r = _0x.pcall(function()
        return _HS:JSONDecode(_0x.game:HttpGet(_0xDEC("aHR0cHM6Ly93b3JrLmluay9fYXBpL3YyL3Rva2VuL2lzVmFsaWQv") .. k))
    end)
    if s and r and r.valid == true then
        fallbackValid = true
    end
    
    if fallbackValid then
        if _CFG._1K1U then
            local canUse, status, bindData = _CKB(k, uid)
            if status == "bound_other" then
                local boundName = "Unknown"
                if bindData and bindData.userName then
                    boundName = bindData.userName
                end
                _KC[k] = {valid = false, msg = "Key bound to: " .. boundName, time = _0x.os.time()}
                return false, "Key bound to: " .. boundName
            elseif status == "new" then
                _BKU(k, uid)
            end
        end
        _KC[k] = {valid = true, msg = "Key Valid!", time = _0x.os.time()}
        return true, "Key Valid!"
    end
    
    _KC[k] = {valid = false, msg = "Invalid key!", time = _0x.os.time()}
    return false, "Invalid key!"
end

local function _CKS()
    _0x.pcall(function() if _0x.getgenv().UH then _0x.getgenv().UH:Destroy() end end)
    _0x.pcall(function() local k = _CG:FindFirstChild("UltimateHubKeySystem") if k then k:Destroy() end end)
    _0x.getgenv().UH = nil
    _0x.task.wait(0.1)
    
    if _CFG._SV then
        local sk = _RF(_CFG._KF)
        local su = _RF(_CFG._UF)
        local cu = _GUI()
        if sk and sk ~= "" then
            if _CFG._1K1U and su and su ~= cu then
                _DF(_CFG._KF)
                _DF(_CFG._UF)
                _SN("Ultimate Hub", "Key reset: Different device", 3)
            else
                _SN("Ultimate Hub", "Checking saved key...", 2)
                local v = _VK(sk)
                if v then
                    _SF(_CFG._UF, cu)
                    _SN("Ultimate Hub", "Key valid! Loading...", 2)
                    return true
                end
                _DF(_CFG._KF)
                _DF(_CFG._UF)
            end
        end
    end
    
    local SGui = Instance.new("ScreenGui")
    SGui.Name = "UltimateHubKeySystem"
    SGui.ResetOnSpawn = false
    SGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    local parentSuccess = _0x.pcall(function() SGui.Parent = _CG end)
    if not parentSuccess then
        _0x.pcall(function() SGui.Parent = _LP:WaitForChild("PlayerGui") end)
    end
    
    local BG = Instance.new("Frame")
    BG.Size = UDim2.new(1, 0, 1, 0)
    BG.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
    BG.BackgroundTransparency = 0.5
    BG.BorderSizePixel = 0
    BG.Parent = SGui
    
    local MF = Instance.new("Frame")
    MF.Size = UDim2.new(0, 360, 0, 220)
    MF.BackgroundColor3 = Color3.fromRGB(25, 25, 35)
    MF.BorderSizePixel = 0
    MF.AnchorPoint = Vector2.new(0.5, 0.5)
    MF.Position = UDim2.new(0.5, 0, 0.5, 0)
    MF.Parent = SGui
    
    local MFCorner = Instance.new("UICorner", MF)
    MFCorner.CornerRadius = UDim.new(0, 12)
    
    local MS = Instance.new("UIStroke", MF)
    MS.Color = Color3.fromRGB(100, 100, 255)
    MS.Thickness = 2
    
    local TB = Instance.new("Frame")
    TB.Size = UDim2.new(1, 0, 0, 45)
    TB.BackgroundColor3 = Color3.fromRGB(30, 30, 45)
    TB.BorderSizePixel = 0
    TB.Parent = MF
    
    local TBCorner = Instance.new("UICorner", TB)
    TBCorner.CornerRadius = UDim.new(0, 12)
    
    local TBF = Instance.new("Frame")
    TBF.Size = UDim2.new(1, 0, 0, 15)
    TBF.Position = UDim2.new(0, 0, 1, -15)
    TBF.BackgroundColor3 = Color3.fromRGB(30, 30, 45)
    TBF.BorderSizePixel = 0
    TBF.Parent = TB
    
    local TL = Instance.new("TextLabel")
    TL.Size = UDim2.new(1, -20, 0, 25)
    TL.Position = UDim2.new(0, 10, 0, 5)
    TL.BackgroundTransparency = 1
    TL.Text = "🔐 Ultimate Hub V" .. _CFG._VER
    TL.TextColor3 = Color3.fromRGB(255, 255, 255)
    TL.TextSize = 18
    TL.Font = Enum.Font.GothamBold
    TL.TextXAlignment = Enum.TextXAlignment.Center
    TL.Parent = TB
    
    local bs, sc
    if _ISC() then
        bs = "🔒 Secure Server (Active)"
        sc = Color3.fromRGB(100, 255, 100)
    else
        bs = "⚠️ Server Not Configured"
        sc = Color3.fromRGB(255, 200, 100)
    end
    
    local ST = Instance.new("TextLabel")
    ST.Size = UDim2.new(1, -20, 0, 15)
    ST.Position = UDim2.new(0, 10, 0, 28)
    ST.BackgroundTransparency = 1
    ST.Text = bs
    ST.TextColor3 = sc
    ST.TextSize = 10
    ST.Font = Enum.Font.Gotham
    ST.TextXAlignment = Enum.TextXAlignment.Center
    ST.Parent = TB
    
    local UI = Instance.new("TextLabel")
    UI.Size = UDim2.new(1, 0, 0, 15)
    UI.Position = UDim2.new(0, 0, 0, 50)
    UI.BackgroundTransparency = 1
    UI.Text = "👤 " .. _LP.Name .. " (ID: " .. _LP.UserId .. ")"
    UI.TextColor3 = Color3.fromRGB(120, 120, 140)
    UI.TextSize = 10
    UI.Font = Enum.Font.Gotham
    UI.Parent = MF
    
    local IC = Instance.new("Frame")
    IC.Size = UDim2.new(0, 320, 0, 40)
    IC.Position = UDim2.new(0.5, -160, 0, 70)
    IC.BackgroundColor3 = Color3.fromRGB(35, 35, 45)
    IC.BorderSizePixel = 0
    IC.Parent = MF
    
    local ICCorner = Instance.new("UICorner", IC)
    ICCorner.CornerRadius = UDim.new(0, 8)
    
    local IS = Instance.new("UIStroke", IC)
    IS.Color = Color3.fromRGB(60, 60, 80)
    IS.Thickness = 1
    
    local KI = Instance.new("TextBox")
    KI.Size = UDim2.new(1, -16, 1, 0)
    KI.Position = UDim2.new(0, 8, 0, 0)
    KI.BackgroundTransparency = 1
    KI.Text = ""
    KI.PlaceholderText = "Paste your key here..."
    KI.PlaceholderColor3 = Color3.fromRGB(100, 100, 100)
    KI.TextColor3 = Color3.fromRGB(255, 255, 255)
    KI.TextSize = 13
    KI.Font = Enum.Font.Gotham
    KI.ClearTextOnFocus = false
    KI.Parent = IC
    
    local STL = Instance.new("TextLabel")
    STL.Size = UDim2.new(1, -40, 0, 25)
    STL.Position = UDim2.new(0, 20, 0, 115)
    STL.BackgroundTransparency = 1
    STL.Text = ""
    STL.TextColor3 = Color3.fromRGB(255, 100, 100)
    STL.TextSize = 11
    STL.Font = Enum.Font.Gotham
    STL.TextXAlignment = Enum.TextXAlignment.Center
    STL.TextWrapped = true
    STL.Parent = MF
    
    local SB = Instance.new("TextButton")
    SB.Size = UDim2.new(0, 155, 0, 36)
    SB.Position = UDim2.new(0.5, -160, 0, 145)
    SB.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
    SB.BorderSizePixel = 0
    SB.Text = "✓ Validate Key"
    SB.TextColor3 = Color3.fromRGB(255, 255, 255)
    SB.TextSize = 13
    SB.Font = Enum.Font.GothamBold
    SB.Parent = MF
    
    local SBCorner = Instance.new("UICorner", SB)
    SBCorner.CornerRadius = UDim.new(0, 8)
    
    local GK = Instance.new("TextButton")
    GK.Size = UDim2.new(0, 155, 0, 36)
    GK.Position = UDim2.new(0.5, 5, 0, 145)
    GK.BackgroundColor3 = Color3.fromRGB(88, 101, 242)
    GK.BorderSizePixel = 0
    GK.Text = "🔑 Get Key"
    GK.TextColor3 = Color3.fromRGB(255, 255, 255)
    GK.TextSize = 13
    GK.Font = Enum.Font.GothamBold
    GK.Parent = MF
    
    local GKCorner = Instance.new("UICorner", GK)
    GKCorner.CornerRadius = UDim.new(0, 8)
    
    local BIC = Instance.new("Frame")
    BIC.Size = UDim2.new(1, -20, 0, 20)
    BIC.Position = UDim2.new(0, 10, 1, -25)
    BIC.BackgroundTransparency = 1
    BIC.Parent = MF
    
    local AL = Instance.new("TextLabel")
    AL.Size = UDim2.new(0.5, 0, 1, 0)
    AL.BackgroundTransparency = 1
    AL.Text = "Attempts: 0/" .. _CFG._MA
    AL.TextColor3 = Color3.fromRGB(100, 100, 100)
    AL.TextSize = 10
    AL.Font = Enum.Font.Gotham
    AL.TextXAlignment = Enum.TextXAlignment.Left
    AL.Parent = BIC
    
    local CRL = Instance.new("TextLabel")
    CRL.Size = UDim2.new(0.5, 0, 1, 0)
    CRL.Position = UDim2.new(0.5, 0, 0, 0)
    CRL.BackgroundTransparency = 1
    CRL.Text = "by ToingDC"
    CRL.TextColor3 = Color3.fromRGB(70, 70, 80)
    CRL.TextSize = 10
    CRL.Font = Enum.Font.Gotham
    CRL.TextXAlignment = Enum.TextXAlignment.Right
    CRL.Parent = BIC
    
    MF.Size = UDim2.new(0, 0, 0, 0)
    _TS:Create(MF, TweenInfo.new(0.35, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {Size = UDim2.new(0, 360, 0, 220)}):Play()
    
    local kv = false
    local vc = Instance.new("BindableEvent")
    local ip = false
    
    local function CloseGUI()
        _TS:Create(MF, TweenInfo.new(0.25, Enum.EasingStyle.Back, Enum.EasingDirection.In), {Size = UDim2.new(0, 0, 0, 0)}):Play()
        _TS:Create(BG, TweenInfo.new(0.25), {BackgroundTransparency = 1}):Play()
        _0x.task.wait(0.25)
        SGui:Destroy()
    end
    
    local function SK()
        if ip then return end
        ip = true
        local ik = KI.Text:gsub("^%s*(.-)%s*$", "%1")
        if ik == "" then
            STL.Text = "⚠️ Please enter a key!"
            STL.TextColor3 = Color3.fromRGB(255, 200, 100)
            ip = false
            return
        end
        if _CA >= _CFG._MA then
            local tl = _CFG._CT - (_0x.os.time() - _LAT)
            if tl > 0 then
                STL.Text = "⏳ Wait " .. tl .. " seconds..."
                STL.TextColor3 = Color3.fromRGB(255, 100, 100)
                ip = false
                return
            else
                _CA = 0
            end
        end
        STL.Text = "🔄 Connecting to server..."
        STL.TextColor3 = Color3.fromRGB(255, 255, 100)
        SB.Text = "..."
        SB.BackgroundColor3 = Color3.fromRGB(100, 100, 100)
        
        _0x.task.spawn(function()
            _0x.task.wait(0.3)
            local v, m = _VK(ik)
            if v then
                STL.Text = "✅ " .. m
                STL.TextColor3 = Color3.fromRGB(100, 255, 100)
                SB.Text = "✓ Success!"
                SB.BackgroundColor3 = Color3.fromRGB(80, 200, 80)
                if _CFG._SV then
                    _SF(_CFG._KF, ik)
                    _SF(_CFG._UF, _GUI())
                end
                _0x.task.wait(1.2)
                CloseGUI()
                kv = true
                vc:Fire()
            else
                _CA = _CA + 1
                _LAT = _0x.os.time()
                STL.Text = "❌ " .. m
                STL.TextColor3 = Color3.fromRGB(255, 100, 100)
                SB.Text = "✓ Validate Key"
                SB.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
                AL.Text = "Attempts: " .. _CA .. "/" .. _CFG._MA
                local op = IC.Position
                for i = 1, 4 do
                    if i % 2 == 0 then
                        IC.Position = op + UDim2.new(0, 6, 0, 0)
                    else
                        IC.Position = op + UDim2.new(0, -6, 0, 0)
                    end
                    _0x.task.wait(0.04)
                end
                IC.Position = op
                IS.Color = Color3.fromRGB(255, 80, 80)
                _0x.task.wait(0.5)
                IS.Color = Color3.fromRGB(60, 60, 80)
                ip = false
            end
        end)
    end
    
    SB.MouseEnter:Connect(function()
        _TS:Create(SB, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(100, 140, 255)}):Play()
    end)
    SB.MouseLeave:Connect(function()
        _TS:Create(SB, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(80, 120, 255)}):Play()
    end)
    GK.MouseEnter:Connect(function()
        _TS:Create(GK, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(108, 121, 255)}):Play()
    end)
    GK.MouseLeave:Connect(function()
        _TS:Create(GK, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(88, 101, 242)}):Play()
    end)
    
    SB.MouseButton1Click:Connect(SK)
    KI.FocusLost:Connect(function(e)
        if e then SK() end
    end)
    GK.MouseButton1Click:Connect(function()
        if _OU(_CFG._K) then
            STL.Text = "🌐 Browser opened!"
            STL.TextColor3 = Color3.fromRGB(100, 255, 100)
        else
            _SC(_CFG._K)
            STL.Text = "📋 Link copied!"
            STL.TextColor3 = Color3.fromRGB(100, 200, 255)
        end
    end)
    
    vc.Event:Wait()
    vc:Destroy()
    return kv
end

local function _LH()
    local C = _0x.getgenv().UHCore
    if not C then
        _0x.pcall(function()
            _0x.loadstring(_0x.game:HttpGet(_CFG._U))()
        end)
        _0x.task.wait(0.5)
        C = _0x.getgenv().UHCore
        if not C then return end
    end
    _0x.pcall(function()
        _CG:FindFirstChild("UltimateHubKeySystem"):Destroy()
    end)
    _0x.task.wait(0.2)
    
    local S = C.S
    local R
    local loadSuccess = _0x.pcall(function()
        R = _0x.loadstring(_0x.game:HttpGet(_0xDEC("aHR0cHM6Ly9zaXJpdXMubWVudS9yYXlmaWVsZA==")))()
    end)
    if not loadSuccess or not R then return end
    
    R.Notify = function() end
    local W = R:CreateWindow({
        Name = "Ultimate Hub V" .. _CFG._VER .. " | ToingDC",
        LoadingTitle = "Ultimate Hub",
        LoadingSubtitle = "by ToingDC",
        ConfigurationSaving = {Enabled = false},
        KeySystem = false
    })
    _0x.getgenv().UH = W
    
    local E = W:CreateTab("ESP", 4483362458)
    E:CreateSection("Player ESP")
    E:CreateToggle({Name = "Killer ESP", CurrentValue = false, Callback = function(v) if v then C.StartKillerESP() else C.StopKillerESP() end end})
    E:CreateToggle({Name = "Survivor ESP", CurrentValue = false, Callback = function(v) if v then C.StartSurvivorESP() else C.StopSurvivorESP() end end})
    E:CreateSection("Object ESP")
    E:CreateToggle({Name = "Generator ESP", CurrentValue = false, Callback = function(v) if v then C.StartGenESP() else C.StopGenESP() end end})
    E:CreateToggle({Name = "Pallet ESP", CurrentValue = false, Callback = function(v) if v then C.StartPalletESP() else C.StopPalletESP() end end})
    
    local SV = W:CreateTab("Survivor", 4483362458)
    SV:CreateSection("Environment")
    SV:CreateToggle({Name = "No Fog", CurrentValue = false, Callback = function(v) if v then C.StartNoFog() else C.StopNoFog() end end})
    SV:CreateToggle({Name = "Fullbright", CurrentValue = false, Callback = function(v) C.SetFullbright(v) end})
    SV:CreateSection("Auto Scripts")
    SV:CreateButton({Name = "Load Auto Generator", Callback = function() C.LoadScript(_0xDEC("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3RyaWFuYXE3NjUtY21kL1ZEL3JlZnMvaGVhZHMvbWFpbi9nZW5l")) end})
    SV:CreateButton({Name = "Load Auto Heal", Callback = function() C.LoadScript(_0xDEC("aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL3RyaWFuYXE3NjUtY21kL1ZEL3JlZnMvaGVhZHMvbWFpbi9hdXRvJTIwaGVhbA==")) end})
    SV:CreateSection("Performance")
    SV:CreateToggle({Name = "Anti-Lag Mode", CurrentValue = false, Callback = function(v) if v then C.StartAntiLag() else C.StopAntiLag() end end})
    
    local K = W:CreateTab("Killer", 4483362458)
    K:CreateSection("Auto Attack")
    K:CreateToggle({Name = "Enable Auto Attack", CurrentValue = false, Callback = function(v) if v then C.StartAutoAttack() else C.StopAutoAttack() end end})
    K:CreateSlider({Name = "Attack Distance", Range = {5, 30}, Increment = 1, CurrentValue = 15, Callback = function(v) S.Kil.AD = v end})
    K:CreateSection("Protection")
    K:CreateToggle({Name = "Anti-Blind", CurrentValue = false, Callback = function(v) if v then C.StartAntiBlind() else C.StopAntiBlind() end end})
    K:CreateSection("Camera Mode")
    K:CreateDropdown({Name = "Camera View", Options = {"Default", "FirstPerson", "ThirdPerson"}, CurrentOption = {"Default"}, Callback = function(o) if o and #o > 0 then C.SetCameraMode(o[1]) end end})
    
    local P = W:CreateTab("Player", 4483362458)
    P:CreateSection("Speed Boost")
    local SPL = P:CreateLabel("Speed: " .. S.Plr.SP)
    P:CreateButton({Name = "Speed -1", Callback = function() S.Plr.SP = _0x.math.max(16, S.Plr.SP - 1) SPL:Set("Speed: " .. S.Plr.SP) if S.Plr.SO then C.ApplySpeed() end end})
    P:CreateButton({Name = "Speed +1", Callback = function() S.Plr.SP = _0x.math.min(200, S.Plr.SP + 1) SPL:Set("Speed: " .. S.Plr.SP) if S.Plr.SO then C.ApplySpeed() end end})
    P:CreateToggle({Name = "Enable Speed", CurrentValue = false, Callback = function(v) if v then C.StartSpeed() else C.StopSpeed() end end})
    P:CreateSection("Teleport")
    local SP = nil
    local PD = P:CreateDropdown({Name = "Select Player", Options = C.GetPlayerList(), Callback = function(o) if o and #o > 0 then SP = o[1] end end})
    P:CreateButton({Name = "Refresh List", Callback = function() PD:Set(C.GetPlayerList()) end})
    P:CreateButton({Name = "Teleport", Callback = function() if SP then C.TeleportTo(SP) end end})
    
    local A = W:CreateTab("Aim", 4483362458)
    A:CreateSection("Target Settings")
    A:CreateDropdown({Name = "Target Role", Options = {"Everyone", "Survivor", "Killer"}, CurrentOption = {"Everyone"}, Callback = function(o) if o and #o > 0 then if o[1] == "Everyone" then S.Aim.M = nil else S.Aim.M = o[1] end end end})
    A:CreateDropdown({Name = "Target Part", Options = {"Head", "Body"}, CurrentOption = {"Head"}, Callback = function(o) if o and #o > 0 then S.Aim.TP = o[1] end end})
    A:CreateToggle({Name = "Skip Knocked", CurrentValue = true, Callback = function(v) S.Aim.SK = v end})
    A:CreateSection("Auto Aim")
    A:CreateToggle({Name = "Enable Auto Aim", CurrentValue = false, Callback = function(v) if v then C.StopAimbot() C.StartAutoAim() else C.StopAutoAim() end end})
    A:CreateSlider({Name = "Auto Aim Distance", Range = {10, 150}, Increment = 5, CurrentValue = 50, Callback = function(v) S.Aim.AAD = v end})
    A:CreateSlider({Name = "Auto Aim Smoothing", Range = {1, 10}, Increment = 1, CurrentValue = 5, Callback = function(v) S.Aim.AAS = v / 10 end})
    A:CreateSection("Aimbot")
    A:CreateToggle({Name = "Enable Aimbot", CurrentValue = false, Callback = function(v) if v then C.StopAutoAim() C.StartAimbot() else C.StopAimbot() end end})
    A:CreateSlider({Name = "Aimbot Distance", Range = {10, 200}, Increment = 5, CurrentValue = 50, Callback = function(v) S.Aim.ABD = v end})
    A:CreateSlider({Name = "Aimbot Smoothing", Range = {1, 10}, Increment = 1, CurrentValue = 8, Callback = function(v) S.Aim.ABS = v / 10 end})
    A:CreateSection("Silent Aim")
    A:CreateToggle({Name = "Enable Silent Aim", CurrentValue = false, Callback = function(v) if v then C.StartSilentAim() else C.StopSilentAim() end end})
    A:CreateSlider({Name = "Silent Aim Distance", Range = {5, 100}, Increment = 5, CurrentValue = 30, Callback = function(v) S.Aim.SID = v end})
    A:CreateSection("Crosshair")
    A:CreateToggle({Name = "Enable Crosshair", CurrentValue = false, Callback = function(v) if v then C.StartCrosshair() else C.StopCrosshair() end end})
    A:CreateSlider({Name = "Crosshair Size", Range = {5, 50}, Increment = 1, CurrentValue = 15, Callback = function(v) S.Vis.CS = v end})
    A:CreateSlider({Name = "Crosshair Gap", Range = {2, 30}, Increment = 1, CurrentValue = 8, Callback = function(v) S.Vis.CG = v end})
    
    local STT = W:CreateTab("Settings", 4483362458)
    STT:CreateSection("ESP Colors")
    STT:CreateColorPicker({Name = "Killer Color", Color = S.Col.K, Callback = function(c) S.Col.K = c C.RefreshESPColors() end})
    STT:CreateColorPicker({Name = "Survivor Color", Color = S.Col.SV, Callback = function(c) S.Col.SV = c C.RefreshESPColors() end})
    STT:CreateColorPicker({Name = "Pallet Color", Color = S.Col.PL, Callback = function(c) S.Col.PL = c C.RefreshESPColors() end})
    STT:CreateSection("Generator Colors")
    STT:CreateColorPicker({Name = "Gen 0-49%", Color = S.Col.GL, Callback = function(c) S.Col.GL = c end})
    STT:CreateColorPicker({Name = "Gen 50-99%", Color = S.Col.GM, Callback = function(c) S.Col.GM = c end})
    STT:CreateColorPicker({Name = "Gen 100%", Color = S.Col.GH, Callback = function(c) S.Col.GH = c end})
    STT:CreateSection("Crosshair Colors")
    STT:CreateColorPicker({Name = "Crosshair Normal", Color = S.Col.CR, Callback = function(c) S.Col.CR = c end})
    STT:CreateColorPicker({Name = "Crosshair Locked", Color = S.Col.CL, Callback = function(c) S.Col.CL = c end})
    STT:CreateSection("Key System")
    STT:CreateButton({Name = "Clear Saved Key", Callback = function() _DF(_CFG._KF) _DF(_CFG._UF) _SN("Success", "Key cleared!", 2) end})
    local keyStatusContent = _ISC() and "✅ Secure Server: ACTIVE\\n🔒 1 Key = 1 User: ENABLED" or "Standard Key System"
    STT:CreateParagraph({Title = "Key Status", Content = keyStatusContent})
    STT:CreateSection("Server")
    STT:CreateButton({Name = "Rejoin Server", Callback = function() C.Rejoin() end})
    STT:CreateSection("Controls")
    STT:CreateButton({Name = "Refresh ESP Colors", Callback = function() C.RefreshESPColors() end})
    STT:CreateButton({Name = "Stop All Features", Callback = function() C.StopAll() end})
    STT:CreateButton({Name = "Destroy Hub", Callback = function() C.StopAll() R:Destroy() _0x.getgenv().UH = nil _0x.getgenv().UHLoaded = nil end})
    
    _SN("Ultimate Hub", "Loaded! Welcome " .. _LP.Name, 3)
end

if _CKS() then
    _LH()
end
`;

// ============================================
// ROUTES
// ============================================

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        version: '9.3-secure'
    });
});

// Root
app.get('/', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.status(401).setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    res.json({ status: 'online', service: 'Ultimate Hub', version: '9.3' });
});

// Script endpoints
const scriptPaths = ['/script', '/api/script', '/loader', '/load', '/run', '/execute', '/s'];
scriptPaths.forEach(path => {
    app.get(path, (req, res) => {
        if (!isRobloxExecutor(req)) {
            res.status(401).setHeader('Content-Type', 'text/html');
            return res.send(NOT_AUTHORIZED_HTML);
        }
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.send(PROTECTED_LOADER_SCRIPT);
    });
});

// Validate Key
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;
        const ip = getRealIP(req);

        if (!validateKey(key)) {
            return res.json({ valid: false, message: "Invalid key format!" });
        }
        
        if (!validateHWID(hwid)) {
            return res.json({ valid: false, message: "Invalid device identifier!" });
        }

        const sanitizedUserName = sanitizeString(userName, 50);
        const sanitizedUserId = sanitizeString(String(userId), 20);
        const hashedKey = hashKey(key);
        const hashedHWID = hashHWID(hwid);

        // Validate with Work.ink
        const isValidKey = await validateWithWorkInk(key);
        if (!isValidKey) {
            return res.json({ valid: false, message: "Invalid key!" });
        }

        // Check existing binding using hashed key
        if (keyDatabase[hashedKey]) {
            const binding = keyDatabase[hashedKey];
            
            if (binding.hwid !== hashedHWID) {
                return res.json({
                    valid: false,
                    bound_to_other: true,
                    bound_user: binding.userName,
                    message: "Key bound to: " + binding.userName
                });
            }

            binding.lastUsed = Date.now();
            binding.useCount = (binding.useCount || 0) + 1;
            saveDatabase();
            
            return res.json({
                valid: true,
                returning_user: true,
                message: "Welcome back!"
            });
        }

        // New binding with hashed values
        keyDatabase[hashedKey] = {
            hwid: hashedHWID,
            userId: sanitizedUserId,
            userName: sanitizedUserName,
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            ipHash: CryptoUtils.hash(ip)
        };

        saveDatabase();
        console.log(`[NEW KEY] ${hashedKey.substring(0, 8)}... -> ${sanitizedUserName}`);
        
        return res.json({ valid: true, new_binding: true, message: "Key registered!" });

    } catch (error) {
        console.error("[Validate] Error:", error.message);
        return res.json({ valid: false, message: "Server error!" });
    }
});

// Check Key
app.post('/api/check', (req, res) => {
    const { key, hwid } = req.body;
    
    if (!validateKey(key)) {
        return res.json({ status: "error", message: "Invalid key format" });
    }

    const hashedKey = hashKey(key);
    const hashedHWID = hashHWID(hwid);

    if (keyDatabase[hashedKey]) {
        if (keyDatabase[hashedKey].hwid === hashedHWID) {
            return res.json({ status: "verified", userName: keyDatabase[hashedKey].userName });
        }
        return res.json({ status: "bound_other", userName: keyDatabase[hashedKey].userName });
    }
    return res.json({ status: "new" });
});

// Bind Key
app.post('/api/bind', (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    
    if (!validateKey(key) || !validateHWID(hwid)) {
        return res.json({ success: false, message: "Invalid input" });
    }

    const hashedKey = hashKey(key);
    const hashedHWID = hashHWID(hwid);

    if (keyDatabase[hashedKey] && keyDatabase[hashedKey].hwid !== hashedHWID) {
        return res.json({ success: false, message: "Already bound" });
    }

    const sanitizedUserName = sanitizeString(userName, 50);
    
    keyDatabase[hashedKey] = { 
        hwid: hashedHWID, 
        userId: sanitizeString(String(userId), 20), 
        userName: sanitizedUserName, 
        boundAt: Date.now(), 
        lastUsed: Date.now(), 
        useCount: 1,
        ipHash: CryptoUtils.hash(getRealIP(req))
    };
    
    saveDatabase();
    return res.json({ success: true });
});

// Stats (Protected)
app.get('/api/stats', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    res.json({ 
        totalKeys: Object.keys(keyDatabase).length, 
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        blockedIPs: blockedIPs.size,
        suspiciousIPs: suspiciousActivity.size,
        version: '9.3-secure'
    });
});

// Admin: Unblock IP
app.post('/api/admin/unblock', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    const { ip } = req.body;
    if (ip && blockedIPs.has(ip)) {
        blockedIPs.delete(ip);
        suspiciousActivity.delete(ip);
        return res.json({ success: true, message: `Unblocked ${ip}` });
    }
    
    return res.json({ success: false, message: "IP not found in blocklist" });
});

// Catch all
app.use('*', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.status(401).setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found" });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('[Error]', err.message);
    res.status(500).json({ error: "Internal server error" });
});

// Cleanup interval (every 10 minutes)
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
    
    // Decay suspicious activity scores
    for (const [ip, score] of suspiciousActivity) {
        const newScore = score - 10;
        if (newScore <= 0) {
            suspiciousActivity.delete(ip);
        } else {
            suspiciousActivity.set(ip, newScore);
        }
    }
    
    console.log(`[Cleanup] RateLimit: ${rateLimitStore.size}, Blocked: ${blockedIPs.size}, Suspicious: ${suspiciousActivity.size}`);
}, 10 * 60 * 1000);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Secure Server V9.3 running on port ${PORT}`);
    console.log(`🔐 Admin secret: ${ADMIN_SECRET.substring(0, 8)}...`);
    console.log(`🔒 Encryption: AES-256-GCM`);
    console.log(`📁 Database: Encrypted JSON`);
});
