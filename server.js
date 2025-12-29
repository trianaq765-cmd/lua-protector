const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// SECURITY: Rate Limiting Manual
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
        return res.status(429).json({ 
            error: "Too many requests", 
            blocked: true,
            retryAfter: remainingTime 
        });
    } else if (blockedIPs[ip]) {
        delete blockedIPs[ip];
    }
    
    if (!rateLimitStore[ip] || rateLimitStore[ip].resetTime < now) {
        rateLimitStore[ip] = {
            count: 1,
            resetTime: now + RATE_LIMIT_WINDOW
        };
    } else {
        rateLimitStore[ip].count++;
    }
    
    if (rateLimitStore[ip].count > RATE_LIMIT_MAX_REQUESTS) {
        blockedIPs[ip] = now + BLOCK_DURATION;
        console.log(`[BLOCKED] IP ${ip} - Too many requests`);
        return res.status(429).json({ 
            error: "Rate limit exceeded", 
            blocked: true,
            retryAfter: Math.ceil(BLOCK_DURATION / 1000)
        });
    }
    
    next();
}

// ============================================
// SECURITY: CORS Configuration
// ============================================
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'UH-Executor', 'UH-Version', 'X-Executor', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimiter);

// ============================================
// SECURITY: Security Headers Middleware
// ============================================
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// DATABASE: Persistent File-Based
// ============================================
const DB_FILE = './keyDatabase.json';
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');

let keyDatabase = {};

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const data = fs.readFileSync(DB_FILE, 'utf8');
            keyDatabase = JSON.parse(data);
            console.log(`[DB] Loaded ${Object.keys(keyDatabase).length} keys`);
        }
    } catch (error) {
        console.error('[DB] Error loading database:', error.message);
        keyDatabase = {};
    }
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(keyDatabase, null, 2));
    } catch (error) {
        console.error('[DB] Error saving database:', error.message);
    }
}

setInterval(saveDatabase, 5 * 60 * 1000);

loadDatabase();

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

const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";

// ============================================
// SECURITY: Input Validation & Sanitization
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

function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);
}

// ============================================
// HTML PAGE: Not Authorized (Premium Style)
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
    <style>
        * {
            margin: 0; padding: 0; box-sizing: border-box;
        }

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
            position: relative;
            z-index: 10;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 20px;
            user-select: none;
        }

        .auth-label {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #ffffff;
            font-size: 1.1rem;
            font-weight: 600;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 25px;
        }

        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800;
            max-width: 700px;
            margin: 0 0 20px 0;
            line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        p {
            color: rgba(255, 255, 255, 0.4);
            font-size: 1.1rem;
            margin: 0;
        }

        .icon {
            font-size: 1.4rem;
        }

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
// SCRIPT LUA (Protected) - FIXED DOUBLE LOAD
// ============================================
const PROTECTED_LOADER_SCRIPT = `
-- ============================================
-- ULTIMATE HUB V9.2 - FIXED DOUBLE LOAD
-- ============================================

-- Prevent double execution
if getgenv().UHLoading then return end
if getgenv().UHLoaded then
    pcall(function() getgenv().UH:Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("Rayfield"):Destroy() end)
    getgenv().UH, getgenv().UHCore, getgenv().UHLoaded = nil, nil, nil
    task.wait(0.3)
end

getgenv().UHLoading = true

local CFG = {
    RailwayURL = "https://lua-protector-production.up.railway.app",
    ValidationURL = "https://lua-protector-production.up.railway.app/api/validate",
    CheckKeyURL = "https://lua-protector-production.up.railway.app/api/check",
    BindKeyURL = "https://lua-protector-production.up.railway.app/api/bind",
    GetKeyLink = "https://work.ink/29pu/key-sistem-3",
    CU = "https://api.junkie-development.de/api/v1/luascripts/public/8a56151af71ed4b56c346b2bef75d232f22d3ffb242e31d5ef79d12f69d974d6/download",
    SV = true,
    KF = "UltimateHubKey.txt",
    UF = "UltimateHubUser.txt",
    MA = 5,
    CT = 60,
    OneKeyOneUser = true
}

local CA, LAT = 0, 0
local HS = game:GetService("HttpService")
local TS = game:GetService("TweenService")
local PL = game:GetService("Players")
local CG = game:GetService("CoreGui")
local SG = game:GetService("StarterGui")
local LP = PL.LocalPlayer

local CoreLoaded = false

local function SF(f, c)
    if writefile then
        pcall(writefile, f, c)
    end
end

local function RF(f)
    if isfile and readfile then
        local s, r = pcall(function()
            if isfile(f) then
                return readfile(f)
            end
            return nil
        end)
        if s then
            return r
        end
    end
    return nil
end

local function DF(f)
    if isfile and delfile then
        pcall(function()
            if isfile(f) then
                delfile(f)
            end
        end)
    end
end

local function SC(t)
    if setclipboard then
        pcall(setclipboard, t)
    end
end

local function GetUserIdentifier()
    local hwid
    local hwidFuncs = {
        function() return gethwid and gethwid() end,
        function() return getexecutorhwid and getexecutorhwid() end,
        function() return syn and syn.cache_hwid and syn.cache_hwid() end,
        function() return fluxus and fluxus.get_hwid and fluxus.get_hwid() end,
        function() return get_hwid and get_hwid() end,
        function() return HWID and HWID() end,
        function() return getexecutorname and getexecutorname() .. "_" .. LP.UserId end
    }
    
    for _, func in ipairs(hwidFuncs) do
        local s, r = pcall(func)
        if s and r and r ~= "" then
            hwid = tostring(r)
            break
        end
    end
    
    if hwid then
        return hwid .. "_" .. LP.UserId
    else
        return "NOHWID_" .. LP.UserId .. "_" .. LP.Name
    end
end

local function IsServerConfigured()
    return CFG.RailwayURL ~= "" and CFG.RailwayURL ~= nil
end

local function DoRequest(url, method, headers, body)
    headers = headers or {}
    headers["UH-Executor"] = "true"
    headers["UH-Version"] = "9.2"
    
    local rf = (syn and syn.request) or request or http_request or (fluxus and fluxus.request) or (delta and delta.request)
    if rf then
        local s, r = pcall(function()
            return rf({Url = url, Method = method or "GET", Headers = headers, Body = body})
        end)
        if s and r then
            return r
        end
    end
    if method == "GET" or not method then
        local s, r = pcall(function()
            return game:HttpGet(url)
        end)
        if s then
            return {Body = r, StatusCode = 200}
        end
    end
    return nil
end

local function CheckKeyBinding(key, uid)
    if not IsServerConfigured() then
        return true, "no_server", nil
    end
    
    local r = DoRequest(CFG.CheckKeyURL, "POST", {
        ["Content-Type"] = "application/json"
    }, HS:JSONEncode({
        key = key,
        hwid = uid,
        userId = LP.UserId,
        userName = LP.Name
    }))
    
    if r and r.Body then
        local s, data = pcall(function()
            return HS:JSONDecode(r.Body)
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

local function BindKeyToUser(key, uid)
    if not IsServerConfigured() then
        return true
    end
    
    local r = DoRequest(CFG.BindKeyURL, "POST", {
        ["Content-Type"] = "application/json"
    }, HS:JSONEncode({
        key = key,
        hwid = uid,
        userId = LP.UserId,
        userName = LP.Name,
        boundAt = os.time(),
        boundDate = os.date("%Y-%m-%d %H:%M:%S")
    }))
    
    return r and (r.StatusCode == 200 or r.StatusCode == 201)
end

local function OU(u)
    if not u or u == "" then
        return false
    end
    local urlFuncs = {"openurl", "OpenURL", "open_url", "browseurl", "BrowseURL", "browse_url"}
    for _, n in ipairs(urlFuncs) do
        local f = getgenv()[n] or getfenv()[n] or _G[n]
        if f and type(f) == "function" and pcall(f, u) then
            return true
        end
    end
    pcall(function()
        if syn and syn.open_browser then
            syn.open_browser(u)
        end
    end)
    pcall(function()
        if fluxus and fluxus.open_browser then
            fluxus.open_browser(u)
        end
    end)
    return false
end

local function SN(t, x, d)
    pcall(function()
        SG:SetCore("SendNotification", {Title = t or "Ultimate Hub", Text = x or "", Duration = d or 5})
    end)
end

local KeyCache = {}

local function VK(k)
    if not k or k == "" then
        return false, "Please enter a key!"
    end
    k = k:gsub("^%s*(.-)%s*$", "%1")
    if #k < 5 then
        return false, "Key too short!"
    end
    
    if KeyCache[k] and (os.time() - KeyCache[k].time) < 300 then
        return KeyCache[k].valid, KeyCache[k].msg
    end
    
    local uid = GetUserIdentifier()
    
    local s, r = pcall(function()
        local response = DoRequest(CFG.ValidationURL, "POST", {
            ["Content-Type"] = "application/json"
        }, HS:JSONEncode({
            key = k,
            hwid = uid,
            userId = LP.UserId,
            userName = LP.Name
        }))
        
        if response and response.Body then
            return HS:JSONDecode(response.Body)
        end
        return nil
    end)
    
    if s and r then
        if r.valid == true or r.success == true then
            if r.bound_to_other then
                local boundName = r.bound_user or "Unknown"
                KeyCache[k] = {valid = false, msg = "Key bound to: " .. boundName, time = os.time()}
                return false, "Key bound to: " .. boundName
            end
            
            local msg = r.message or "Key Valid!"
            if r.new_binding then
                msg = "Key Registered!"
            elseif r.returning_user then
                msg = "Welcome back!"
            end
            
            KeyCache[k] = {valid = true, msg = msg, time = os.time()}
            return true, msg
        else
            local errMsg = r.message or "Invalid key!"
            KeyCache[k] = {valid = false, msg = errMsg, time = os.time()}
            return false, errMsg
        end
    end
    
    local fallbackValid = false
    s, r = pcall(function()
        return HS:JSONDecode(game:HttpGet("https://work.ink/_api/v2/token/isValid/" .. k))
    end)
    if s and r and r.valid == true then
        fallbackValid = true
    end
    
    if fallbackValid then
        if CFG.OneKeyOneUser then
            local canUse, status, bindData = CheckKeyBinding(k, uid)
            if status == "bound_other" then
                local boundName = "Unknown"
                if bindData and bindData.userName then
                    boundName = bindData.userName
                end
                KeyCache[k] = {valid = false, msg = "Key bound to: " .. boundName, time = os.time()}
                return false, "Key bound to: " .. boundName
            elseif status == "new" then
                BindKeyToUser(k, uid)
            end
        end
        KeyCache[k] = {valid = true, msg = "Key Valid!", time = os.time()}
        return true, "Key Valid!"
    end
    
    KeyCache[k] = {valid = false, msg = "Invalid key or server error!", time = os.time()}
    return false, "Invalid key!"
end

local function LoadCore()
    if CoreLoaded and getgenv().UHCore then
        return getgenv().UHCore
    end
    
    local success = pcall(function()
        loadstring(game:HttpGet(CFG.CU))()
    end)
    
    if success then
        CoreLoaded = true
        task.wait(0.3)
        return getgenv().UHCore
    end
    
    return nil
end

local function CKS()
    pcall(function()
        if getgenv().UH then
            getgenv().UH:Destroy()
        end
    end)
    pcall(function()
        local k = CG:FindFirstChild("UltimateHubKeySystem")
        if k then
            k:Destroy()
        end
    end)
    getgenv().UH = nil
    task.wait(0.1)
    
    if CFG.SV then
        local sk = RF(CFG.KF)
        local su = RF(CFG.UF)
        local cu = GetUserIdentifier()
        if sk and sk ~= "" then
            if CFG.OneKeyOneUser and su and su ~= cu then
                DF(CFG.KF)
                DF(CFG.UF)
                SN("Ultimate Hub", "Key reset: Different device", 3)
            else
                SN("Ultimate Hub", "Checking saved key...", 2)
                local v = VK(sk)
                if v then
                    SF(CFG.UF, cu)
                    SN("Ultimate Hub", "Key valid! Loading...", 2)
                    return true
                end
                DF(CFG.KF)
                DF(CFG.UF)
            end
        end
    end
    
    local SGui = Instance.new("ScreenGui")
    SGui.Name = "UltimateHubKeySystem"
    SGui.ResetOnSpawn = false
    SGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    local parentSuccess = pcall(function()
        SGui.Parent = CG
    end)
    if not parentSuccess then
        pcall(function()
            SGui.Parent = LP:WaitForChild("PlayerGui")
        end)
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
    TL.Text = "🔐 Ultimate Hub V9.2"
    TL.TextColor3 = Color3.fromRGB(255, 255, 255)
    TL.TextSize = 18
    TL.Font = Enum.Font.GothamBold
    TL.TextXAlignment = Enum.TextXAlignment.Center
    TL.Parent = TB
    
    local bs, sc
    if IsServerConfigured() then
        bs = "🔒 Railway Server (Active)"
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
    UI.Text = "👤 " .. LP.Name .. " (ID: " .. LP.UserId .. ")"
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
    AL.Text = "Attempts: 0/" .. CFG.MA
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
    TS:Create(MF, TweenInfo.new(0.35, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {Size = UDim2.new(0, 360, 0, 220)}):Play()
    
    local kv = false
    local vc = Instance.new("BindableEvent")
    local ip = false
    
    local function CloseGUI()
        TS:Create(MF, TweenInfo.new(0.25, Enum.EasingStyle.Back, Enum.EasingDirection.In), {Size = UDim2.new(0, 0, 0, 0)}):Play()
        TS:Create(BG, TweenInfo.new(0.25), {BackgroundTransparency = 1}):Play()
        task.wait(0.25)
        SGui:Destroy()
    end
    
    local function SK()
        if ip then
            return
        end
        ip = true
        local ik = KI.Text:gsub("^%s*(.-)%s*$", "%1")
        if ik == "" then
            STL.Text = "⚠️ Please enter a key!"
            STL.TextColor3 = Color3.fromRGB(255, 200, 100)
            ip = false
            return
        end
        if CA >= CFG.MA then
            local tl = CFG.CT - (os.time() - LAT)
            if tl > 0 then
                STL.Text = "⏳ Wait " .. tl .. " seconds..."
                STL.TextColor3 = Color3.fromRGB(255, 100, 100)
                ip = false
                return
            else
                CA = 0
            end
        end
        STL.Text = "🔄 Connecting to server..."
        STL.TextColor3 = Color3.fromRGB(255, 255, 100)
        SB.Text = "..."
        SB.BackgroundColor3 = Color3.fromRGB(100, 100, 100)
        
        task.spawn(function()
            task.wait(0.3)
            local v, m = VK(ik)
            if v then
                STL.Text = "✅ " .. m
                STL.TextColor3 = Color3.fromRGB(100, 255, 100)
                SB.Text = "✓ Success!"
                SB.BackgroundColor3 = Color3.fromRGB(80, 200, 80)
                if CFG.SV then
                    SF(CFG.KF, ik)
                    SF(CFG.UF, GetUserIdentifier())
                end
                task.wait(1.2)
                CloseGUI()
                kv = true
                vc:Fire()
            else
                CA = CA + 1
                LAT = os.time()
                STL.Text = "❌ " .. m
                STL.TextColor3 = Color3.fromRGB(255, 100, 100)
                SB.Text = "✓ Validate Key"
                SB.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
                AL.Text = "Attempts: " .. CA .. "/" .. CFG.MA
                local op = IC.Position
                for i = 1, 4 do
                    if i % 2 == 0 then
                        IC.Position = op + UDim2.new(0, 6, 0, 0)
                    else
                        IC.Position = op + UDim2.new(0, -6, 0, 0)
                    end
                    task.wait(0.04)
                end
                IC.Position = op
                IS.Color = Color3.fromRGB(255, 80, 80)
                task.wait(0.5)
                IS.Color = Color3.fromRGB(60, 60, 80)
                ip = false
            end
        end)
    end
    
    SB.MouseEnter:Connect(function()
        TS:Create(SB, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(100, 140, 255)}):Play()
    end)
    SB.MouseLeave:Connect(function()
        TS:Create(SB, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(80, 120, 255)}):Play()
    end)
    GK.MouseEnter:Connect(function()
        TS:Create(GK, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(108, 121, 255)}):Play()
    end)
    GK.MouseLeave:Connect(function()
        TS:Create(GK, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(88, 101, 242)}):Play()
    end)
    
    SB.MouseButton1Click:Connect(SK)
    KI.FocusLost:Connect(function(e)
        if e then
            SK()
        end
    end)
    GK.MouseButton1Click:Connect(function()
        if OU(CFG.GetKeyLink) then
            STL.Text = "🌐 Browser opened!"
            STL.TextColor3 = Color3.fromRGB(100, 255, 100)
        else
            SC(CFG.GetKeyLink)
            STL.Text = "📋 Link copied!"
            STL.TextColor3 = Color3.fromRGB(100, 200, 255)
        end
    end)
    
    vc.Event:Wait()
    vc:Destroy()
    return kv
end

local function LH()
    pcall(function()
        CG:FindFirstChild("UltimateHubKeySystem"):Destroy()
    end)
    
    local C = LoadCore()
    if not C then
        SN("Ultimate Hub", "Failed to load core!", 3)
        getgenv().UHLoading = nil
        return
    end
    
    task.wait(0.2)
    
    local R
    local loadSuccess = pcall(function()
        R = loadstring(game:HttpGet("https://sirius.menu/rayfield"))()
    end)
    
    if not loadSuccess or not R then
        SN("Ultimate Hub", "Failed to load UI!", 3)
        getgenv().UHLoading = nil
        return
    end
    
    local S = C.Settings or {}
    
    R.Notify = function() end
    local W = R:CreateWindow({
        Name = "Ultimate Hub V9.2 | ToingDC",
        LoadingTitle = "Ultimate Hub",
        LoadingSubtitle = "by ToingDC",
        ConfigurationSaving = {Enabled = false},
        KeySystem = false
    })
    getgenv().UH = W
    
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
    SV:CreateSection("Performance")
    SV:CreateToggle({Name = "Anti-Lag Mode", CurrentValue = false, Callback = function(v) if v then C.StartAntiLag() else C.StopAntiLag() end end})
    
    local K = W:CreateTab("Killer", 4483362458)
    K:CreateSection("Auto Attack")
    K:CreateToggle({Name = "Enable Auto Attack", CurrentValue = false, Callback = function(v) if v then C.StartAutoAttack() else C.StopAutoAttack() end end})
    K:CreateSlider({Name = "Attack Distance", Range = {5, 30}, Increment = 1, CurrentValue = 15, Callback = function(v) if S.Kil then S.Kil.AD = v end end})
    K:CreateSection("Protection")
    K:CreateToggle({Name = "Anti-Blind", CurrentValue = false, Callback = function(v) if v then C.StartAntiBlind() else C.StopAntiBlind() end end})
    K:CreateSection("Camera Mode")
    K:CreateDropdown({Name = "Camera View", Options = {"Default", "FirstPerson", "ThirdPerson"}, CurrentOption = {"Default"}, Callback = function(o) if o and #o > 0 then C.SetCameraMode(o[1]) end end})
    
    local P = W:CreateTab("Player", 4483362458)
    P:CreateSection("Speed Boost")
    local currentSpeed = (S.Plr and S.Plr.SP) or 16
    local SPL = P:CreateLabel("Speed: " .. currentSpeed)
    P:CreateButton({Name = "Speed -1", Callback = function() 
        if S.Plr then 
            S.Plr.SP = math.max(16, S.Plr.SP - 1) 
            SPL:Set("Speed: " .. S.Plr.SP) 
        end 
    end})
    P:CreateButton({Name = "Speed +1", Callback = function() 
        if S.Plr then 
            S.Plr.SP = math.min(200, S.Plr.SP + 1) 
            SPL:Set("Speed: " .. S.Plr.SP) 
        end 
    end})
    P:CreateToggle({Name = "Enable Speed", CurrentValue = false, Callback = function(v) 
        if C.WalkspeedSystem then
            if v then C.WalkspeedSystem:Start() else C.WalkspeedSystem:Stop() end
        end
    end})
    P:CreateSection("Teleport")
    local SP = nil
    local playerList = C.GetPlayerList and C.GetPlayerList() or {}
    local PD = P:CreateDropdown({Name = "Select Player", Options = playerList, Callback = function(o) if o and #o > 0 then SP = o[1] end end})
    P:CreateButton({Name = "Refresh List", Callback = function() 
        local newList = C.GetPlayerList and C.GetPlayerList() or {}
        PD:Set(newList) 
    end})
    P:CreateButton({Name = "Teleport", Callback = function() if SP and C.TeleportTo then C.TeleportTo(SP) end end})
    
    local A = W:CreateTab("Aim", 4483362458)
    A:CreateSection("Target Settings")
    A:CreateDropdown({Name = "Target Role", Options = {"Everyone", "Survivor", "Killer"}, CurrentOption = {"Everyone"}, Callback = function(o) 
        if o and #o > 0 and S.Aim then 
            if o[1] == "Everyone" then S.Aim.M = nil else S.Aim.M = o[1] end 
        end 
    end})
    A:CreateDropdown({Name = "Target Part", Options = {"Head", "Body"}, CurrentOption = {"Head"}, Callback = function(o) 
        if o and #o > 0 and S.Aim then S.Aim.TP = o[1] end 
    end})
    A:CreateSection("Auto Aim")
    A:CreateToggle({Name = "Enable Auto Aim", CurrentValue = false, Callback = function(v) 
        if C.AimSystem then
            if v then C.AimSystem:Start() else C.AimSystem:Stop() end
        end
    end})
    A:CreateSlider({Name = "Auto Aim Distance", Range = {10, 150}, Increment = 5, CurrentValue = 50, Callback = function(v) if S.Aim then S.Aim.AAD = v end end})
    A:CreateSection("Crosshair")
    A:CreateToggle({Name = "Enable Crosshair", CurrentValue = false, Callback = function(v) 
        if v then 
            if C.StartCrosshair then C.StartCrosshair() end
        else 
            if C.StopCrosshair then C.StopCrosshair() end
        end 
    end})
    A:CreateSlider({Name = "Crosshair Size", Range = {5, 50}, Increment = 1, CurrentValue = 15, Callback = function(v) if S.Vis then S.Vis.CS = v end end})
    A:CreateSlider({Name = "Crosshair Gap", Range = {2, 30}, Increment = 1, CurrentValue = 8, Callback = function(v) if S.Vis then S.Vis.CG = v end end})
    
    local STT = W:CreateTab("Settings", 4483362458)
    STT:CreateSection("ESP Colors")
    local killerColor = (S.Col and S.Col.K) or Color3.fromRGB(255, 80, 80)
    local survivorColor = (S.Col and S.Col.SV) or Color3.fromRGB(80, 255, 80)
    local palletColor = (S.Col and S.Col.PL) or Color3.fromRGB(255, 200, 80)
    STT:CreateColorPicker({Name = "Killer Color", Color = killerColor, Callback = function(c) if S.Col then S.Col.K = c end if C.RefreshESPColors then C.RefreshESPColors() end end})
    STT:CreateColorPicker({Name = "Survivor Color", Color = survivorColor, Callback = function(c) if S.Col then S.Col.SV = c end if C.RefreshESPColors then C.RefreshESPColors() end end})
    STT:CreateColorPicker({Name = "Pallet Color", Color = palletColor, Callback = function(c) if S.Col then S.Col.PL = c end if C.RefreshESPColors then C.RefreshESPColors() end end})
    STT:CreateSection("Key System")
    STT:CreateButton({Name = "Clear Saved Key", Callback = function() DF(CFG.KF) DF(CFG.UF) SN("Success", "Key cleared!", 2) end})
    local keyStatusContent = IsServerConfigured() and "✅ Railway Server: ACTIVE" or "Standard Key System"
    STT:CreateParagraph({Title = "Key Status", Content = keyStatusContent})
    STT:CreateSection("Server")
    STT:CreateButton({Name = "Rejoin Server", Callback = function() if C.Rejoin then C.Rejoin() end end})
    STT:CreateSection("Controls")
    STT:CreateButton({Name = "Refresh ESP Colors", Callback = function() if C.RefreshESPColors then C.RefreshESPColors() end end})
    STT:CreateButton({Name = "Stop All Features", Callback = function() if C.StopAll then C.StopAll() end end})
    STT:CreateButton({Name = "Destroy Hub", Callback = function() 
        if C.StopAll then C.StopAll() end 
        R:Destroy() 
        getgenv().UH = nil 
        getgenv().UHLoaded = nil 
        getgenv().UHLoading = nil
    end})
    
    getgenv().UHLoaded = true
    getgenv().UHLoading = nil
    
    SN("Ultimate Hub", "Loaded! Welcome " .. LP.Name, 3)
end

if CKS() then
    LH()
else
    getgenv().UHLoading = nil
end
`;

// ============================================
// DETECT ROBLOX EXECUTOR (FIXED)
// ============================================
function isRobloxExecutor(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const acceptHeader = req.headers['accept'] || '';
    const secFetchMode = req.headers['sec-fetch-mode'] || '';
    const secFetchDest = req.headers['sec-fetch-dest'] || '';
    
    // 1. Cek header custom dari executor (PASTI executor)
    const executorHeaders = [
        'uh-executor',
        'uh-version', 
        'x-executor',
        'roblox-id',
        'syn-fingerprint',
        'exploitid',
        'krnl-fingerprint',
        'fluxus-fingerprint',
        'delta-fingerprint',
        'script-ware-fingerprint'
    ];
    
    for (const header of executorHeaders) {
        if (req.headers[header]) {
            console.log(`[EXECUTOR] Detected via header: ${header}`);
            return true;
        }
    }
    
    // 2. Cek user-agent executor keywords
    const executorKeywords = ['roblox', 'syn', 'krnl', 'fluxus', 'delta', 'scriptware', 'sentinel', 'jjsploit', 'oxygen', 'electron', 'comet'];
    for (const keyword of executorKeywords) {
        if (userAgent.includes(keyword)) {
            console.log(`[EXECUTOR] Detected via UA keyword: ${keyword}`);
            return true;
        }
    }
    
    // 3. BROWSER DETECTION - Prioritaskan deteksi browser
    
    // Browser modern selalu punya sec-fetch headers
    if (secFetchMode === 'navigate' || secFetchDest === 'document') {
        console.log('[BROWSER] Detected via sec-fetch headers');
        return false;
    }
    
    // Browser keywords di user-agent
    const browserKeywords = [
        'mozilla',
        'chrome',
        'safari',
        'firefox',
        'edge',
        'opera',
        'msie',
        'trident',
        'webkit',
        'gecko'
    ];
    
    let isBrowser = false;
    for (const keyword of browserKeywords) {
        if (userAgent.includes(keyword)) {
            isBrowser = true;
            break;
        }
    }
    
    // Jika terdeteksi sebagai browser
    if (isBrowser) {
        console.log('[BROWSER] Detected via UA keywords');
        return false;
    }
    
    // Jika accept header mengandung text/html (browser request)
    if (acceptHeader.includes('text/html')) {
        console.log('[BROWSER] Detected via Accept header');
        return false;
    }
    
    // 4. Jika user-agent kosong/pendek = kemungkinan executor
    if (!userAgent || userAgent.length < 10) {
        console.log('[EXECUTOR] Detected via empty/short UA');
        return true;
    }
    
    // 5. Default: Anggap executor
    console.log('[EXECUTOR] Default assumption');
    return true;
}

// ============================================
// ROUTES
// ============================================

// Health check (public)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

// Root
app.get('/', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.status(401).setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    res.json({ status: 'online', service: 'Ultimate Hub', version: '9.2' });
});

// Script endpoints - MULTIPLE PATHS
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

// Validate Key (with enhanced validation)
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;

        if (!validateKey(key)) {
            return res.json({ valid: false, message: "Invalid key format!" });
        }
        
        if (!validateHWID(hwid)) {
            return res.json({ valid: false, message: "Invalid device identifier!" });
        }

        const sanitizedUserName = sanitizeString(userName, 50);
        const sanitizedUserId = sanitizeString(String(userId), 20);

        let isValidKey = false;
        try {
            const workinkResponse = await axios.get(WORKINK_API + encodeURIComponent(key), { 
                timeout: 10000,
                headers: {
                    'User-Agent': 'UltimateHub/9.2'
                }
            });
            if (workinkResponse.data && workinkResponse.data.valid === true) {
                isValidKey = true;
            }
        } catch (err) {
            console.log("[Work.ink] Error:", err.message);
        }

        if (!isValidKey) {
            return res.json({ valid: false, message: "Invalid key!" });
        }

        if (keyDatabase[key]) {
            const binding = keyDatabase[key];
            
            if (binding.hwid !== hwid) {
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

        keyDatabase[key] = {
            hwid: hwid,
            userId: sanitizedUserId,
            userName: sanitizedUserName,
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            ip: getRealIP(req)
        };

        saveDatabase();
        console.log(`[NEW KEY] ${hashKey(key)} -> ${sanitizedUserName}`);
        
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

    if (keyDatabase[key]) {
        if (keyDatabase[key].hwid === hwid) {
            return res.json({ status: "verified", userName: keyDatabase[key].userName });
        }
        return res.json({ status: "bound_other", userName: keyDatabase[key].userName });
    }
    return res.json({ status: "new" });
});

// Bind Key
app.post('/api/bind', (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    
    if (!validateKey(key) || !validateHWID(hwid)) {
        return res.json({ success: false, message: "Invalid input" });
    }

    if (keyDatabase[key] && keyDatabase[key].hwid !== hwid) {
        return res.json({ success: false, message: "Already bound" });
    }

    const sanitizedUserName = sanitizeString(userName, 50);
    
    keyDatabase[key] = { 
        hwid, 
        userId: sanitizeString(String(userId), 20), 
        userName: sanitizedUserName, 
        boundAt: Date.now(), 
        lastUsed: Date.now(), 
        useCount: 1,
        ip: getRealIP(req)
    };
    
    saveDatabase();
    return res.json({ success: true });
});

// Stats (Protected with admin secret)
app.get('/api/stats', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    res.json({ 
        totalKeys: Object.keys(keyDatabase).length, 
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        blockedIPs: Object.keys(blockedIPs).length
    });
});

// Admin: Clear blocked IPs (protected)
app.post('/api/admin/unblock', (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    
    const { ip } = req.body;
    if (ip && blockedIPs[ip]) {
        delete blockedIPs[ip];
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
    
    for (const ip in rateLimitStore) {
        if (rateLimitStore[ip].resetTime < now) {
            delete rateLimitStore[ip];
        }
    }
    
    for (const ip in blockedIPs) {
        if (blockedIPs[ip] < now) {
            delete blockedIPs[ip];
        }
    }
}, 10 * 60 * 1000);

// Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔐 Admin secret: ${ADMIN_SECRET.substring(0, 8)}...`);
    console.log(`📁 Database file: ${DB_FILE}`);
});
