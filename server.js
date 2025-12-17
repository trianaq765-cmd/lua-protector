const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
app.use(cors());
app.use(express.json());

// Database in-memory
let keyDatabase = {};

// Work.ink API
const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";

// ============================================
// HTML PAGE: Not Authorized (untuk browser)
// ============================================
const NOT_AUTHORIZED_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow: hidden;
        }
        .container {
            text-align: center;
            padding: 60px 40px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            max-width: 500px;
            animation: fadeIn 0.5s ease-out;
        }
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        h1 {
            color: #ff4757;
            font-size: 28px;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 3px;
            text-shadow: 0 0 20px rgba(255, 71, 87, 0.5);
        }
        .message {
            color: #a0a0a0;
            font-size: 16px;
            line-height: 1.8;
            margin-bottom: 30px;
        }
        .warning-box {
            background: rgba(255, 71, 87, 0.1);
            border: 1px solid rgba(255, 71, 87, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .warning-box p {
            color: #ff6b7a;
            font-size: 14px;
        }
        .btn {
            display: inline-block;
            padding: 15px 40px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 30px;
            font-weight: 600;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 2px;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
        }
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }
        .footer {
            margin-top: 40px;
            color: #555;
            font-size: 12px;
        }
        .particles {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            pointer-events: none;
            overflow: hidden;
            z-index: -1;
        }
        .particle {
            position: absolute;
            width: 4px;
            height: 4px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            animation: float 15s infinite;
        }
        @keyframes float {
            0%, 100% {
                transform: translateY(100vh) rotate(0deg);
                opacity: 0;
            }
            10% {
                opacity: 1;
            }
            90% {
                opacity: 1;
            }
            100% {
                transform: translateY(-100vh) rotate(720deg);
                opacity: 0;
            }
        }
    </style>
</head>
<body>
    <div class="particles">
        ${Array(20).fill().map((_, i) => 
            `<div class="particle" style="left: ${Math.random() * 100}%; animation-delay: ${Math.random() * 15}s; animation-duration: ${15 + Math.random() * 10}s;"></div>`
        ).join('')}
    </div>
    
    <div class="container">
        <div class="icon">⛔</div>
        <h1>Not Authorized</h1>
        <div class="warning-box">
            <p>🔒 You are not allowed to view these files.</p>
        </div>
        <p class="message">
            This script is protected and can only be executed<br>
            through authorized Roblox executors.<br><br>
            <strong>Close this page & proceed.</strong>
        </p>
        <button class="btn" onclick="window.close(); window.location.href='about:blank';">
            Close Page
        </button>
        <div class="footer">
            Protected by Ultimate Hub Security System<br>
            © 2024 ToingDC
        </div>
    </div>

    <script>
        // Disable right click
        document.addEventListener('contextmenu', e => e.preventDefault());
        
        // Disable view source shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey && (e.key === 'u' || e.key === 's' || e.key === 'p')) {
                e.preventDefault();
            }
            if (e.key === 'F12') {
                e.preventDefault();
            }
        });
        
        // Clear console
        console.clear();
        console.log('%c⛔ Access Denied', 'color: red; font-size: 30px; font-weight: bold;');
        console.log('%cThis script is protected.', 'color: gray; font-size: 14px;');
    </script>
</body>
</html>
`;

// ============================================
// SCRIPT LUA ANDA (Disimpan di server)
// ============================================
const PROTECTED_LOADER_SCRIPT = `
if getgenv().UHLoaded then
    pcall(function() getgenv().UH:Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("Rayfield"):Destroy() end)
    getgenv().UH, getgenv().UHCore, getgenv().UHLoaded = nil, nil, nil
    task.wait(0.3)
end
getgenv().UHLoaded = true

local CFG = {
    RailwayURL = "https://lua-protector-production.up.railway.app",
    ValidationURL = "https://lua-protector-production.up.railway.app/api/validate",
    CheckKeyURL = "https://lua-protector-production.up.railway.app/api/check",
    BindKeyURL = "https://lua-protector-production.up.railway.app/api/bind",
    GetKeyLink = "https://work.ink/29pu/key-sistem-3",
    CU = "https://raw.githubusercontent.com/trianaq765-cmd/lootlabs-keysystem-/refs/heads/main/Protected_2260249086296060.lua%20(1).txt",
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
        function() return get_hwid and get_hwid() end
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
    local rf = (syn and syn.request) or request or http_request or (fluxus and fluxus.request)
    if rf then
        local s, r = pcall(function()
            return rf({Url = url, Method = method or "GET", Headers = headers or {}, Body = body})
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
    local C = getgenv().UHCore
    if not C then
        pcall(function()
            loadstring(game:HttpGet(CFG.CU))()
        end)
        task.wait(0.5)
        C = getgenv().UHCore
        if not C then
            return
        end
    end
    pcall(function()
        CG:FindFirstChild("UltimateHubKeySystem"):Destroy()
    end)
    task.wait(0.2)
    
    local S = C.S
    local R
    local loadSuccess = pcall(function()
        R = loadstring(game:HttpGet("https://sirius.menu/rayfield"))()
    end)
    if not loadSuccess or not R then
        return
    end
    
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
    E:CreateToggle({
        Name = "Killer ESP",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartKillerESP()
            else
                C.StopKillerESP()
            end
        end
    })
    E:CreateToggle({
        Name = "Survivor ESP",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartSurvivorESP()
            else
                C.StopSurvivorESP()
            end
        end
    })
    E:CreateSection("Object ESP")
    E:CreateToggle({
        Name = "Generator ESP",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartGenESP()
            else
                C.StopGenESP()
            end
        end
    })
    E:CreateToggle({
        Name = "Pallet ESP",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartPalletESP()
            else
                C.StopPalletESP()
            end
        end
    })
    
    local SV = W:CreateTab("Survivor", 4483362458)
    SV:CreateSection("Environment")
    SV:CreateToggle({
        Name = "No Fog",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartNoFog()
            else
                C.StopNoFog()
            end
        end
    })
    SV:CreateToggle({
        Name = "Fullbright",
        CurrentValue = false,
        Callback = function(v)
            C.SetFullbright(v)
        end
    })
    SV:CreateSection("Auto Scripts")
    SV:CreateButton({
        Name = "Load Auto Generator",
        Callback = function()
            C.LoadScript("https://raw.githubusercontent.com/trianaq765-cmd/VD/refs/heads/main/gene")
        end
    })
    SV:CreateButton({
        Name = "Load Auto Heal",
        Callback = function()
            C.LoadScript("https://raw.githubusercontent.com/trianaq765-cmd/VD/refs/heads/main/auto%20heal")
        end
    })
    SV:CreateSection("Performance")
    SV:CreateToggle({
        Name = "Anti-Lag Mode",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartAntiLag()
            else
                C.StopAntiLag()
            end
        end
    })
    
    local K = W:CreateTab("Killer", 4483362458)
    K:CreateSection("Auto Attack")
    K:CreateToggle({
        Name = "Enable Auto Attack",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartAutoAttack()
            else
                C.StopAutoAttack()
            end
        end
    })
    K:CreateSlider({
        Name = "Attack Distance",
        Range = {5, 30},
        Increment = 1,
        CurrentValue = 15,
        Callback = function(v)
            S.Kil.AD = v
        end
    })
    K:CreateSection("Protection")
    K:CreateToggle({
        Name = "Anti-Blind",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartAntiBlind()
            else
                C.StopAntiBlind()
            end
        end
    })
    K:CreateSection("Camera Mode")
    K:CreateDropdown({
        Name = "Camera View",
        Options = {"Default", "FirstPerson", "ThirdPerson"},
        CurrentOption = {"Default"},
        Callback = function(o)
            if o and #o > 0 then
                C.SetCameraMode(o[1])
            end
        end
    })
    
    local P = W:CreateTab("Player", 4483362458)
    P:CreateSection("Speed Boost")
    local SPL = P:CreateLabel("Speed: " .. S.Plr.SP)
    P:CreateButton({
        Name = "Speed -1",
        Callback = function()
            S.Plr.SP = math.max(16, S.Plr.SP - 1)
            SPL:Set("Speed: " .. S.Plr.SP)
            if S.Plr.SO then
                C.ApplySpeed()
            end
        end
    })
    P:CreateButton({
        Name = "Speed +1",
        Callback = function()
            S.Plr.SP = math.min(200, S.Plr.SP + 1)
            SPL:Set("Speed: " .. S.Plr.SP)
            if S.Plr.SO then
                C.ApplySpeed()
            end
        end
    })
    P:CreateToggle({
        Name = "Enable Speed",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartSpeed()
            else
                C.StopSpeed()
            end
        end
    })
    P:CreateSection("Teleport")
    local SP = nil
    local PD = P:CreateDropdown({
        Name = "Select Player",
        Options = C.GetPlayerList(),
        Callback = function(o)
            if o and #o > 0 then
                SP = o[1]
            end
        end
    })
    P:CreateButton({
        Name = "Refresh List",
        Callback = function()
            PD:Set(C.GetPlayerList())
        end
    })
    P:CreateButton({
        Name = "Teleport",
        Callback = function()
            if SP then
                C.TeleportTo(SP)
            end
        end
    })
    
    local A = W:CreateTab("Aim", 4483362458)
    A:CreateSection("Target Settings")
    A:CreateDropdown({
        Name = "Target Role",
        Options = {"Everyone", "Survivor", "Killer"},
        CurrentOption = {"Everyone"},
        Callback = function(o)
            if o and #o > 0 then
                if o[1] == "Everyone" then
                    S.Aim.M = nil
                else
                    S.Aim.M = o[1]
                end
            end
        end
    })
    A:CreateDropdown({
        Name = "Target Part",
        Options = {"Head", "Body"},
        CurrentOption = {"Head"},
        Callback = function(o)
            if o and #o > 0 then
                S.Aim.TP = o[1]
            end
        end
    })
    A:CreateToggle({
        Name = "Skip Knocked",
        CurrentValue = true,
        Callback = function(v)
            S.Aim.SK = v
        end
    })
    A:CreateSection("Auto Aim")
    A:CreateToggle({
        Name = "Enable Auto Aim",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StopAimbot()
                C.StartAutoAim()
            else
                C.StopAutoAim()
            end
        end
    })
    A:CreateSlider({
        Name = "Auto Aim Distance",
        Range = {10, 150},
        Increment = 5,
        CurrentValue = 50,
        Callback = function(v)
            S.Aim.AAD = v
        end
    })
    A:CreateSlider({
        Name = "Auto Aim Smoothing",
        Range = {1, 10},
        Increment = 1,
        CurrentValue = 5,
        Callback = function(v)
            S.Aim.AAS = v / 10
        end
    })
    A:CreateSection("Aimbot")
    A:CreateToggle({
        Name = "Enable Aimbot",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StopAutoAim()
                C.StartAimbot()
            else
                C.StopAimbot()
            end
        end
    })
    A:CreateSlider({
        Name = "Aimbot Distance",
        Range = {10, 200},
        Increment = 5,
        CurrentValue = 50,
        Callback = function(v)
            S.Aim.ABD = v
        end
    })
    A:CreateSlider({
        Name = "Aimbot Smoothing",
        Range = {1, 10},
        Increment = 1,
        CurrentValue = 8,
        Callback = function(v)
            S.Aim.ABS = v / 10
        end
    })
    A:CreateSection("Silent Aim")
    A:CreateToggle({
        Name = "Enable Silent Aim",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartSilentAim()
            else
                C.StopSilentAim()
            end
        end
    })
    A:CreateSlider({
        Name = "Silent Aim Distance",
        Range = {5, 100},
        Increment = 5,
        CurrentValue = 30,
        Callback = function(v)
            S.Aim.SID = v
        end
    })
    A:CreateSection("Crosshair")
    A:CreateToggle({
        Name = "Enable Crosshair",
        CurrentValue = false,
        Callback = function(v)
            if v then
                C.StartCrosshair()
            else
                C.StopCrosshair()
            end
        end
    })
    A:CreateSlider({
        Name = "Crosshair Size",
        Range = {5, 50},
        Increment = 1,
        CurrentValue = 15,
        Callback = function(v)
            S.Vis.CS = v
        end
    })
    A:CreateSlider({
        Name = "Crosshair Gap",
        Range = {2, 30},
        Increment = 1,
        CurrentValue = 8,
        Callback = function(v)
            S.Vis.CG = v
        end
    })
    
    local STT = W:CreateTab("Settings", 4483362458)
    STT:CreateSection("ESP Colors")
    STT:CreateColorPicker({
        Name = "Killer Color",
        Color = S.Col.K,
        Callback = function(c)
            S.Col.K = c
            C.RefreshESPColors()
        end
    })
    STT:CreateColorPicker({
        Name = "Survivor Color",
        Color = S.Col.SV,
        Callback = function(c)
            S.Col.SV = c
            C.RefreshESPColors()
        end
    })
    STT:CreateColorPicker({
        Name = "Pallet Color",
        Color = S.Col.PL,
        Callback = function(c)
            S.Col.PL = c
            C.RefreshESPColors()
        end
    })
    STT:CreateSection("Generator Colors")
    STT:CreateColorPicker({
        Name = "Gen 0-49%",
        Color = S.Col.GL,
        Callback = function(c)
            S.Col.GL = c
        end
    })
    STT:CreateColorPicker({
        Name = "Gen 50-99%",
        Color = S.Col.GM,
        Callback = function(c)
            S.Col.GM = c
        end
    })
    STT:CreateColorPicker({
        Name = "Gen 100%",
        Color = S.Col.GH,
        Callback = function(c)
            S.Col.GH = c
        end
    })
    STT:CreateSection("Crosshair Colors")
    STT:CreateColorPicker({
        Name = "Crosshair Normal",
        Color = S.Col.CR,
        Callback = function(c)
            S.Col.CR = c
        end
    })
    STT:CreateColorPicker({
        Name = "Crosshair Locked",
        Color = S.Col.CL,
        Callback = function(c)
            S.Col.CL = c
        end
    })
    STT:CreateSection("Key System")
    STT:CreateButton({
        Name = "Clear Saved Key",
        Callback = function()
            DF(CFG.KF)
            DF(CFG.UF)
            SN("Success", "Key cleared!", 2)
        end
    })
    
    local keyStatusContent
    if IsServerConfigured() then
        keyStatusContent = "✅ Railway Server: ACTIVE\\n🔒 1 Key = 1 User: ENABLED\\n📦 Server: lua-protector-production"
    else
        keyStatusContent = "Standard Key System"
    end
    STT:CreateParagraph({Title = "Key Status", Content = keyStatusContent})
    
    STT:CreateSection("Server")
    STT:CreateButton({
        Name = "Rejoin Server",
        Callback = function()
            C.Rejoin()
        end
    })
    STT:CreateSection("Controls")
    STT:CreateButton({
        Name = "Refresh ESP Colors",
        Callback = function()
            C.RefreshESPColors()
        end
    })
    STT:CreateButton({
        Name = "Stop All Features",
        Callback = function()
            C.StopAll()
        end
    })
    STT:CreateButton({
        Name = "Destroy Hub",
        Callback = function()
            C.StopAll()
            R:Destroy()
            getgenv().UH = nil
            getgenv().UHLoaded = nil
        end
    })
    
    SN("Ultimate Hub", "Loaded! Welcome " .. LP.Name, 3)
end

if CKS() then
    LH()
end
`;

// ============================================
// FUNGSI: Detect jika request dari Roblox Executor
// ============================================
function isRobloxExecutor(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const robloxHeader = req.headers['roblox-id'] || req.headers['syn-fingerprint'] || req.headers['exploitid'];
    
    // Executor biasanya tidak punya user-agent browser standar
    const browserAgents = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera'];
    const isBrowser = browserAgents.some(agent => userAgent.includes(agent));
    
    // Cek apakah ada header khusus dari executor
    if (robloxHeader) {
        return true;
    }
    
    // Jika user-agent kosong atau bukan browser, kemungkinan executor
    if (!userAgent || userAgent === '' || userAgent.includes('roblox') || userAgent.includes('syn')) {
        return true;
    }
    
    // Cek custom header yang dikirim dari script
    if (req.headers['x-executor'] || req.headers['uh-client']) {
        return true;
    }
    
    // Jika dari browser standar, return false
    if (isBrowser && !req.headers['x-executor']) {
        return false;
    }
    
    return true;
}

// ============================================
// ENDPOINT: Root - Health Check
// ============================================
app.get('/', (req, res) => {
    // Jika dari browser, tampilkan HTML
    if (!isRobloxExecutor(req)) {
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    res.json({
        status: 'online',
        service: 'Ultimate Hub Key System',
        version: '1.0.0'
    });
});

// ============================================
// ENDPOINT: Get Script (Protected)
// ============================================
app.get('/script', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(PROTECTED_LOADER_SCRIPT);
});

app.get('/api/script', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(PROTECTED_LOADER_SCRIPT);
});

// ============================================
// ENDPOINT: Loader (Short URL)
// ============================================
app.get('/loader', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    res.setHeader('Content-Type', 'text/plain');
    res.send(PROTECTED_LOADER_SCRIPT);
});

// ============================================
// ENDPOINT: Validate Key
// ============================================
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;

        if (!key || key.length < 5) {
            return res.json({
                valid: false,
                message: "Invalid key format!"
            });
        }

        // Cek ke Work.ink API
        let isValidKey = false;
        try {
            const workinkResponse = await axios.get(WORKINK_API + key, {
                timeout: 10000
            });
            if (workinkResponse.data && workinkResponse.data.valid === true) {
                isValidKey = true;
            }
        } catch (err) {
            console.log("Work.ink API error:", err.message);
        }

        if (!isValidKey) {
            return res.json({
                valid: false,
                message: "Invalid key!"
            });
        }

        // Cek binding di database
        if (keyDatabase[key]) {
            const binding = keyDatabase[key];
            
            if (binding.hwid !== hwid) {
                return res.json({
                    valid: false,
                    bound_to_other: true,
                    bound_user: binding.userName,
                    message: "Key is bound to another user!"
                });
            }

            binding.lastUsed = Date.now();
            binding.useCount = (binding.useCount || 0) + 1;
            
            return res.json({
                valid: true,
                returning_user: true,
                message: "Welcome back, " + userName + "!"
            });
        }

        // Key baru - bind ke user
        keyDatabase[key] = {
            hwid: hwid,
            userId: userId,
            userName: userName,
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1
        };

        console.log(`[NEW BINDING] Key: ${key.substring(0, 8)}... -> User: ${userName} (${userId})`);

        return res.json({
            valid: true,
            new_binding: true,
            message: "Key registered successfully!"
        });

    } catch (error) {
        console.error("Validate error:", error);
        return res.json({
            valid: false,
            message: "Server error!"
        });
    }
});

// ============================================
// ENDPOINT: Check Key Binding
// ============================================
app.post('/api/check', (req, res) => {
    try {
        const { key, hwid, userId } = req.body;

        if (!key) {
            return res.json({ status: "error", message: "No key provided" });
        }

        if (keyDatabase[key]) {
            const binding = keyDatabase[key];
            
            if (binding.hwid === hwid) {
                return res.json({
                    status: "verified",
                    userName: binding.userName,
                    boundAt: binding.boundAt,
                    useCount: binding.useCount
                });
            } else {
                return res.json({
                    status: "bound_other",
                    userName: binding.userName
                });
            }
        }

        return res.json({ status: "new" });

    } catch (error) {
        console.error("Check error:", error);
        return res.json({ status: "error", message: "Server error" });
    }
});

// ============================================
// ENDPOINT: Bind Key
// ============================================
app.post('/api/bind', (req, res) => {
    try {
        const { key, hwid, userId, userName, boundAt } = req.body;

        if (!key || !hwid) {
            return res.json({ success: false, message: "Missing required fields" });
        }

        if (keyDatabase[key] && keyDatabase[key].hwid !== hwid) {
            return res.json({
                success: false,
                message: "Key already bound to another user"
            });
        }

        keyDatabase[key] = {
            hwid: hwid,
            userId: userId,
            userName: userName,
            boundAt: boundAt || Date.now(),
            lastUsed: Date.now(),
            useCount: 1
        };

        console.log(`[BIND] Key: ${key.substring(0, 8)}... -> User: ${userName}`);

        return res.json({ success: true, message: "Key bound successfully" });

    } catch (error) {
        console.error("Bind error:", error);
        return res.json({ success: false, message: "Server error" });
    }
});

// ============================================
// ENDPOINT: Stats
// ============================================
app.get('/api/stats', (req, res) => {
    // Protect stats endpoint juga
    if (!isRobloxExecutor(req) && !req.query.admin) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    const totalKeys = Object.keys(keyDatabase).length;
    const recentBindings = Object.entries(keyDatabase)
        .sort((a, b) => b[1].boundAt - a[1].boundAt)
        .slice(0, 10)
        .map(([key, data]) => ({
            key: key.substring(0, 8) + "...",
            userName: data.userName,
            boundAt: new Date(data.boundAt).toISOString(),
            useCount: data.useCount
        }));

    res.json({
        totalBoundKeys: totalKeys,
        recentBindings: recentBindings,
        serverUptime: process.uptime()
    });
});

// ============================================
// CATCH ALL - Show Not Authorized for unknown routes
// ============================================
app.use('*', (req, res) => {
    if (!isRobloxExecutor(req)) {
        res.setHeader('Content-Type', 'text/html');
        return res.send(NOT_AUTHORIZED_HTML);
    }
    
    res.status(404).json({ error: "Endpoint not found" });
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Ultimate Hub Key Server running on port ${PORT}`);
    console.log(`🔒 Script protection: ENABLED`);
    console.log(`📊 Stats: /api/stats`);
});
