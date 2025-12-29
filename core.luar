--[[
    Ultimate Hub V9.3 - Core Script
    Upload file ini ke: github.com/trianaq765-cmd/ultimate-hub/blob/main/core.lua
]]

getgenv().UHCore = {}
local C = getgenv().UHCore

-- ============================================
-- SETTINGS
-- ============================================
C.S = {
    Plr = {SP = 16, SO = false},
    Kil = {AD = 15},
    Aim = {M = nil, TP = "Head", SK = true, AAD = 50, AAS = 0.5, ABD = 50, ABS = 0.8, SID = 30},
    Col = {
        K = Color3.fromRGB(255, 0, 0),
        SV = Color3.fromRGB(0, 255, 0),
        PL = Color3.fromRGB(255, 255, 0),
        GL = Color3.fromRGB(255, 100, 100),
        GM = Color3.fromRGB(255, 255, 100),
        GH = Color3.fromRGB(100, 255, 100),
        CR = Color3.fromRGB(255, 255, 255),
        CL = Color3.fromRGB(255, 0, 0)
    },
    Vis = {CS = 15, CG = 8}
}

-- Services
local Players = game:GetService("Players")
local Lighting = game:GetService("Lighting")
local TeleportService = game:GetService("TeleportService")
local RunService = game:GetService("RunService")
local LocalPlayer = Players.LocalPlayer

-- ============================================
-- FEATURE FUNCTIONS
-- ============================================

-- ESP (placeholder - ganti dengan implementasi sebenarnya)
C.StartKillerESP = function() print("[UH] Killer ESP Started") end
C.StopKillerESP = function() print("[UH] Killer ESP Stopped") end
C.StartSurvivorESP = function() print("[UH] Survivor ESP Started") end
C.StopSurvivorESP = function() print("[UH] Survivor ESP Stopped") end
C.StartGenESP = function() print("[UH] Generator ESP Started") end
C.StopGenESP = function() print("[UH] Generator ESP Stopped") end
C.StartPalletESP = function() print("[UH] Pallet ESP Started") end
C.StopPalletESP = function() print("[UH] Pallet ESP Stopped") end

-- Environment
C.StartNoFog = function() 
    Lighting.FogEnd = 100000 
    Lighting.FogStart = 100000
    print("[UH] No Fog Started") 
end
C.StopNoFog = function() 
    Lighting.FogEnd = 1000 
    Lighting.FogStart = 0
    print("[UH] No Fog Stopped") 
end
C.SetFullbright = function(v) 
    Lighting.Brightness = v and 2 or 1 
    Lighting.GlobalShadows = not v 
    Lighting.Ambient = v and Color3.new(1,1,1) or Color3.new(0.5, 0.5, 0.5)
end

-- Performance
C.StartAntiLag = function() 
    for _, v in pairs(game:GetDescendants()) do
        if v:IsA("ParticleEmitter") or v:IsA("Trail") then
            v.Enabled = false
        end
    end
    print("[UH] Anti-Lag Started") 
end
C.StopAntiLag = function() print("[UH] Anti-Lag Stopped") end

-- Killer Features
C.StartAutoAttack = function() print("[UH] Auto Attack Started") end
C.StopAutoAttack = function() print("[UH] Auto Attack Stopped") end
C.StartAntiBlind = function() print("[UH] Anti-Blind Started") end
C.StopAntiBlind = function() print("[UH] Anti-Blind Stopped") end
C.SetCameraMode = function(m) print("[UH] Camera Mode: " .. m) end

-- Speed
C.StartSpeed = function() 
    C.S.Plr.SO = true 
    C.ApplySpeed() 
    print("[UH] Speed Started") 
end
C.StopSpeed = function() 
    C.S.Plr.SO = false 
    local h = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("Humanoid") 
    if h then h.WalkSpeed = 16 end 
    print("[UH] Speed Stopped") 
end
C.ApplySpeed = function() 
    local h = LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("Humanoid") 
    if h then h.WalkSpeed = C.S.Plr.SP end 
end

-- Aim Features
C.StartAutoAim = function() print("[UH] Auto Aim Started") end
C.StopAutoAim = function() print("[UH] Auto Aim Stopped") end
C.StartAimbot = function() print("[UH] Aimbot Started") end
C.StopAimbot = function() print("[UH] Aimbot Stopped") end
C.StartSilentAim = function() print("[UH] Silent Aim Started") end
C.StopSilentAim = function() print("[UH] Silent Aim Stopped") end
C.StartCrosshair = function() print("[UH] Crosshair Started") end
C.StopCrosshair = function() print("[UH] Crosshair Stopped") end

-- Utility
C.RefreshESPColors = function() print("[UH] ESP Colors Refreshed") end
C.StopAll = function() 
    C.StopKillerESP()
    C.StopSurvivorESP()
    C.StopGenESP()
    C.StopPalletESP()
    C.StopNoFog()
    C.StopAntiLag()
    C.StopAutoAttack()
    C.StopAntiBlind()
    C.StopSpeed()
    C.StopAutoAim()
    C.StopAimbot()
    C.StopSilentAim()
    C.StopCrosshair()
    print("[UH] All Features Stopped") 
end
C.Rejoin = function() 
    TeleportService:TeleportToPlaceInstance(game.PlaceId, game.JobId) 
end
C.LoadScript = function(url) 
    pcall(function() loadstring(game:HttpGet(url))() end) 
end

C.GetPlayerList = function()
    local list = {}
    for _, p in pairs(Players:GetPlayers()) do
        if p ~= LocalPlayer then
            table.insert(list, p.Name)
        end
    end
    return list
end

C.TeleportTo = function(name)
    local target = Players:FindFirstChild(name)
    if target and target.Character and target.Character:FindFirstChild("HumanoidRootPart") then
        if LocalPlayer.Character and LocalPlayer.Character:FindFirstChild("HumanoidRootPart") then
            LocalPlayer.Character.HumanoidRootPart.CFrame = target.Character.HumanoidRootPart.CFrame
        end
    end
end

-- ============================================
-- LOAD RAYFIELD UI
-- ============================================
local success, Rayfield = pcall(function()
    return loadstring(game:HttpGet("https://sirius.menu/rayfield"))()
end)

if not success or not Rayfield then
    warn("[UH] Failed to load Rayfield")
    return
end

Rayfield.Notify = function() end

local Window = Rayfield:CreateWindow({
    Name = "Ultimate Hub V9.3 | ToingDC",
    LoadingTitle = "Ultimate Hub",
    LoadingSubtitle = "by ToingDC",
    ConfigurationSaving = {Enabled = false},
    KeySystem = false
})

getgenv().UH = Window

-- ============================================
-- ESP TAB
-- ============================================
local ESP = Window:CreateTab("ESP", 4483362458)
ESP:CreateSection("Player ESP")
ESP:CreateToggle({Name = "Killer ESP", CurrentValue = false, Callback = function(v) if v then C.StartKillerESP() else C.StopKillerESP() end end})
ESP:CreateToggle({Name = "Survivor ESP", CurrentValue = false, Callback = function(v) if v then C.StartSurvivorESP() else C.StopSurvivorESP() end end})
ESP:CreateSection("Object ESP")
ESP:CreateToggle({Name = "Generator ESP", CurrentValue = false, Callback = function(v) if v then C.StartGenESP() else C.StopGenESP() end end})
ESP:CreateToggle({Name = "Pallet ESP", CurrentValue = false, Callback = function(v) if v then C.StartPalletESP() else C.StopPalletESP() end end})

-- ============================================
-- SURVIVOR TAB
-- ============================================
local Survivor = Window:CreateTab("Survivor", 4483362458)
Survivor:CreateSection("Environment")
Survivor:CreateToggle({Name = "No Fog", CurrentValue = false, Callback = function(v) if v then C.StartNoFog() else C.StopNoFog() end end})
Survivor:CreateToggle({Name = "Fullbright", CurrentValue = false, Callback = function(v) C.SetFullbright(v) end})
Survivor:CreateSection("Performance")
Survivor:CreateToggle({Name = "Anti-Lag Mode", CurrentValue = false, Callback = function(v) if v then C.StartAntiLag() else C.StopAntiLag() end end})

-- ============================================
-- KILLER TAB
-- ============================================
local Killer = Window:CreateTab("Killer", 4483362458)
Killer:CreateSection("Auto Attack")
Killer:CreateToggle({Name = "Enable Auto Attack", CurrentValue = false, Callback = function(v) if v then C.StartAutoAttack() else C.StopAutoAttack() end end})
Killer:CreateSlider({Name = "Attack Distance", Range = {5, 30}, Increment = 1, CurrentValue = 15, Callback = function(v) C.S.Kil.AD = v end})
Killer:CreateSection("Protection")
Killer:CreateToggle({Name = "Anti-Blind", CurrentValue = false, Callback = function(v) if v then C.StartAntiBlind() else C.StopAntiBlind() end end})

-- ============================================
-- PLAYER TAB
-- ============================================
local Player = Window:CreateTab("Player", 4483362458)
Player:CreateSection("Speed")
local SpeedLabel = Player:CreateLabel("Speed: " .. C.S.Plr.SP)
Player:CreateButton({Name = "Speed -1", Callback = function() 
    C.S.Plr.SP = math.max(16, C.S.Plr.SP - 1) 
    SpeedLabel:Set("Speed: " .. C.S.Plr.SP) 
    if C.S.Plr.SO then C.ApplySpeed() end 
end})
Player:CreateButton({Name = "Speed +1", Callback = function() 
    C.S.Plr.SP = math.min(200, C.S.Plr.SP + 1) 
    SpeedLabel:Set("Speed: " .. C.S.Plr.SP) 
    if C.S.Plr.SO then C.ApplySpeed() end 
end})
Player:CreateToggle({Name = "Enable Speed", CurrentValue = false, Callback = function(v) if v then C.StartSpeed() else C.StopSpeed() end end})

Player:CreateSection("Teleport")
local SelectedPlayer = nil
local PlayerDropdown = Player:CreateDropdown({Name = "Select Player", Options = C.GetPlayerList(), Callback = function(o) if o and #o > 0 then SelectedPlayer = o[1] end end})
Player:CreateButton({Name = "Refresh", Callback = function() PlayerDropdown:Set(C.GetPlayerList()) end})
Player:CreateButton({Name = "Teleport", Callback = function() if SelectedPlayer then C.TeleportTo(SelectedPlayer) end end})

-- ============================================
-- AIM TAB
-- ============================================
local Aim = Window:CreateTab("Aim", 4483362458)
Aim:CreateSection("Target Settings")
Aim:CreateDropdown({Name = "Target Role", Options = {"Everyone", "Survivor", "Killer"}, CurrentOption = {"Everyone"}, Callback = function(o) 
    if o and #o > 0 then 
        if o[1] == "Everyone" then C.S.Aim.M = nil else C.S.Aim.M = o[1] end 
    end 
end})
Aim:CreateDropdown({Name = "Target Part", Options = {"Head", "Body"}, CurrentOption = {"Head"}, Callback = function(o) 
    if o and #o > 0 then C.S.Aim.TP = o[1] end 
end})

Aim:CreateSection("Auto Aim")
Aim:CreateToggle({Name = "Enable Auto Aim", CurrentValue = false, Callback = function(v) if v then C.StopAimbot() C.StartAutoAim() else C.StopAutoAim() end end})
Aim:CreateSlider({Name = "Auto Aim Distance", Range = {10, 150}, Increment = 5, CurrentValue = 50, Callback = function(v) C.S.Aim.AAD = v end})

Aim:CreateSection("Aimbot")
Aim:CreateToggle({Name = "Enable Aimbot", CurrentValue = false, Callback = function(v) if v then C.StopAutoAim() C.StartAimbot() else C.StopAimbot() end end})
Aim:CreateSlider({Name = "Aimbot Distance", Range = {10, 200}, Increment = 5, CurrentValue = 50, Callback = function(v) C.S.Aim.ABD = v end})

-- ============================================
-- SETTINGS TAB
-- ============================================
local Settings = Window:CreateTab("Settings", 4483362458)
Settings:CreateSection("ESP Colors")
Settings:CreateColorPicker({Name = "Killer Color", Color = C.S.Col.K, Callback = function(c) C.S.Col.K = c C.RefreshESPColors() end})
Settings:CreateColorPicker({Name = "Survivor Color", Color = C.S.Col.SV, Callback = function(c) C.S.Col.SV = c C.RefreshESPColors() end})
Settings:CreateColorPicker({Name = "Pallet Color", Color = C.S.Col.PL, Callback = function(c) C.S.Col.PL = c C.RefreshESPColors() end})

Settings:CreateSection("Controls")
Settings:CreateButton({Name = "Stop All", Callback = function() C.StopAll() end})
Settings:CreateButton({Name = "Rejoin", Callback = function() C.Rejoin() end})
Settings:CreateButton({Name = "Destroy Hub", Callback = function() 
    C.StopAll() 
    Rayfield:Destroy() 
    getgenv().UH = nil 
    getgenv().UHLoaded = nil 
end})

-- ============================================
-- DONE
-- ============================================
game:GetService("StarterGui"):SetCore("SendNotification", {
    Title = "Ultimate Hub", 
    Text = "Loaded! Welcome " .. LocalPlayer.Name, 
    Duration = 3
})

print("[Ultimate Hub] V9.3 Loaded Successfully!")
