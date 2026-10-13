if not LPH_OBFUSCATED then
    LPH_ENCSTR = function(Value) return Value end
    LPH_ATTRIBUTES = function() end
    LPH_PRECHECK = function(Check) Check() end
    LPH_CRASH = function() error("Authentication failed") end
    VM = function() end
    PRESET = function() end
    ONYX = true
    SECURE = true
    FAST = true
end

LPH_PRECHECK(function()
    if type(request) == "function" and type(gethwid) == "function"
        and type(isfunctionhooked) == "function" and game:GetService("RunService"):IsClient()
        and game:GetService("Players").LocalPlayer ~= nil then
        return 0x5A719C3D
    end
    return 0
end, 0x5A719C3D)

local BaseURL = LPH_ENCSTR("AUTH_BASE_URL")
local ProjectID = LPH_ENCSTR("PROJECT_ID")
local ScriptID = LPH_ENCSTR("SCRIPT_ID")
local ScriptVersion = LPH_ENCSTR("SCRIPT_VERSION")
local HttpService = game:GetService("HttpService")
local Player = game:GetService("Players").LocalPlayer
local HWID = gethwid()
local UserID = tostring(Player.UserId)
local Key = rawget(getfenv(0), "Key")

if type(Key) ~= "string" or #Key == 0 or type(HWID) ~= "string" or #HWID == 0 then
    LPH_CRASH()
end

if isfunctionhooked(request) then
    LPH_CRASH()
end

local function Send(Path, Data, Token, Raw)
    LPH_ATTRIBUTES(PRESET(FAST))
    local Headers = {
        ["Content-Type"] = "application/json",
        ["x-luashield-executor"] = "potassium"
    }
    if Token then
        Headers.Authorization = "Bearer " .. Token
    end
    local Response = request({
        Url = BaseURL .. Path,
        Method = "POST",
        Headers = Headers,
        Body = HttpService:JSONEncode(Data)
    })
    if not Response or Response.StatusCode ~= 200 then
        LPH_CRASH()
    end
    if Raw then
        return Response.Body
    end
    return HttpService:JSONDecode(Response.Body)
end

local function Authenticate()
    LPH_ATTRIBUTES(VM(ONYX), PRESET(SECURE))
    local Challenge = Send("/auth/challenge", {
        project_id = ProjectID,
        script_id = ScriptID,
        hwid = HWID,
        user_id = UserID
    })
    local Result = Send("/auth/authorize", { challenge = Challenge.challenge, key = Key })
    if type(Result.token) ~= "string" or Result.version ~= ScriptVersion then
        LPH_CRASH()
    end
    return Result
end

local Result = Authenticate()
local SessionToken = Result.token
local LS_ScriptName = Result.script
local LS_ScriptVersion = Result.version
local LS_Username = Result.username
local LS_Executions = Result.executions
local LS_CrackAttempts = Result.crack_attempts
local LS_Exploit = Result.exploit

local function LS_SecureWebhook(Url, Body)
    LPH_ATTRIBUTES(VM(ONYX), PRESET(SECURE))
    local Response = request({
        Url = Url,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["LuaShield-Access-Token"] = SessionToken
        },
        Body = HttpService:JSONEncode(Body)
    })
    if not Response or Response.StatusCode ~= 200 then
        LPH_CRASH()
    end
    return true
end

task.spawn(function()
    while task.wait(15) do
        local Success = pcall(function()
            local Response = Send("/auth/heartbeat", {}, SessionToken)
            if not Response.valid then
                LPH_CRASH()
            end
        end)
        if not Success then
            Player:Kick("LuaShield: Your license session has expired")
            return
        end
    end
end)

-- The protected script is only released to an authorized session, and only once.
local Payload = Send("/auth/payload", {}, SessionToken, true)
local Chunk, CompileError = loadstring(Payload)
if not Chunk then
    LPH_CRASH()
end

-- Protected scripts receive this table as `...` (local Info = ...).
Chunk({
    ScriptName = LS_ScriptName,
    Version = LS_ScriptVersion,
    Username = LS_Username,
    Executions = LS_Executions,
    CrackAttempts = LS_CrackAttempts,
    Exploit = LS_Exploit,
    SecureWebhook = LS_SecureWebhook
})
