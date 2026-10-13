-- Runs client/client.lua under a mocked Roblox/executor environment and checks the loader flow:
-- challenge -> authorize -> payload (run once) and the heartbeat/webhook helpers.
-- No Roblox or real executor involved; this exercises control flow, not Luraph output.

local Passed, Failed = 0, 0
local function check(Name, Ok)
    if Ok then Passed = Passed + 1; print("ok   - " .. Name)
    else Failed = Failed + 1; print("FAIL - " .. Name) end
end

-- Minimal JSON stand-in: a registry maps opaque tokens to tables, so we test flow without a parser.
local function makeJson()
    local Store, N = {}, 0
    return {
        JSONEncode = function(_, Value) N = N + 1; local K = "j" .. N; Store[K] = Value; return K end,
        JSONDecode = function(_, Token) return Store[Token] end
    }
end

-- Build a fresh global environment and run the client. `opts.responder(url, body, token)` returns
-- a fake HTTP response. Returns a table describing what happened.
local function runClient(opts)
    local Calls = {}
    local HttpService = makeJson()
    local Kicked
    local Ran

    local Player = { UserId = 123456, Kick = function(_, Reason) Kicked = Reason end }
    local Services = {
        HttpService = HttpService,
        RunService = { IsClient = function() return true end },
        Players = { LocalPlayer = Player }
    }

    -- Install globals the client relies on.
    _G.LPH_OBFUSCATED = nil
    _G.Key = opts.key
    _G.request = function(Req)
        -- Token is the Bearer value, if any.
        local Token = Req.Headers and Req.Headers.Authorization
        if Token then Token = Token:gsub("^Bearer ", "") end
        Calls[#Calls + 1] = { url = Req.Url, token = Token, access = Req.Headers and Req.Headers["LuaShield-Access-Token"] }
        local Resp = opts.responder(Req.Url, HttpService:JSONDecode(Req.Body), Token, HttpService)
        -- The client decodes Body as JSON; turn table bodies into encodable tokens, leave raw strings
        -- (the payload) untouched.
        if type(Resp.Body) == "table" then Resp.Body = HttpService:JSONEncode(Resp.Body) end
        return Resp
    end
    _G.gethwid = function() return opts.hwid or "device-1" end
    _G.isfunctionhooked = function() return opts.hooked == true end
    _G.game = { GetService = function(_, Name) return Services[Name] end }
    _G.task = {
        spawn = function(Fn) Fn() end,
        -- Let the heartbeat loop body run exactly once, then stop.
        wait = (function() local Once = true; return function() local V = Once; Once = false; return V end end)()
    }
    _G.__record = function(Info) Ran = Info end

    -- Mirror server BuildLoader: substitute the placeholders the publisher fills in.
    local File = assert(io.open("client/client.lua", "r"))
    local Source = File:read("*a"); File:close()
    local Subs = {
        AUTH_BASE_URL = "http://test", PROJECT_ID = "proj-1",
        SCRIPT_ID = "script-1", SCRIPT_VERSION = opts.version or "v1.0.0"
    }
    for Token, Value in pairs(Subs) do
        Source = Source:gsub(Token, function() return Value end)
    end
    local Chunk = assert(loadstring(Source, "client"))
    local Ok, Err = pcall(Chunk)
    return { ok = Ok, err = Err, calls = Calls, kicked = Kicked, ran = Ran }
end

local Version = "v1.0.0"

-- A responder for the happy path.
local function happyResponder(Url, _Body, Token)
    if Url:find("/auth/challenge$") then
        return { StatusCode = 200, Body = { challenge = ("a"):rep(64) } }
    elseif Url:find("/auth/authorize$") then
        return { StatusCode = 200, Body = {
            token = "session-token", script = "MyScript", version = Version,
            username = "alice", executions = 3, crack_attempts = 0, exploit = "Potassium"
        } }
    elseif Url:find("/auth/heartbeat$") then
        return { StatusCode = 200, Body = { valid = true } }
    elseif Url:find("/auth/payload$") then
        -- Raw body: real Lua that records the Info table it receives.
        return { StatusCode = 200, Body = "__record(...)" }
    end
    return { StatusCode = 404, Body = {} }
end

-- Scenario 1: valid license runs the payload with the right Info and uses the bearer token.
do
    local R = runClient({ key = "valid-key", responder = happyResponder })
    check("client runs to completion on a valid license", R.ok)
    check("payload executed once with Info", R.ran ~= nil)
    check("Info carries the username from authorize", R.ran and R.ran.Username == "alice")
    check("Info carries script name and version", R.ran and R.ran.ScriptName == "MyScript" and R.ran.Version == Version)
    -- Verify the call sequence and bearer usage.
    local urls = {}
    for _, C in ipairs(R.calls) do urls[#urls + 1] = C.url end
    local function hit(suffix) for _, u in ipairs(urls) do if u:find(suffix) then return true end end return false end
    check("called /auth/challenge", hit("/auth/challenge$"))
    check("called /auth/authorize", hit("/auth/authorize$"))
    check("called /auth/payload with the session token", (function()
        for _, C in ipairs(R.calls) do if C.url:find("/auth/payload$") then return C.token == "session-token" end end
        return false
    end)())
    -- SecureWebhook helper should post with the access-token header.
    check("Info.SecureWebhook is callable", type(R.ran and R.ran.SecureWebhook) == "function")
    if R.ran and R.ran.SecureWebhook then
        local okHook = pcall(function()
            -- Patch request to a webhook responder for this call.
            local Prev = _G.request
            _G.request = function(Req) return { StatusCode = 200, Body = "ok" } end
            R.ran.SecureWebhook("https://example.com/hook", { content = "hi" })
            _G.request = Prev
        end)
        check("SecureWebhook succeeds on a 200", okHook)
    end
end

-- Scenario 2: authorize fails -> LPH_CRASH -> error, and the payload never runs.
do
    local R = runClient({ key = "bad-key", responder = function(Url)
        if Url:find("/auth/challenge$") then return { StatusCode = 200, Body = { challenge = ("a"):rep(64) } } end
        if Url:find("/auth/authorize$") then return { StatusCode = 403, Body = {} } end
        return { StatusCode = 404, Body = {} }
    end })
    check("client errors when authorization fails", not R.ok)
    check("payload never runs on failed authorization", R.ran == nil)
end

-- Scenario 3: a missing key crashes before any request is made.
do
    local R = runClient({ key = nil, responder = happyResponder })
    check("client errors when no key is present", not R.ok)
    check("no requests made without a key", #R.calls == 0)
end

print(string.format("\n%d passed, %d failed", Passed, Failed))
os.exit(Failed == 0 and 0 or 1)
