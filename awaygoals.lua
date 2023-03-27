-- awaygoals.lua
-- module that disables "Away Goals" in 2-legged matches in all competitions

local m = { version = "v1.0" }

-- keyboard controls
local toggle = {
    label = "[0]", vkey = 0x30
}

-- patch data structure
-- the idea here to have an "adaptable" patch, where offsets are not hard-coded
-- for specific version of the game EXE, but are found dynamically on game startup
-- using code patterns.
local patch = {
    {
        --[[
        000000014042E388 | 41:8D0C50                       | lea ecx,qword ptr ds:[r8+rdx*2]         |
        000000014042E38C | 42:8D044B                       | lea eax,qword ptr ds:[rbx+r9*2]         |
        000000014042E390 | 3BC1                            | cmp eax,ecx                             | checking for away goals
        --]]
        pattern = '\x41\x8d\x0c\x50\x42\x8d\x04\x4b\x3b\xc1',
        changes = {
            { offset = 3, old = '\x50', new = '\x10' },
            { offset = 7, old = '\x4b', new = '\x0b' },
        }
    },
    {
        --[[
        0000000140449ECF | 43:8D0C41                       | lea ecx,qword ptr ds:[r9+r8*2]          | team A: home goals + away goals doubled
        0000000140449ED3 | 43:8D0456                       | lea eax,qword ptr ds:[r14+r10*2]        | team B: home goals + away goals doubled
        0000000140449ED7 | 3BC1                            | cmp eax,ecx                             | check aggregate score with away goals doubled
        --]]
        pattern = '\x43\x8d\x0c\x41\x43\x8d\x04\x56\x3b\xc1',
        changes = {
            { offset = 3, old = '\x41', new = '\x01' },
            { offset = 7, old = '\x56', new = '\x16' },
        }
    },
    {
        --[[
        000000014044A501 | 807D 69 00                      | cmp byte ptr ss:[rbp+69],0              | check if away goals matter in extra time
        000000014044A505 | 74 08                           | je pes2021.14044A50F                    |
        000000014044A507 | 8D0409                          | lea eax,qword ptr ds:[rcx+rcx]          | double the away goals
        --]]
        pattern = '\x80\x7d\x69\x00\x74\x08\x8d\x04\x09',
        changes = {
            { offset = 7, old = '\x04', new = '\x01' },
            { offset = 8, old = '\x09', new = '\x90' },
        }
    },
    {
        --[[
        000000014147DB47 | 8D0C41                          | lea ecx,qword ptr ds:[rcx+rax*2]        | double AG: commentary
        000000014147DB4A | 8B8424 94000000                 | mov eax,dword ptr ss:[rsp+94]           |
        000000014147DB51 | 894C24 28                       | mov dword ptr ss:[rsp+28],ecx           |
        000000014147DB55 | 8D3400                          | lea esi,qword ptr ds:[rax+rax]          | double AG: commentary
        --]]
        pattern = '\x8d\x0c\x41\x8b\x84\x24\x94\x00\x00\x00\x89\x4c\x24\x28\x8d\x34\x00',
        changes = {
            { offset = 2, old = '\x41', new = '\x01' },
            { offset = 15, old = '\x34', new = '\x30' },
            { offset = 16, old = '\x00', new = '\x90' },
        }
    },
    {
        --[[
        000000014151A5B4 | 0FB64E 1F                       | movzx ecx,byte ptr ds:[rsi+1F]          |
        000000014151A5B8 | 0FB650 1F                       | movzx edx,byte ptr ds:[rax+1F]          |
        000000014151A5BC | 894D 38                         | mov dword ptr ss:[rbp+38],ecx           |
        000000014151A5BF | 8955 F0                         | mov dword ptr ss:[rbp-10],edx           |
        000000014151A5C2 | 3BCA                            | cmp ecx,edx                             | compare away goals
        000000014151A5C4 | 74 70                           | je pes2021.14151A636                    |
        --]]
        pattern = '\x0f\xb6\x4e\x1f\x0f\xb6\x50\x1f\x89\x4d\x38\x89\x55\xf0\x3b\xca\x74\x70',
        changes = {
            { offset = 16, old = '\x74', new = '\xeb' },
        }
    },
    {
        --[[
        000000014151A688 | 74 48                           | je pes2021.14151A6D2                    | check either how many ET goals or if away ET goals matter
        000000014151A68A | 8B4D 38                         | mov ecx,dword ptr ss:[rbp+38]           |
        000000014151A68D | 85C9                            | test ecx,ecx                            |
        000000014151A68F | 74 41                           | je pes2021.14151A6D2                    |
        000000014151A691 | 48:8B75 E8                      | mov rsi,qword ptr ss:[rbp-18]           |
        --]]
        pattern = '\x74\x48\x8b\x4d\x38\x85\xc9\x74\x41\x48\x8b\x75\xe8',
        changes = {
            { offset = 0, old = '\x74', new = '\xeb' },
        }
    },
}

local function find_patterns()
    all_found = true
    for i, entry in ipairs(patch) do
        local addr = memory.search_process(entry.pattern)
        if not addr then
            error(string.format("unable to find pattern %d. exiting", i))
        end
        for _, c in ipairs(entry.changes) do
            local b = memory.read(addr + c.offset, 1)
            if b ~= c.old and b ~= c.new then
                error(string.format("got unexpected value %s at %s. exiting", hex(b), hex(addr + c.offset)))
            end
        end
        -- store the address in patch structure
        entry.addr = addr
    end
end

local function is_away_goals_enabled()
    for _, entry in ipairs(patch) do
        for _, c in ipairs(entry.changes) do
            if memory.read(entry.addr + c.offset, 1) == c.new then
                return false
            end
        end
    end
    return true
end

local function set_away_goals_rule(enabled)
    log(string.format("setting away-goals to: enabled = %s", enabled))
    for _, entry in ipairs(patch) do
        for _, c in ipairs(entry.changes) do
            local baddr = entry.addr + c.offset
            local was = memory.unpack("u8", memory.read(baddr, 1))
            if enabled then
                memory.write(baddr, c.old)
            else
                memory.write(baddr, c.new)
            end
            local now = memory.unpack("u8", memory.read(baddr, 1))
            log(string.format("AG patch applied: %s: 0x%02x -> 0x%02x", memory.hex(baddr), was, now))
        end
    end
    log(string.format("away-goals is now: %s", enabled and "ON" or "OFF"))
end

function m.key_down(ctx, vkey)
    if vkey == toggle.vkey then
        local current_state = is_away_goals_enabled()
        set_away_goals_rule(not current_state)
    end
end

function m.overlay_on(ctx)
    local state = is_away_goals_enabled() and "Away Goals ON" or "Away Goals OFF"
    return string.format("%s: current state: %s | press %s to toggle", m.version, state, toggle.label)
end

function m.init(ctx)
    ctx.register("overlay_on", m.overlay_on)
    ctx.register("key_down", m.key_down)
    -- verify that we can patch this exe
    find_patterns()
    -- start with away goals disabled
    set_away_goals_rule(false)
end

return m
