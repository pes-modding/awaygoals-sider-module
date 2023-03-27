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
        pattern = '\x41\x8d\x0c\x50\x42\x8d\x04\x4b\x3b\xc1',
        changes = {
            { offset = 3, old = '\x50', new = '\x10' },
            { offset = 7, old = '\x4b', new = '\x0b' },
        }
    },
    {
        pattern = '\x43\x8d\x0c\x41\x43\x8d\x04\x56\x3b\xc1',
        changes = {
            { offset = 3, old = '\x41', new = '\x01' },
            { offset = 7, old = '\x56', new = '\x16' },
        }
    },
    {
        pattern = '\x80\x7d\x69\x00\x74\x08\x8d\x04\x09',
        changes = {
            { offset = 7, old = '\x04', new = '\x01' },
            { offset = 8, old = '\x09', new = '\x90' },
        }
    },
    {
        pattern = '\x8d\x0c\x41\x8b\x84\x24\x94\x00\x00\x00\x89\x4c\x24\x28\x8d\x34\x00',
        changes = {
            { offset = 2, old = '\x41', new = '\x01' },
            { offset = 15, old = '\x34', new = '\x30' },
            { offset = 16, old = '\x00', new = '\x90' },
        }
    },
    {
        pattern = '\x0f\xb6\x4e\x1f\x0f\xb6\x50\x1f\x89\x4d\x38\x89\x55\xf0\x3b\xca\x74\x70',
        changes = {
            { offset = 16, old = '\x74', new = '\xeb' },
        }
    },
    {
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
    return string.format("%s | current state: %s | press %s to toggle", m.version, state, toggle.label)
end

function m.init(ctx)
    ctx.register("overlay_on", m.overlay_on)
    ctx.register("key_down", m.key_down)
    -- verify that we can patch this exe: find all addresses
    find_patterns()
    -- start with away goals disabled
    set_away_goals_rule(false)
end

return m
