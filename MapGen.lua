#!/usr/local/bin/fmadiolua

ffi = require("ffi")

ffi.cdef[[

typedef struct
{
	u32		Offset;
	u8		Name[128];
} LinkEntry_t;

]]

local Extern =
{
["aux_swap16"]			= true,
["aux_swap32"]			= true,
["aux_swap64"]			= true,

["fmad_rdtsc"]			= true,
["fmad_clock_ns"]		= true,
["fmad_usleep"]			= true,
["fmad_nsleep"]			= true,

}

local Entry = ffi.new("LinkEntry_t")
local Count = 0

local Out = io.open("symbol.bin", "w")

-- terminate
Entry.Offset = 0
Entry.Name = "___end__"; 
Out:write(ffi.string(Entry, ffi.sizeof("LinkEntry_t")))
Count = Count + 1

local FileName = assert(ARGV[1], "invalid input file")

local f = io.popen("readelf -s "..FileName)
for l in f:lines() do

	local s = l:split("[%s]+")

	if (#s < 4) then continue end
	local Offset = tonumber(s[3], 16)
	local Name = s[9] 
	local Type = s[5]	
	local Bind = s[6]	
	local Scope = s[7]	

	if (Type != "FUNC") then continue end
	if (Bind != "GLOBAL") then continue end
	if (Scope != "DEFAULT") then continue end

	if (Name == nil) then continue end
	if (Offset == nil) then continue end
	if (Offset == 0) then continue end

	--if (Extern[Name] == nil) then continue end

	Entry.Name 		= Name
	Entry.Offset 	= Offset 

	Out:write(ffi.string(Entry, ffi.sizeof("LinkEntry_t")))
	Count = Count + 1
end

--Entry.Offset = 1
--Entry.Name[127] = 9 
--Out:write(ffi.string(Entry, ffi.sizeof("LinkEntry_t")))
--Count = Count + 1

-- magic
local Magic = ffi.new("u32 [?]", 4)
Magic[0] = 0 
Magic[1] = Count 
Magic[2] = Count* ffi.sizeof("LinkEntry_t") 
Magic[3] = 0xbeef0001
Out:write(ffi.string(Magic, 16))

Out:close()
f:close()

return 0
