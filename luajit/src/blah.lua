#!./luajit

local ffi = require("ffi")

local str = "16.3300"

v2 = 0
sub = nil 
for i=1,#str do

	local c = str:byte(i) 

	-- decimal point
	if (c == 0x2e) then
		sub = i 
		continue
	end

	c = c - 0x30
	if (c < 0) or (c > 9) then continue end

	if (sub == nil) then
		v2 = v2 * 10 + c
	else
		v2 = v2 + c * ( 1.0 / math.pow(10, i - sub))
	end
end

print(v2)

local v = v2 --math.ceil( tonumber(str) * 100) / 100

local int = v * 10000

print(string.format("%f %i %f\n", v, int, int))

