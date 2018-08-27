print("ass")
--for i=1,100 do

--local a = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
local i = 0
--while i < 100 do
--for i=1,100 do
--for i in pairs(a) do
while (i < 15) do

	i = i + 1

	if (i > 14) then break end

	if (i < 10) then continue end

	print(i)
end
print("done")
