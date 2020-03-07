local ffi = require("ffi")

ffi.cdef[[

	struct Output_t;
	struct Output_t* 		Output_Create(	bool IsNULL, 
											bool IsSTDOUT, 
											bool IsESOut, 	
											bool IsCompress, 
											bool IsESNULL, 
											u32 Output_BufferCnt, 
											u32 Output_KeepAlive, 
											double Output_KeepAliveTimeout, 
											u32 Output_FilterPath, 
											u8* QueuePath, 
											u32 ThreadCnt,
											u32 CPUCnt,
											u32* CPUMap);

	void 					Output_ESHostAdd			(struct Output_t* Out, u8* HostName, u32 HostPort);

	void 					Global_SetDeviceName		(u8* DeviceName);

	// pipeline status
	struct Pipeline_t;
	struct Pipeline_t* 		Pipe_Create					(u8* Name);
	int 					Pipe_SetBPF					(struct Pipeline_t* Pipe, u8* BPFString);
	int 					Pipe_SetFastFilterMACSrc	(struct Pipeline_t* Pipe, u8 MAC0, u8 MAC1, u8 MAC2, u8 MAC3, u8 MAC4, u8 MAC5); 
	int 					Pipe_SetFastFilterMACDst	(struct Pipeline_t* Pipe, u8 MAC0, u8 MAC1, u8 MAC2, u8 MAC3, u8 MAC4, u8 MAC5); 

	int 					Pipe_SetBurstTime			(struct Pipeline_t* Pipe, double TimeBucketNS);
	int 					Pipe_SetUpdateRate			(double OutputNS);
	void					Pipe_SetOutput				(struct Output_t* Output);
	void 					Pipe_SetCaptureName			(u8* CaptureName);
	void 					Pipe_SetCPUCore				(int CPU); 
	void 					Pipe_SetCPUWorker			(int CPUCnt, u32* CPUMap);
	void 					Pipe_SetUserJSON			(struct Pipeline_t* Pipe, u8* UserJSON);


]]

-----------------------------------------------------------------------------------------------------------------------------------
-- builtins 
function string:split( inSplitPattern, outResults )

	if not outResults then
		outResults = { }
	end
	local theStart = 1
	local theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
	while theSplitStart do
		table.insert( outResults, string.sub( self, theStart, theSplitStart-1 ) )
		theStart = theSplitEnd + 1
		theSplitStart, theSplitEnd = string.find( self, inSplitPattern, theStart )
	end

	table.insert( outResults, string.sub( self, theStart ) )
	return outResults
end

function string:strip()
	return self:gsub("^%s*(.-)%s*$", "%1")
end

function trace(Message, ...)
	io.stderr:write( string.format(Message, unpack({...})))
end




-----------------------------------------------------------------------------------------------------------------------------------

local Output_IsNULL 			= false;
local Output_IsSTDOUT 			= false;
local Output_IsESPUSH 			= false;
local Output_IsCompress 		= false;
local Output_IsESNULL 			= false;

local Output_IsCompress 		= false;
local Output_IsESNULL 			= false;

local Output_ESHostList 		= {};
local Output_ThreadCount		= 32 
local Output_CPUMapList 		= {0, 1, 2, 3};

local Output_KeepAlive			= true;
local Output_KeepAliveTimeout	= 10e9;
local Output_FilterPath			= true;

local Pipe_CPUMapList 			= {}
local Pipe_IsDisableFastFilter 	= false;				-- optional disable fast filters	

-----------------------------------------------------------------------------------------------------------------------------------
-- setup default cpu maps based on command line args 
for i,j in ipairs(ARGV) do

	-- cpu core cpu 
	if (j == "--cpu-core") then 
		local CPU = tonumber( ARGV[i + 1] ) 
		ffi.C.Pipe_SetCPUCore(CPU)
	end

	-- cpu pipe workers assignment
	if (j == "--cpu-pipe") then 

		local CPUCnt = tonumber( ARGV[i + 1] ) 
		local CPUList = {} 
		for a=0,CPUCnt-1 do
			table.insert(CPUList, tonumber( ARGV[ i + 2 + a] ))
		end	

		-- set mapping
		local _CPUList = ffi.new("int[128]", CPUList) 
		ffi.C.Pipe_SetCPUWorker(#CPUList, _CPUList)
	end

	-- cpu mapping for output workers 
	if (j == "--cpu-output") then 

		local CPUCnt = tonumber( ARGV[i + 1] ) 
		local CPUList = {} 
		for a=0,CPUCnt-1 do
			table.insert(CPUList, tonumber( ARGV[ i + 2 + a] ))
		end	
		Output_CPUMapList = CPUList
	end

end

-----------------------------------------------------------------------------------------------------------------------------------
-- sets what kind of output mode to use
Output_Mode = function(Mode)

	if (Mode == "NULL") then
		Output_IsNULL = true;
	end	
	if (Mode == "STDOUT") then
		Output_IsSTDOUT = true;
	end	
	if (Mode == "ESPUSH") then
		Output_IsESPUSH = true;
	end	
end

-----------------------------------------------------------------------------------------------------------------------------------
-- sets the output thread cpu mapping
Output_CPUMap = function(CPUMap)

	Output_CPUMapList = CPUMap
end

-----------------------------------------------------------------------------------------------------------------------------------
-- add an ES host output
Output_ESHost = function(Host, Port)

	table.insert(Output_ESHostList, { Host = Host, Port = Port })
end

-----------------------------------------------------------------------------------------------------------------------------------
-- Set Keep Alive setting 
Output_ESKeepAlive = function(Enable, Timeout)

	Output_KeepAlive 		= Enable
	Output_KeepAliveTimeout = Timeout 
end

-----------------------------------------------------------------------------------------------------------------------------------
-- set the total number of output threads
Output_ThreadCnt = function(Cnt)
	Output_ThreadCount = Cnt
end

-----------------------------------------------------------------------------------------------------------------------------------
-- creates the output backend
Output_Create = function(Mode)

	local _CPUMap = ffi.new("int[128]", Output_CPUMapList) 

	local Output  = ffi.C.Output_Create(	Output_IsNULL, 
											Output_IsSTDOUT, 
											Output_IsESPUSH, 
											Output_IsCompress, 
											Output_IsESNULL, 
											64, 
											Output_KeepAlive,
											Output_KeepAliveTimeout,
											Output_FilterPath,
											nil,
											Output_ThreadCount,
											#Output_CPUMapList,
											_CPUMap);

	-- add any ES Hosts
	for i,Info in ipairs(Output_ESHostList) do
		ffi.C.Output_ESHostAdd(Output, ffi.cast("u8*", Info.Host), Info.Port)
	end

	return Output
end

-----------------------------------------------------------------------------------------------------------------------------------
-- PCAP snapshot period
Global_UpdateRate = function(Rate)

	ffi.C.Pipe_SetUpdateRate(Rate);
end

-----------------------------------------------------------------------------------------------------------------------------------
-- sets the capture name 
Global_CaptureName = function(Name)

	ffi.C.Pipe_SetCaptureName( ffi.cast("u8*", Name) );
end

-----------------------------------------------------------------------------------------------------------------------------------
-- dummy handlers for analytics configuration settings
Global_FollowNow 	= function(Name) end


-----------------------------------------------------------------------------------------------------------------------------------
-- explicitly set device name 
Global_DeviceName 	= function(Name) 
	ffi.C.Global_SetDeviceName( ffi.cast("u8*", Name))
end

-----------------------------------------------------------------------------------------------------------------------------------
-- disable fast path 
Pipe_DisableFastFilter 	= function() 
	trace("Disable Fast Filter\n");
	Pipe_IsDisableFastFilter = true;	
end


-----------------------------------------------------------------------------------------------------------------------------------
-- sets the output thread cpu mapping
Pipe_CPUMap = function(CPUMap)

	local _CPUMap = ffi.new("int[128]", CPUMap)
	ffi.C.Pipe_SetCPUWorker( #CPUMap, _CPUMap);
end

-----------------------------------------------------------------------------------------------------------------------------------
local Pipe_FastBPF = function(Pipe, Name, BPF)

	if (Pipe_IsDisableFastFilter) then return nil end

	local s = BPF:split("%s+")
	--for a,b in ipairs(s) do  print(a, "["..b.."]") end

	-- check simple ether src 
	if (#s == 3) and (s[1] == "ether") and (s[2] == "src") then

		local MAC = s[3]:split(":")

		MAC[1] = tonumber("0x"..MAC[1])
		MAC[2] = tonumber("0x"..MAC[2])
		MAC[3] = tonumber("0x"..MAC[3])
		MAC[4] = tonumber("0x"..MAC[4])
		MAC[5] = tonumber("0x"..MAC[5])
		MAC[6] = tonumber("0x"..MAC[6])

		ffi.C.Pipe_SetFastFilterMACSrc(Pipe, MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], MAC[6]);
		--trace("[%-40s] MACSrcFilter: ether src filter %02x:%02x:%02x:%02x:%02x:%02x [%s]\n", Name, MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], MAC[6], BPF);

		return true
	end

	-- check simple ether dst 
	if (#s == 3) and (s[1] == "ether") and (s[2] == "dst") then

		local MAC = s[3]:split(":")

		MAC[1] = tonumber("0x"..MAC[1])
		MAC[2] = tonumber("0x"..MAC[2])
		MAC[3] = tonumber("0x"..MAC[3])
		MAC[4] = tonumber("0x"..MAC[4])
		MAC[5] = tonumber("0x"..MAC[5])
		MAC[6] = tonumber("0x"..MAC[6])

		ffi.C.Pipe_SetFastFilterMACDst(Pipe, MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], MAC[6]);
		--trace("[%-40s] MACSrcFilter: ether src filter %02x:%02x:%02x:%02x:%02x:%02x [%s]\n", Name, MAC[1], MAC[2], MAC[3], MAC[4], MAC[5], MAC[6], BPF);

		return true
	end

end

-----------------------------------------------------------------------------------------------------------------------------------
-- top level 
Pipe_Create = function(Info)

	-- create output object if it has not been created yet
	if (Output == nil) then
		Output = Output_Create()

		-- set the output device to use
		ffi.C.Pipe_SetOutput(Output);
	end

	-- create the pipeline
	local Pipe = ffi.C.Pipe_Create( ffi.cast("u8*", Info.Name))


	-- check for fast path optimizations
	if (Pipe_FastBPF(Pipe, Info.Name, Info.BPF) == nil) then	

		-- fallback to regular BPF 
		if (ffi.C.Pipe_SetBPF(Pipe, ffi.cast("u8*", Info.BPF)) < 0 ) then
			return
		end
	end

	-- set burst rate (if passed) 
	if (tonumber(Info.BurstTime) != nil) then
		ffi.C.Pipe_SetBurstTime(Pipe, tonumber(Info.BurstTime))
	end

	-- if user specified JSON is added
	if (Info.JSON != nil) then
		ffi.C.Pipe_SetUserJSON(Pipe, ffi.cast("u8*", Info.JSON))
	end
end
