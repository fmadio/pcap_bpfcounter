-- how often to generate output log entries
--SetUpdateRate(60e9)
Global_UpdateRate	(100e6)
Global_CaptureName	("bpfcounter_test")

-- debug mode
--Output_ESNULL()

-- select output mode
--Output_Mode("NULL")
--Output_Mode("STDOUT")
Output_Mode("ESPUSH")

-- set 1sec keep alive
Output_ESKeepAlive(true, 1e9)

-- add some ES Hosts
Output_ESHost	("192.168.2.176", 9200) 

-- CPU Mapping
--Output_CPUMap	({40, 41, 42, 43})
--Pipe_CPUMap		({44, 45, 46, 47})

----------------------------------------------------------------------------

-- create pipelines
Pipe_Create(
{
	["Name"] 			= "everything",
	["BPF"]  			= "",
	["RE"]   			= "",
	["JSON"] 			= '"EtherSrc":"00:00:00:00:00:00","EtherDst":"11:11:11:11:11:11"',
})

Pipe_Create(
{
	["Name"] 			= "everything-tcp",
	["BPF"]  			= "tcp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

Pipe_Create(
{
	["Name"] 			= "everything-udp",
	["BPF"]  			= "udp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

Pipe_Create(
{
	["Name"] 			= "base4",
	["BPF"]  			= "host 192.168.2.136",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

