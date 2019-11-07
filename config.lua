-- how often to generate output log entries
--SetUpdateRate(60e9)
Global_UpdateRate	(100e6)
Global_CaptureName	("bpfcounter_test")

-- debug mode
--Output_ESNULL()

-- select output mode
--Output_Mode("NULL")
Output_Mode("STDOUT")
--Output_Mode("ESPUSH")

-- add some ES Hosts
Output_ESHost("192.168.2.115", 9200) 

-- CPU Mapping
Output_CPUMap	({40, 41, 42, 43})
Pipe_CPUMap		({44, 45, 46, 47})

----------------------------------------------------------------------------

-- create pipelines
Pipe_Create(
{
	["Name"] 			= "everything",
	["BPF"]  			= "",
	["RE"]   			= "",
	["JSON"] 			= '"EtherSrc":"asdf","EtherDst":"popopoop"',
	["Output"] 			= "/mnt/remote0/cap0.stats",
})

Pipe_Create(
{
	["Name"] 			= "everything-tcp",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "tcp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

Pipe_Create(
{
	["Name"] 			= "everything-udp",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "udp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

Pipe_Create(
{
	["Name"] 			= "base4",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "host 192.168.2.136",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

