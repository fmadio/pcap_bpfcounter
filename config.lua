print("config file")

-- how often to generate output log entries
SetUpdateRate(60e9)

-- create pipelines
CreatePipeline(
{
	["Name"] 			= "everything",
	["BPF"]  			= "",
	["RE"]   			= "",
	["Output"] 			= "/mnt/remote0/cap0.stats",
})

CreatePipeline(
{
	["Name"] 			= "everything-tcp",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "tcp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

CreatePipeline(
{
	["Name"] 			= "everything-udp",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "udp",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

CreatePipeline(
{
	["Name"] 			= "base4",
	["Output"] 			= "/mnt/remote0/cap0.stats",
	["BPF"]  			= "host 192.168.2.136",
	["RE"]   			= "",
	["BurstTime"]		= 100e3,		
})

