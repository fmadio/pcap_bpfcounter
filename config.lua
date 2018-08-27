print("config file")
print(CreatePipeline)

CreatePipeline(
{
	["Name"] 			= "everything",
	["BPF"]  			= "",
	["RE"]   			= "",
	["Output"] 			= "/mnt/remote0/cap0.stats/",
})

CreatePipeline(
{
	["Name"] 			= "everything-tcp",
	["OutDir"] 			= "/mnt/remote0/cap0.stats/",
	["BPF"]  			= "tcp",
	["RE"]   			= "",
})

CreatePipeline(
{
	["Name"] 			= "vlan1-core-network",
	["OutDir"] 			= "/mnt/remote0/cap0.stats/",
	["BPF"]  			= "vlan 1",
	["RE"]   			= "",
})

CreatePipeline(
{
	["Name"] 			= "gw0-core-network",
	["BPF"]  			= "host 192.168.1.1",
	["RE"]   			= "",
	["OutputFile"] 		= "/mnt/remote0/cap0.stats/",
	["MicroBurst"] =
	{
		["TimeBucket"]		= 100e3,
		["Trigger"]			= 1e9,
	}
})

CreatePipeline(
{
	["Name"] 			= "gw1-core-network",
	["BPF"]  			= "host 192.168.2.1",
	["RE"]   			= "",
	["OutputFile"] 		= "/mnt/remote0/cap0.stats/",
	["MicroBurst"] =
	{
		["TimeBucket"]		= 100e3,
		["Trigger"]			= 1e9,
	}
})

