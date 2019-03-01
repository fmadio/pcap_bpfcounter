SetUpdateRate = function(Rate)

	pipe.output_time(Rate)

end

CreatePipeline = function(Info)

	-- create the pipeline
	local Index = pipe.create(Info.Name)

	-- set the BPF expression
	if (pipe.bpf(Index, Info.BPF) != nil) then
		return
	end

	-- set burst rate (if passed) 
	if (tonumber(Info.BurstTime) != nil) then
		pipe.burst(Index, tonumber(Info.BurstTime))
	end

	-- open the output file 
	local d = os.ns2clock( os.clock_ns() )  
	local FileName = string.format(Info.Output.."/%04i-%02i-%02i-"..Info.Name,
			d.year,
			d.month,
			d.day)
	if (pipe.output(Index, FileName) != nil) then
		return
	end
	

end
