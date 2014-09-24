local commands = {}

commands["help"] = function () 
	print("Avaliable commands:")
	for k, _ in pairs(commands) do
		print("\t"..k)
	end
end

return function (line)
	local cmd = line:match("^%s*(%w+)")
	local args = {}
	local pos = #cmd + 1
	local arg_end_pos
	while (pos < #line) do
		pos, arg_end_pos = line:find("%s*%w+", pos + 1)
		if (pos == nil) then
			break
		end
		args[#args + 1] = line:sub(pos, arg_end_pos):match("%s*(%w+)")
		pos = arg_end_pos
	end

	if commands[cmd] ~= nil then
		commands[cmd](table.unpack(args))
	else
		print(cmd..": command not found")
	end
end