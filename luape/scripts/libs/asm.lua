local asm_line_meta = {
	__index = {
		number = function (self, i)
			local pattern = "%x+h"
			local n = i or 1
			local p_begin = 1, p_end
			for i = 0, n, 1 do
				p_begin, p_end = self.code_:find(pattern, p)
				if p_begin ~= nil then
					if i == n - 1 then
						local hex = self.code_:sub(p_begin, p_end - 1)
						return tonumber(hex, 16)
					end
				end
			end
			return nil
		end,

		offset = function (self, i)
			return self:number(i) - self.base_
		end
	},

	__tostring = function (self)
		return self.code_
	end
}

local function newASM(addr, base, n)
	n = n or 20
	local asm = luape.diasm(addr, n)
	if #asm then
		asm.base = base
		setmetatable(asm, {
			__index = {
				dump = function (self)
					for k, v in ipairs(self) do
						print(k, v)
					end
				end,
				
				line = function (self, n) 
					local obj = {
						code_ = self[n],
						base_ = base
					}
					setmetatable(obj, asm_line_meta)
					return obj
				end,

				diasm = function (addr, n)
					return newASM(addr, n)
				end
			}
		})
		return asm
	else
		return nil
	end
end

return {
	new = newASM
}