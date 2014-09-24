#include "BytePatternGen.h"

#include <beaengine\BeaEngine.h>
#include <vector>
#include <string>
#include <exception>
#include <cassert>
#include <list>
#include <algorithm>

static const int kMaxInstructions = 20;

static size_t to_string(size_t len, DISASM & dasm, char *dst) {
	size_t pos, write_pos = 0, opcode_size = len - dasm.Argument1.ArgSize - dasm.Argument2.ArgSize - dasm.Argument3.ArgSize;
	char hex_map[] = "0123456789ABCDEF";
	std::list<std::pair<size_t, size_t>> replaces;

	auto find_replace_range = [len, &dasm](Int64 displacement) -> std::pair < size_t, size_t > {
		uint32_t target = *reinterpret_cast<uint32_t *>(&displacement);
		auto ptr = reinterpret_cast<uint8_t *>(dasm.EIP);
		auto orig_ptr = ptr;
		for (; ptr < ptr + len - sizeof(target); ++ptr) {
			uint32_t val = *reinterpret_cast<uint32_t *>(ptr);
			if (val == target) {
				return std::make_pair<size_t, size_t>(ptr - orig_ptr, sizeof(target));
			}
		}
		return std::make_pair<size_t, size_t>(0, 0);
	};

	auto is_in_replace_range = [&replaces](size_t pos) -> bool {
		return std::find_if(replaces.begin(), replaces.end(), [pos](std::pair<size_t, size_t>& pair) {
			return pair.first <= pos && pos < pair.first + pair.second;
		}) != replaces.end();
	};

	//printf("arg1type: 0x%08X, arg2type: 0x%08X, d:0x%8X\n", dasm.Argument1.ArgType, dasm.Argument2.ArgType, dasm.Argument1.Memory.Displacement);
	if (dasm.Instruction.BranchType || dasm.Argument1.ArgType == MEMORY_TYPE && dasm.Argument2.ArgType == CONSTANT_TYPE + ABSOLUTE_) {
		Int32 opcode = dasm.Instruction.Opcode;
		size_t opcode_size = opcode <= 0xFF ? 1 : opcode <= 0xFFFF ? 2 : 3;
		size_t addr_size = len - opcode_size;
		replaces.push_back(std::make_pair(opcode_size, addr_size));
	}
	else {
		auto need_strip = [](decltype(dasm.Argument1)& arg) -> bool {
			return (arg.ArgType == MEMORY_TYPE && arg.Memory.Displacement != 0 && arg.Memory.BaseRegister == 0 && arg.Memory.IndexRegister == 0 && arg.Memory.Scale == 0);
		};

		//arg1
		if (dasm.Argument1.ArgType != NO_ARGUMENT) {
			if (need_strip(dasm.Argument1)) {
				auto range = find_replace_range(dasm.Argument1.Memory.Displacement);
				assert(range.second != 0);
				replaces.push_back(range);
			}
		}

		//arg2
		if (dasm.Argument2.ArgType != NO_ARGUMENT) {
			if (need_strip(dasm.Argument2)) {
				auto range = find_replace_range(dasm.Argument2.Memory.Displacement);
				assert(range.second != 0);
				replaces.push_back(range);
			}
		}

		//arg1
		if (dasm.Argument2.ArgType != NO_ARGUMENT) {
			if (need_strip(dasm.Argument2)) {
				auto range = find_replace_range(dasm.Argument2.Memory.Displacement);
				assert(range.second != 0);
				replaces.push_back(range);
			}
		}
	}

	for (pos = 0, write_pos = 0; pos < len; ++pos) {
		auto byte = reinterpret_cast<uint8_t *>(dasm.EIP)[pos];
		if (is_in_replace_range(pos)) {
			dst[write_pos++] = '?';
			dst[write_pos++] = '?';
		}
		else {
			dst[write_pos++] = hex_map[byte / 0x10];
			dst[write_pos++] = hex_map[byte % 0x10];
		}
		dst[write_pos++] = ' ';
	}

	assert(pos == len);
	return write_pos;
}

const std::string BytePatternGen(uint8_t *start, uint8_t *max) {
	std::string rv;
	std::vector<char> buffer(128);

	DISASM dasm;
	memset(&dasm, 0, sizeof(DISASM));

	int len, i = 0, op_len;
	int err = 0;

	dasm.SecurityBlock = max - start;
	dasm.EIP = (UIntPtr)start;

	while ((!err) && i < kMaxInstructions) {
		len = Disasm(&dasm);
		int opcode = dasm.Instruction.Opcode;
		if (len != UNKNOWN_OPCODE && dasm.Instruction.Opcode != 0xCC) {
			if (len <= 0) {
				err = 1;
				break;
			}

			op_len = opcode <= 0xFF ? 1 : opcode <= 0xFFFF ? 2 : 3;

			size_t strLen = len * 3 - 1;
			char *buff;
			if (dasm.Instruction.BranchType) {
				/*
				printf("[0x%llX] %s\n",
				dasm.Instruction.AddrValue,
				dasm.CompleteInstr);
				*/
			}
			int buff_pos;
			if (strLen > buffer.size()) {
				buffer.resize(strLen);
			}
			buff = &buffer[0];

			buff_pos = to_string(len, dasm, buff);
			buff[buff_pos - 1] = '\0';

			if (rv.length()) {
				rv.append(" ");
			}
			rv.append(buff);

			//printf("%08X %s\n", dasm.EIP, dasm.CompleteInstr);
			//printf("==> %s\n", buff);

			dasm.EIP = dasm.EIP + (UIntPtr)len;
			i++;
		}
		else {
			err = 1;
		}
	}

	return rv;
}