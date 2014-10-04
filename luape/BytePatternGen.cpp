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
	size_t pos, write_pos = 0;;
	char hex_map[] = "0123456789ABCDEF";
	std::list<std::pair<size_t, size_t>> replaces;

	auto get_size = [](Int64 value) -> size_t {
		size_t size = 0;
		if (value < 0) {
			value = -value;
		}
		for (; value != 0; value = value >> 8, ++size);
		return size;
	};

	auto find_replace_range = [len, &dasm, get_size](Int64 value) -> std::pair < size_t, size_t > {
		auto opcode = dasm.Instruction.Opcode;
		size_t op_size = opcode < 0xFF ? 1 : opcode < 0xFFFF ? 2 : 3;
		size_t size = get_size(value);
		uint8_t *target = reinterpret_cast<uint8_t *>(&value); //little-endian
		auto ptr = reinterpret_cast<uint8_t *>(dasm.EIP);
		auto orig_ptr = ptr;
		for (ptr = ptr + op_size; ptr < ptr + len - size; ++ptr) {
			if (memcmp(ptr, target, size) == 0) {
				return std::pair<size_t, size_t>(ptr - orig_ptr, size);
			}
		}
		return std::make_pair<size_t, size_t>(0, 0);
	};

	auto is_in_replace_range = [&replaces](size_t pos) -> bool {
		return std::find_if(replaces.begin(), replaces.end(), [pos](std::pair<size_t, size_t>& pair) {
			return pair.first <= pos && pos < pair.first + pair.second;
		}) != replaces.end();
	};

	/*
	printf("immediat: 0x%llX, arg1type: 0x%08X:%d, arg2type: 0x%08X:%d, arg3type: 0x%08X:%d, d:0x%8X\n",
	dasm.Instruction.Immediat,
	dasm.Argument1.ArgType, dasm.Argument1.ArgSize,
	dasm.Argument2.ArgType, dasm.Argument2.ArgSize,
	dasm.Argument3.ArgType, dasm.Argument3.ArgSize,
	dasm.Argument1.Memory.Displacement);
	*/
	auto mark_ranges = [&](decltype(dasm.Argument1)& arg) {
		if (arg.ArgType == MEMORY_TYPE) {
			if (arg.Memory.Displacement) {
				auto range = find_replace_range(arg.Memory.Displacement);
				if (range.second > 0) {
					replaces.push_back(range);
				}
			}

			if (arg.Memory.IndexRegister) {
				auto range = find_replace_range(arg.Memory.IndexRegister);
				if (range.second > 0) {
					replaces.push_back(range);
				}
			}
		}
		else if (arg.ArgType == CONSTANT_TYPE + RELATIVE_ || arg.ArgType == CONSTANT_TYPE + ABSOLUTE_){
			auto range = find_replace_range(dasm.Instruction.Immediat);
			if (range.second > 0) {
				replaces.push_back(range);
			}
		}
	};

	if (dasm.Instruction.BranchType) {
		auto opcode = dasm.Instruction.Opcode;
		size_t op_size = opcode < 0xFF ? 1 : opcode < 0xFFFF ? 2 : 3;
		if (len > op_size) {
			replaces.push_back(std::pair<size_t, size_t>(op_size, len - op_size));
		}
	}
	else {
		//arg1
		if (dasm.Argument1.ArgType != NO_ARGUMENT) {
			mark_ranges(dasm.Argument1);
		}

		//arg2
		if (dasm.Argument2.ArgType != NO_ARGUMENT) {
			mark_ranges(dasm.Argument2);
		}

		//arg3
		if (dasm.Argument3.ArgType != NO_ARGUMENT) {
			mark_ranges(dasm.Argument3);
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