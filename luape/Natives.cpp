#include "Natives.h"
#include <vector>
#include <Windows.h>
#include <lua.hpp>
#include <cstdint>
#include <Psapi.h>
#include <BeaEngine\BeaEngine.h>
#include "BytePattern.h"
#include "BytePatternGen.h"
#include "PEImage.h"

static HMODULE BaseImageModule;
static size_t BaseImageModuleSize;

static uint32_t GetMaxReadableSize(void *ptr) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) {
		return 0;
	}

	DWORD protect = PAGE_GUARD | PAGE_NOCACHE | PAGE_NOACCESS;
	if (mbi.State & MEM_FREE || !mbi.Protect & protect) {
		return 0;
	}

	return mbi.RegionSize - ((uint32_t)ptr - (uint32_t)mbi.BaseAddress);
}

void NativesRegister(lua_State *L) {
	BaseImageModule = GetModuleHandle(NULL);
	MODULEINFO mi = { 0 };
	GetModuleInformation(GetCurrentProcess(), BaseImageModule, &mi, sizeof(mi));
	BaseImageModuleSize = mi.SizeOfImage;

	luaL_newmetatable(L, "luape.pattern");
	lua_pushstring(L, "__gc");
	lua_pushcfunction(L, [](lua_State *L) -> int {
		Pattern *pattern = *reinterpret_cast<Pattern **>(luaL_checkudata(L, 1, "luape.pattern"));
		BytePattern::DestroyPattern(pattern);
		return 0;
	});
	lua_rawset(L, -3);

	luaL_newmetatable(L, "luape.peimage");

	lua_pushstring(L, "__index");
	lua_newtable(L);
	luaL_Reg pe_methods[] = {
		{
			"load", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				const char *path = luaL_checkstring(L, 2);
				try {
					image->Load(path);
				}
				catch (const std::exception& e) {
					delete image;
					return luaL_error(L, "Load PE file failed: %s", e.what());
				}
				return 0;
			}
		},

		{
			"unload", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				if (image->IsLoaded()) {
					image->Unload();
					lua_pushboolean(L, true);
				}
				else {
					lua_pushboolean(L, false);
				}
				return 0;
			}
		},

		{
			"getImageBase", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				if (image->IsLoaded()) {
					lua_pushunsigned(L, image->image_base());
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"getSize", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				if (image->IsLoaded()) {
					lua_pushunsigned(L, image->size());
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"getMappedBaseAddress", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				if (image->IsLoaded()) {
					lua_pushunsigned(L, (lua_Unsigned)image->data());
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"findAddressByRVA", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				uint32_t rva = luaL_checkinteger(L, 2);
				if (image->IsLoaded()) {
					auto ptr = image->FindPointerByRVA(rva);
					if (ptr) {
						lua_pushunsigned(L, (lua_Unsigned)ptr);
					}
					else {
						lua_pushnil(L);
					}
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"findRVAByFileOffset", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				uint32_t offset = luaL_checkinteger(L, 2);
				if (image->IsLoaded()) {
					auto rva = image->FindRVAByFileOffset(offset);
					if (rva) {
						lua_pushunsigned(L, (lua_Unsigned)rva);
					}
					else {
						lua_pushnil(L);
					}
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"findFileOffsetByPattern", [](lua_State *L) -> int {
				PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
				if (image->IsLoaded()) {
					Pattern *p = *reinterpret_cast<Pattern **>(luaL_checkudata(L, 2, "luape.pattern"));
					const void *ptr = BytePattern::Find(p, image->data(), image->size());
					if (ptr) {
						lua_pushunsigned(L, reinterpret_cast<const uint8_t *>(ptr)-image->data());
					}
					else {
						lua_pushnil(L);
					}
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{ NULL, NULL }
	};
	luaL_setfuncs(L, pe_methods, 0);
	lua_rawset(L, -3);

	lua_pushstring(L, "__gc");
	lua_pushcfunction(L, [](lua_State *L) -> int {
		PEImage *image = *reinterpret_cast<PEImage **>(luaL_checkudata(L, 1, "luape.peimage"));
		delete image;
		return 0;
	});
	lua_rawset(L, -3);


	lua_newtable(L);

	luaL_Reg natives[] = {
		{
			"newPE", [](lua_State *L) -> int {			
				PEImage * image = new PEImage();
				if (lua_gettop(L) > 0) {
					const char *path = luaL_checkstring(L, 1);
					try {
						image->Load(path);
					}
					catch (const std::exception& e) {
						delete image;
						return luaL_error(L, "Load PE file failed: %s", e.what());
					}
				}
				*reinterpret_cast<PEImage **>(lua_newuserdata(L, sizeof(PEImage *))) = image;
				luaL_setmetatable(L, "luape.peimage");
				return 1;
			}
		},

		{
			"generatePatternString", [](lua_State *L) -> int {
				lua_Unsigned addr = luaL_checkunsigned(L, 1);
				lua_Unsigned size = GetMaxReadableSize((void *)addr);
				if (lua_isnumber(L, 2)) {
					lua_Unsigned size_arg = lua_tounsigned(L, 2);
					if (size_arg < size) {
						size = size_arg;
					}
				}
				if (addr && size > 0) {
					uint8_t *ptr = (uint8_t *)addr;
					const std::string& pstr = BytePatternGen(ptr, ptr + size);
					if (pstr.length() > 0) {
						lua_pushstring(L, pstr.c_str());
					}
					else {
						lua_pushnil(L);
					}
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"selectFile", [](lua_State *L) -> int {
				const char *title = NULL;
				if (lua_gettop(L) > 0) {
					title = luaL_checkstring(L, 1);
				}
				char fn[256];
				fn[0] = 0;
				OPENFILENAMEA ofn = { 0 };
				ofn.lStructSize = sizeof(ofn);
				ofn.lpstrFilter = NULL;
				ofn.lpstrFile = fn;
				ofn.nMaxFile = sizeof(fn);
				ofn.nFilterIndex = 1;
				ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
				ofn.lpstrTitle = title;
				if (GetOpenFileNameA(&ofn) && ofn.lpstrFile[0]) {
					lua_pushstring(L, fn);
				} else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"setClipboard", [](lua_State *L) -> int {
				const char *content = luaL_checkstring(L, 1);
				int len = strlen(content);
				if (len > 0) {
					HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len + 1);
					memcpy(GlobalLock(hMem), content, len);
					GlobalUnlock(hMem);
					OpenClipboard(0);
					EmptyClipboard();
					SetClipboardData(CF_TEXT, hMem);
					CloseClipboard();
				}
				return 0;
			}
		},

		{
			"loadLibrary", [](lua_State *L) -> int {
				const char *name = luaL_checkstring(L, 1);
				auto module = LoadLibraryA(name);
				if (!module) {
					lua_pushfstring(L, "Loadlibrary error: %d", GetLastError());
					return lua_error(L);
				}
				else {
					lua_pushlightuserdata(L, module);
				}
				return 1;
			}
		},

		{
			"freeLibrary", [](lua_State *L) -> int {
				luaL_checktype(L, 1, LUA_TLIGHTUSERDATA);
				void *module = lua_touserdata(L, 1);
				if (FreeLibrary(reinterpret_cast<HMODULE>(module)) != TRUE) {
					lua_pushfstring(L, "FreeLibrary error: %d", GetLastError());
					return lua_error(L);
				}
				return 0;
			}
		},

		{
			"pattern", [](lua_State *L) -> int {
				const char *pattern = luaL_checkstring(L, 1);
				if (strlen(pattern) == 0) {
					lua_pushfstring(L, "empty pattern string");
					return lua_error(L);
				}
				*reinterpret_cast<Pattern **>(lua_newuserdata(L, sizeof(Pattern *))) = BytePattern::CreatePattern(pattern);
				luaL_getmetatable(L, "luape.pattern");
				lua_setmetatable(L, -2);
				return 1;
			}
		},

		{
			"findPatternOffset", [](lua_State *L) -> int {
				Pattern *p = *reinterpret_cast<Pattern **>(luaL_checkudata(L, 1, "luape.pattern"));
				uint8_t *base = reinterpret_cast<uint8_t *>(BaseImageModule);
				const void *ptr = BytePattern::Find(p, base, BaseImageModuleSize);
				if (ptr) {
					lua_pushunsigned(L, reinterpret_cast<const uint8_t *>(ptr)-base);
				}
				else {
					lua_pushnil(L);
				}
				return 1;
			}
		},

		{
			"getBaseAddress", [](lua_State *L) -> int {
				lua_pushunsigned(L, reinterpret_cast<uint32_t>(BaseImageModule));
				return 1;
			}
		},

		{
			"diasm", [](lua_State *L) -> int {
				lua_Unsigned addr = luaL_checkunsigned(L, 1);
				int lines = luaL_checkinteger(L, 2);

				uint32_t size = GetMaxReadableSize((void *)addr);
				lua_newtable(L);
				int rv = lua_gettop(L);

				DISASM d;
				int len, i = 0;
				bool error = false;
				memset(&d, 0, sizeof(DISASM));
				d.EIP = (UIntPtr)addr;
				d.SecurityBlock = size;
				while (!error && i < lines) {
					len = Disasm(&d);
					if (len != UNKNOWN_OPCODE && len != OUT_OF_BLOCK) {
						lua_pushstring(L, d.CompleteInstr);
						lua_rawseti(L, rv, i + 1);
						d.EIP += (UIntPtr)len;
						++i;
					}
					else {
						error = true;
					}
				}

				return 1;
			}
		},

		{ NULL, NULL }
	};

	luaL_setfuncs(L, natives, 0);

	char cwd[MAX_PATH + 1];
	GetCurrentDirectoryA(MAX_PATH, cwd);
	lua_pushstring(L, "cwd");
	lua_pushstring(L, cwd);
	lua_rawset(L, -3);

	lua_setglobal(L, "luape");
}