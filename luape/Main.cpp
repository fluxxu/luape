#include <iostream>
#include <string>
#include <memory>
#include <Objbase.h>
#include "ScriptProcess.h"
#include "Natives.h"

static std::unique_ptr<ScriptProcess> g_script_proc;

int main(int argc, const char *argv[]) {
	CoInitializeEx(NULL, COINIT_MULTITHREADED);

	std::string package_path;

#ifdef _DEBUG
	package_path = __FILE__;
	package_path = package_path.substr(0, package_path.find_last_of('\\')) + "\\scripts";
#else
	char path[MAX_PATH + 1];
	path[0] = 0;
	auto len = GetModuleFileNameA(NULL, path, sizeof(path));
	if (len) {
		char *pos = strrchr(path, '\\');
		*pos = 0;
		package_path = path;
		package_path.append("\\scripts");
	}
	else {
		package_path = ".\\scripts";
	}
	
#endif

	std::cout << "Package Directory: " << package_path.c_str() << std::endl;
	std::cout << "================================================================================";

	auto init = [&package_path]() -> int {
		g_script_proc.reset(new ScriptProcess((package_path + "\\?.lua").c_str()));

		lua_State *L = g_script_proc->L();
		NativesRegister(L);
		g_script_proc->set_error_handler([](const char *msg) {
			std::cerr << msg << std::endl;
		});

		g_script_proc->LoadScript((package_path + "\\console.lua").c_str(), 1);
		lua_pushvalue(L, -1);
		luaL_ref(L, LUA_REGISTRYINDEX);
		return lua_gettop(L);
	};

	int fn = init();

	while (true) {
		char buffer[260] = { 0 };
		std::cout << ">";
		std::cin.getline(buffer, sizeof(buffer));
		if (strcmp(buffer, "reload") == 0) {
			fn = init();
		}
		else if (strcmp(buffer, "clear") == 0) {
			system("cls");
		}
		else if (strlen(buffer) > 0) {
			if (g_script_proc) {
				lua_State *L = g_script_proc->L();

				if (lua_isfunction(L, fn)) {
					lua_pushvalue(L, fn);
					lua_pushstring(L, buffer);
					g_script_proc->Call(1, 0);
				}
				else {
					lua_pop(L, 1);
				}
			}
			else {
				std::cerr << "Script process is not initialized." << std::endl;
			}
		}
	}

	return 0;
}