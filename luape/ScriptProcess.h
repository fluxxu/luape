#pragma once

#include <lua.hpp>
#include <list>
#include <map>
#include <cstdint>

typedef void(*ScriptProcessErrorHandler)(const char* msg);
typedef float(*ScriptGetTimeInterface)(void);

//功能:
//	从脚本注册回调，输入id和function
//	从C++执行回调，输入id
//	Sleep和Resume

typedef std::list<int> ScriptCallbackRefListType;
typedef std::map<uint32_t, ScriptCallbackRefListType> ScriptCallbackMapType;
typedef std::list<lua_State*> ScriptYieldThreadListType;
typedef std::map<float, ScriptYieldThreadListType> ScriptYieldThreadListMapType;
typedef std::map<lua_State*, int> ScriptThreadRefMapType;

template <typename T>
struct LuaTypeTraits {
	void push(lua_State *L, T value);
};

#define DEFINE_LUA_TYPE(type, pushfunc) \
	template <> \
	struct LuaTypeTraits<type> { \
		void push(lua_State *L, type value) { \
			pushfunc(L, value); \
		} \
	};

DEFINE_LUA_TYPE(char *, lua_pushstring)
DEFINE_LUA_TYPE(int, lua_pushinteger)
DEFINE_LUA_TYPE(float, lua_pushnumber)
DEFINE_LUA_TYPE(double, lua_pushnumber)

#undef DEFINE_LUA_TYPE

class ScriptProcess {
public:
	ScriptProcess(ScriptGetTimeInterface get_time = nullptr);
	ScriptProcess(const char * require_path, ScriptGetTimeInterface get_time = nullptr);
	~ScriptProcess();

	bool LoadScript(const char* filename, int ret = 0);

	void RegisterNatives(const struct luaL_Reg* natives, const char* libname = NULL);

	void Call(int nargs, int nresults);
	void ThreadExec();

	void SleepThread(lua_State* thread_state, float time);
	void Tick(float time);

	void ExecuteCallbacks(uint32_t type);

	void AddCallback(lua_State* L, uint32_t type);
	void RemoveCallback(lua_State* L, uint32_t type);

	lua_State* L() { return this->master_; }
	void set_error_handler(ScriptProcessErrorHandler v){ this->error_handler_ = v; };
private:
	int errfunc_;
	static int ErrorHandler(lua_State *L);
	void ProcessError(lua_State *L);

	lua_State* master_;
	ScriptProcessErrorHandler error_handler_;
	ScriptGetTimeInterface get_time_;

	ScriptCallbackMapType callback_map_;
	ScriptYieldThreadListMapType yield_thread_map_;
	ScriptThreadRefMapType thread_ref_map_;

	ScriptProcess(ScriptProcess&) = delete;
	void operator=(ScriptProcess) = delete;
};