#include <Windows.h>
#include <chrono>
#include <cassert>
#include "ScriptProcess.h"

ScriptProcess::ScriptProcess(ScriptGetTimeInterface get_time) {
	this->error_handler_ = NULL;
	this->get_time_ = get_time ? get_time : [](void) -> float {
		using namespace std::chrono;
		auto ms = duration_cast<milliseconds>(high_resolution_clock::now().time_since_epoch()).count();
		return static_cast<float>(ms / 1000);
	};

	lua_State* L = this->master_ = luaL_newstate();

	luaL_openlibs(L);

	lua_pushlightuserdata(L, this);
	lua_pushcclosure(L, ErrorHandler, 1);
	errfunc_ = lua_gettop(L);
}

ScriptProcess::ScriptProcess(const char * require_path, ScriptGetTimeInterface get_time) : ScriptProcess(get_time) {
	auto L = this->master_;
	//设置require路径
	lua_getglobal(L, LUA_LOADLIBNAME);
	assert(lua_isnil(L, -1) == 0);
	lua_pushstring(L, "path");
	lua_pushstring(L, require_path);
	lua_rawset(L, -3);
	lua_pop(L, 1);
}

ScriptProcess::~ScriptProcess() {
	lua_close(this->master_);
}

int ScriptProcess::ErrorHandler(lua_State *L) {
	ScriptProcess *process = (ScriptProcess *)lua_touserdata(L, lua_upvalueindex(1));
	process->ProcessError(L);
	return 0;
}

void ScriptProcess::RegisterNatives(const struct luaL_Reg* natives, const char* libname) {
	lua_getglobal(this->master_, "_G");
	if (libname) {
		lua_pushstring(this->master_, libname);
		lua_newtable(this->master_);
		luaL_setfuncs(this->master_, natives, 0);
		lua_rawset(this->master_, -3);
	}
	else {
		luaL_setfuncs(this->master_, natives, 0);
	}
	lua_pop(this->master_, 1);
}


void ScriptProcess::Call(int nargs, int nresults) {
	if (!lua_isfunction(this->master_, -(1 + nargs))) {
		lua_pushstring(this->master_, "Exec failed: not a function");
		this->ProcessError(this->master_);
		return;
	}

	lua_pcall(this->master_, nargs, nresults, errfunc_);
}

//函数在栈顶，运行完出栈
void ScriptProcess::ThreadExec() {
	if (!lua_isfunction(this->master_, -1)) {
		lua_pushstring(this->master_, "Start thread failed: not a function");
		this->ProcessError(this->master_);
		return;
	}
	//function的引用
	int func_ref = luaL_ref(this->master_, LUA_REGISTRYINDEX);
	lua_State* L = lua_newthread(this->master_);
	//保存一个新线程的引用
	int ref_thread = luaL_ref(this->master_, LUA_REGISTRYINDEX);
	lua_rawgeti(L, LUA_REGISTRYINDEX, func_ref);
	luaL_unref(this->master_, LUA_REGISTRYINDEX, func_ref);

	int result = lua_resume(L, NULL, 0);
	//如果直接执行完毕就直接清理
	if (result == 0) {
		luaL_unref(L, LUA_REGISTRYINDEX, ref_thread);
	}
	else if (result == LUA_YIELD) {
		this->thread_ref_map_[L] = ref_thread;
	}
}

bool ScriptProcess::LoadScript(const char* filename, int ret) {
	lua_State* L = this->master_;
	if (luaL_loadfile(this->master_, filename) != 0) {
		this->ProcessError(L);
		return false;
	}

	if (lua_isnil(this->master_, -1)) {
		return false;
	}
	
	return lua_pcall(this->master_, 0, ret, errfunc_) == LUA_OK;
}

//Callback在栈顶, 加入完毕以后清出栈
void ScriptProcess::AddCallback(lua_State* L, uint32_t type) {
	int ref_callback = luaL_ref(L, LUA_REGISTRYINDEX);
	this->callback_map_[type].push_back(ref_callback);
}

//Callback在栈顶, 执行完毕以后清出栈
void ScriptProcess::RemoveCallback(lua_State* L, uint32_t type) {
	if (this->callback_map_.count(type) > 0) {
		if (this->callback_map_[type].size() > 0) {
			ScriptCallbackRefListType* list = &(this->callback_map_[type]);
			bool found = false;
			for (ScriptCallbackRefListType::iterator iter = list->begin(); !found && iter != list->end();) {
				lua_rawgeti(L, LUA_REGISTRYINDEX, *iter);
				if (1 == lua_rawequal(L, -1, -2)) {
					luaL_unref(L, LUA_REGISTRYINDEX, *iter);
					found = true;
					list->erase(iter);
				}
				else
					++iter;
				lua_pop(L, 1);
			}
		}
	}
	lua_pop(L, 1);
}

void ScriptProcess::SleepThread(lua_State* thread_state, float length) {
	float resume_time = get_time_() + length;
	this->yield_thread_map_[resume_time].push_back(thread_state);
}

void ScriptProcess::Tick(float time) {
	if (this->yield_thread_map_.size() == 0)
		return;

	lua_State* L;
	ScriptYieldThreadListMapType::iterator iter;
	ScriptYieldThreadListType::iterator iter_list;
	ScriptYieldThreadListType* list;
	for (iter = this->yield_thread_map_.begin(); iter != this->yield_thread_map_.end();) {
		if (iter->first > time)
			break;

		list = &(iter->second);
		for (iter_list = iter->second.begin(); iter_list != iter->second.end();) {
			L = *iter_list;
			int result = lua_resume(L, NULL, 0);
			//如果直接执行完毕就直接清理
			if (result == 0) {
				luaL_unref(L, LUA_REGISTRYINDEX, this->thread_ref_map_[L]);
				this->thread_ref_map_.erase(L);
			}
			else if (result == LUA_YIELD) {
				//如果继续Sleep,那么只删除当前的记录，继续保持thread的引用
			}
			//无论如何都要删除当前的记录，因为时间必定不一样
			list->erase(iter_list++);
		}
		//如果所有的线程都执行完了，就在map中删除当前时间点的记录
		if (list->size() == 0) {
			this->yield_thread_map_.erase(iter++);
		}
		else
			iter++;
	}
}

void ScriptProcess::ExecuteCallbacks(uint32_t type) {
	if (this->callback_map_.count(type) == 0)
		return;

	ScriptCallbackRefListType* list = &(this->callback_map_[type]);
	ScriptCallbackRefListType::iterator iter;

	for (iter = list->begin(); iter != list->end();) {
		int ref = *(iter++);
		lua_rawgeti(this->master_, LUA_REGISTRYINDEX, ref);
		this->ThreadExec();
	}
}

void ScriptProcess::ProcessError(lua_State* L) {
	if (lua_isstring(L, -1) && NULL != this->error_handler_) {
		std::string errmsg = lua_tostring(L, -1);
		luaL_traceback(L, L, NULL, 1);
		errmsg.append("\n");
		errmsg.append(lua_tostring(L, -1));
		lua_pop(L, 1);

		this->error_handler_(errmsg.c_str());
	}
	lua_pop(L, 1);
}