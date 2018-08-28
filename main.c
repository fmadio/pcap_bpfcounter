#include <stdio.h>
#include <stdlib.h>
#include <string.h> 
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "fTypes.h"

//-------------------------------------------------------------------------------

bool 		g_SignalExit = 0;
u64			g_OutputTimeNS = 1e9;


extern u8	_binary_lmain_lua_start;
extern u8	_binary_lmain_lua_end;

//-------------------------------------------------------------------------------

int 	Parse_Start		(void);
void 	Parse_Open		(lua_State* L);

//-------------------------------------------------------------------------------

static void laction (int i)
{
	signal(i, SIG_DFL); /* if another SIGINT happens before lstop, terminate process (default action) */
	printf("signal\n");

	g_SignalExit = 1;
//	lua_sethook(globalL, lstop, LUA_MASKCALL | LUA_MASKRET | LUA_MASKCOUNT, 1);
}

//-------------------------------------------------------------------------------

static int traceback (lua_State *L) 
{

	if (!lua_isstring(L, 1))  /* 'message' not a string? */
		return 1;  /* keep it intact */

	lua_getfield(L, LUA_GLOBALSINDEX, "debug");
	if (!lua_istable(L, -1)) {
		printf("no debug info\n");
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		printf("no traceback info\n");
		lua_pop(L, 2);
		return 1;
	}

	lua_pushvalue(L, 1);  /* pass error message */
	lua_pushinteger(L, 2);  /* skip this function and traceback */
	lua_call(L, 2, 1);  /* call debug.traceback */
	/*
    const char* msg = lua_tostring(L, 1);
    const char* msg2 = lua_tostring(L, 2);
    printf("dump done %s %p\n", msg, msg2); 
	*/
	return 1;
}

//-------------------------------------------------------------------------------

static int docall (lua_State *L, int narg, int clear)
{
	int status;
	int base = lua_gettop(L) - narg;  	/* function index */
	lua_pushcfunction(L, traceback);  	/* push traceback function */
	lua_insert(L, base);  				/* put it under chunk and args */

	signal(SIGINT, laction);
	status = lua_pcall(L, narg, (clear ? 0 : LUA_MULTRET), base);
	signal(SIGINT, SIG_DFL);

	lua_remove(L, base);  // remove traceback function 

	// force a complete garbage collection in case of errors 
	if (status != 0) lua_gc(L, LUA_GCCOLLECT, 0);
	return status;
}

//-------------------------------------------------------------------------------

static int report(lua_State *L, int status) 
{
	if (status && !lua_isnil(L, -1))
	{
		const char *msg = lua_tostring(L, -1);
		if (msg == NULL) msg = "(error object is not a string)";

		// both just to be sure
		printf("%s\n", msg);
		lua_pop(L, 1);
		return -1;
	}
	return status;
}

//-------------------------------------------------------------------------------

static int lclock_ns(lua_State* L)
{
	lua_pushnumber(L, clock_ns() );
	return 1;
}

static int lns2clock(lua_State* L)
{
	u64 t = lua_tonumber(L, -1); 

	clock_date_t c = ns2clock(t);

	int wday		= dayofweek(c.day, c.month, c.year);

	lua_newtable(L);	
	lua_pushnumber(L, c.year);	lua_setfield(L, -2, "year");
	lua_pushnumber(L, c.month);	lua_setfield(L, -2, "month");
	lua_pushnumber(L, c.day);	lua_setfield(L, -2, "day");
	lua_pushnumber(L, c.hour);	lua_setfield(L, -2, "hour");
	lua_pushnumber(L, c.min);	lua_setfield(L, -2, "min");
	lua_pushnumber(L, c.sec);	lua_setfield(L, -2, "sec");

	lua_pushnumber(L, wday);	lua_setfield(L, -2, "wday");

	return 1;
}

static void lua_register_os(lua_State* L, const char* FnName, lua_CFunction Func)
{
	lua_getglobal(L, "os");
	assert(!lua_isnil(L, -1));

	lua_pushcfunction(L, Func);
	lua_setfield(L, -2, FnName); 
}

//-------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	lua_State *L = lua_open();
	luaL_openlibs(L);

	Parse_Open(L);

	// built in general purpose  
	lua_newtable(L);
	lua_setglobal(L, "os");
	lua_register_os(L, "ns2clock",			lns2clock);
	lua_register_os(L, "clock_ns",			lclock_ns);

	g_OutputTimeNS				= 60e9;

	// config load files 
	printf("Setup\n");
	{
		u8* BootScript = &_binary_lmain_lua_start; 
		u64 BootScriptLen = (&_binary_lmain_lua_end) - (&_binary_lmain_lua_start);

		int ret = luaL_loadbuffer(L, BootScript, BootScriptLen, "lmain"); 
		int status = docall(L, 0, 0);
		report(L, status);	
	}

	printf("Config File\n");
	{
		int ret = luaL_loadfile(L, "./config.lua");
		int status = docall(L, 0, 0);
		report(L, status);	
	}

	Parse_Start();
}
