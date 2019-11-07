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

double		TSC2Nano = 0.0;


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
		fprintf(stderr, "%s\n", msg);
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

//-----------------------------------------------------------------------------------------------
//
// setup link table for luajit FFI function searching 
//

typedef struct
{
	unsigned int 	Offset;
	char			Name[128];
} LinkEntry_t;

static u32				s_LinkCnt = 0;
static LinkEntry_t		s_Link[16*1024];

int dlinit(FILE* F, s32 BaseOffset)
{
	while (true)
	{
		s32 Offset = -sizeof(LinkEntry_t) * (s_LinkCnt+1);
		fseek(F, Offset+BaseOffset, SEEK_END);

		u32 len = fread(&s_Link[s_LinkCnt], sizeof(LinkEntry_t), 1, F);
		//fprintf(stderr, "%08x [%s]\n", s_Link[s_LinkCnt].Offset, s_Link[s_LinkCnt].Name);

		if (s_Link[s_LinkCnt].Offset == 0) break;		
		s_LinkCnt++;
	}

	fprintf(stderr, "lua link count: %i\n", s_LinkCnt);

	return sizeof(LinkEntry_t)*(s_LinkCnt+1) + BaseOffset;
}

void* dlopen(const char*filename, int flag)
{
	printf("dlopen\n");
	return NULL;
}

// nasty shit
void* dlsym(void* handle, const char* name)
{
	//printf("search %s\n", name);
	for (int i=0; i < s_LinkCnt; i++)
	{
		if (strcmp(name, s_Link[i].Name) == 0)
		{
			return (void *)(unsigned long long)s_Link[i].Offset;
		}
	}

	/*
	//printf("search symbol %s\n", name);
	FILE* F = fopen("dsv.map", "r");
	if (F)
	{
		while (!feof(F))
		{
			LinkEntry_t E;
			int Len = fread(&E, 1, sizeof(E), F);

			//printf("%i %08x %s\n", Len, E.Offset, E.Name);
			if (Len != sizeof(E)) break;

			if (strcmp(name, E.Name) == 0)
			{
				return (void *)(unsigned long long)E.Offset;
			}
		}
		fclose(F);
	}
	*/

	fprintf(stderr, "failed to find symbol [%s]\n", name);	
	return NULL;
}

void * gethostbyaddr(void* ptr, int a, int b)
{
	return NULL;
}

void * gethostbyname(void* ptr)
{
	return NULL;
}

char* dlerror(void)
{
	assert(0);
}

int dlclose(void* handle)
{
	assert(0);
}


//-------------------------------------------------------------------------------

static bool LoadLuaEnvironment(u8* FileName)
{
	FILE* F = fopen(FileName, "rb");
	if (!F)
	{
		printf("failed to open self? [%s]\n", FileName); 
		return false; 
	}
	s32 Offset = 0;

	char* LuaBinary = NULL;
	u32 LuaBinaryLen = 0;

	bool Done = false;
	while (!Done)
	{
		Offset = Offset - 16;
		s32 Magic[4] = {0, 0};
		fseek(F, Offset, SEEK_END);
		fread(&Magic, 16, 1, F);

		//printf("Magic: %08x %08x %08x %08x\n", Magic[0], Magic[1], Magic[2], Magic[3]);
		switch (Magic[3])
		{
		// symbol table
		case 0xbeef0001:
			//printf("symbol table : %i\n", Magic[1]);
			dlinit(F, Offset);
			Offset = Offset - Magic[2];
			//printf("new offset: %08x : %08x\n", Offset, Magic[2]);
			break;
/*
		// lua binary
		case 0xbeef0002:	
		{
			u32 BinSize 		= Magic[0];
			u32 FileNameSize 	= Magic[1];

			char FileName[128] = { 0 };
			Offset -= FileNameSize;
			fseek(F, Offset, SEEK_END);
			int rlen = fread(FileName, FileNameSize, 1, F);

			Offset 				= Offset - BinSize;
			LuaBinary 			= malloc(BinSize);

			fseek(F, Offset, SEEK_END);
			fread(LuaBinary, BinSize, 1, F);
			LuaBinaryLen = BinSize; 
			//printf("embedded binary : %i [%s]\n", LuaBinaryLen, FileName);

			// execute embeded script
			int status = luaL_loadbuffer(L, LuaBinary, LuaBinaryLen, FileName); 
			if (status != 0)
			{
				const char* msg = lua_tostring(L, -1);
				printf("embed load failed [%s]\n", msg);
			}
			else
			{
				// run with full traceback/debug enviormnent
				status = docall(L, 0, 1);
				//printf("call : %i\n", status);
				report(L, status);
				if (status) return false;
			}
			free(LuaBinary);
		}
		break;

		// embedded string  (for header files)
		case 0xbeef0003:	
			{
				Offset = Offset - Magic[0];

				char* LuaString = malloc(Magic[0]);

				fseek(F, Offset, SEEK_END);
				fread(LuaString, Magic[0], 1, F);

				u32* d32 = (u32*)LuaString;
			
				assert(d32[0] == 0x1234);
				u32 GlobalIDLen = d32[1];
				u32 StringLen 	= d32[2];

				u8* GlobalID = LuaString + 3*4;
				GlobalID[ GlobalIDLen ] = 0;

				//printf("id [%s]\n", GlobalID); 

				lua_pushlstring(L, LuaString + 3*4 + GlobalIDLen, StringLen); 
				lua_setfield(L, LUA_GLOBALSINDEX, LuaString + 3*4); 
				lua_rawset(L, -2);

				u32 IDLength = *( (u32*)LuaString);
				u32 StrLength	= Magic[0] - IDLength - 4; 

				//printf("embdeed string: %i\n", IDLength);

				free(LuaBinary);
			}
			break;

*/
		default:
			//printf("done\n");
			Done = true;
			break;
		}
		//printf("Magic: %08x %08x\n", Magic[1], Magic[0]);
	}
	//printf("finished\n");
	fclose(F);

	return true;
}
  
//-------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	lua_State *L = lua_open();
	luaL_openlibs(L);

	// initialize symbol table 
	LoadLuaEnvironment("./pcap_bpfcounter");	

	// parse config options
	lua_newtable(L);
	u32 idx = 1;

	u8* ConfigFileName = "./config.lua";
	for (int i=0; i < argc; i++)
	{
		if (strcmp(argv[i], "--config") == 0)
		{
			ConfigFileName = argv[i+1];
			i++;
		}

		lua_pushstring(L, argv[i]);
		lua_rawseti(L, -2, idx++);
	}
	lua_setglobal(L, "ARGV");


//	Parse_Open(L);
//	Output_Open(L);

	// built in general purpose  
	lua_newtable(L);
	lua_setglobal(L, "os");
	lua_register_os(L, "ns2clock",			lns2clock);
	lua_register_os(L, "clock_ns",			lclock_ns);

	g_OutputTimeNS				= 60e9;

	// config load files 
	fprintf(stderr, "Setup\n");
	{
		u8* BootScript = &_binary_lmain_lua_start; 
		u64 BootScriptLen = (&_binary_lmain_lua_end) - (&_binary_lmain_lua_start);

		int ret = luaL_loadbuffer(L, BootScript, BootScriptLen, "lmain"); 
		int status = docall(L, 0, 0);
		report(L, status);	
	}

	fprintf(stderr, "Config File [%s]\n", ConfigFileName);
	{
		int ret = luaL_loadfile(L, ConfigFileName); 
		int status = docall(L, 0, 0);
		report(L, status);	
	}
	fflush(stdout);

	Parse_Start();
}
