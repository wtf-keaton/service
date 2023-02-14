#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "../hash/hash.h"
#include "../helpers/structs.h"
#include "../connection/connection.h"
#include "../driver/driver.h"
#include "../json/json.h"

namespace fusion::injector
{
	bool execute( );

	DWORD get_process_id( const char* process_name );

	bool parse_imports( const char* module_name );

	uintptr_t get_proc_address( uintptr_t module, std::string_view func );
}