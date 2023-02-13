#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include "../hash/hash.h"
#include "../helpers/structs.h"
#include "../connection/connection.h"
//#include "../driver/driver.h"
#include "../json/json.h"

namespace fusion::injector
{
	bool execute( HANDLE handle );

	DWORD get_process_id( const char* process_name );

	uintptr_t get_process_module_base( const char* lpModuleName );
	DWORD_PTR GetProcessBaseAddress( DWORD processID );
	uintptr_t get_proc_address( HANDLE handle, uintptr_t module, std::string_view func );
}