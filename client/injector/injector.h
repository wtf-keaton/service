#include <Windows.h>

#include "../hash/hash.h"
#include "../helpers/structs.h"
#include "../connection/connection.h"
#include "../driver/driver.h"
#include "../json/json.h"

namespace fusion::injector
{
	bool execute( );

	uintptr_t get_proc_address( const char* module, hash_t hash );
}