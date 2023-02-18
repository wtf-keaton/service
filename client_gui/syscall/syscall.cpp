#include "syscall.h"

namespace fusion::syscall
{
	uint64_t get_module_base( const wchar_t* module_name )
	{
		UNICODE_STRING mod_name;
		RtlInitUnicodeString( &mod_name, module_name );
		HANDLE out;
		LdrGetDllHandle( nullptr, nullptr, &mod_name, &out );
		return reinterpret_cast< uint64_t >( out );
	}


	uint64_t get_proc_address( uint64_t mod_base, uint64_t function_hash )
	{
		IMAGE_NT_HEADERS* nt = reinterpret_cast< IMAGE_NT_HEADERS* >( reinterpret_cast< IMAGE_DOS_HEADER* >( mod_base )->e_lfanew + mod_base );

		IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( mod_base + nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

		uint32_t* functions = reinterpret_cast< uint32_t* >( mod_base + exports->AddressOfFunctions );
		uint32_t* names = reinterpret_cast< uint32_t* >( mod_base + exports->AddressOfNames );
		uint16_t* ordinals = reinterpret_cast< uint16_t* >( mod_base + exports->AddressOfNameOrdinals );

		for ( int i = 0; i < exports->NumberOfNames; ++i )
		{
			if ( HASH( reinterpret_cast< const char* >( mod_base + names[ i ] ) ) == function_hash )
				return mod_base + functions[ ordinals[ i ] ];
		}

		return 0;
	}
}