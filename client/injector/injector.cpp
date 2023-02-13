#include "injector.h"
#include "../syscall/syscall.h"

namespace fusion::injector
{
	bool execute( HANDLE handle )
	{
		binary_request_t binary{};
		fusion::client::recv( &binary, sizeof binary );

		auto allocated_base = syscall::allocate( handle, binary.size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if ( !allocated_base )
		{
			//fusion::driver::unload( );
			return false;
		}

		auto imports = nlohmann::json::parse( binary.imports );

		uint64_t imports_count = 0;

		nlohmann::json final_imports;
		if ( nlohmann::json::accept( binary.imports ) )
		{
			auto imports = nlohmann::json::parse( binary.imports );

			for ( auto& [key, value] : imports.items( ) )
			{
				for ( auto& i : value )
				{
					auto name = i.get<std::string>( );

					auto address = get_proc_address( handle, get_process_module_base( key.c_str( ) ), name );
					final_imports[ name ] = address;

					imports_count++;
				}
			}
			imports.clear( );
		}

		if ( !fusion::client::send( &allocated_base, sizeof( allocated_base ) ) )
		{
			//fusion::driver::free( allocated_base );
			//fusion::driver::unload( );
			return false;
		}

		fusion::client::send( final_imports.dump( ) );
		final_imports.clear( );

		std::vector<char> data;
		int size = fusion::client::read_stream( data, binary.size );

		if ( size == binary.size )
		{
			if ( !syscall::write( handle, allocated_base, data.data( ), data.size( ) ) )
			{
				printf_s( "failed to write data\n" );
				return false;
			}

			auto entry = allocated_base + binary.entry;

			static std::vector<uint8_t> shellcode = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2,0x01, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC0,
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };

			*reinterpret_cast< uint64_t* >( &shellcode[ 6 ] ) = allocated_base;
			*reinterpret_cast< uint64_t* >( &shellcode[ 26 ] ) = entry;

			auto code = syscall::allocate( handle, shellcode.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
			if ( !syscall::write( handle, code, shellcode.data( ), shellcode.size( ) ) )
			{
				printf_s( "failed to write shellcode\n" );
				return false;
			}

			syscall::nt_create_thread( handle, reinterpret_cast< void* >( code ) );

			syscall::free( reinterpret_cast<void*>( code ) );
		}
	}

	DWORD get_process_id( const char* process_name )
	{
		{
			PROCESSENTRY32   pe32;
			HANDLE         hSnapshot = NULL;

			pe32.dwSize = sizeof( PROCESSENTRY32 );
			hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

			if ( Process32First( hSnapshot, &pe32 ) )
			{
				do
				{
					if ( strcmp( pe32.szExeFile, process_name ) == 0 )
						break;
				} while ( Process32Next( hSnapshot, &pe32 ) );
			}

			if ( hSnapshot != INVALID_HANDLE_VALUE )
				CloseHandle( hSnapshot );

			return pe32.th32ProcessID;
		}
	}

	DWORD_PTR GetProcessBaseAddress( DWORD processID )
	{
		DWORD_PTR   baseAddress = 0;
		HANDLE      processHandle = OpenProcess( PROCESS_ALL_ACCESS, FALSE, processID );
		HMODULE* moduleArray;
		LPBYTE      moduleArrayBytes;
		DWORD       bytesRequired;

		if ( processHandle )
		{
			if ( EnumProcessModules( processHandle, NULL, 0, &bytesRequired ) )
			{
				if ( bytesRequired )
				{
					moduleArrayBytes = ( LPBYTE ) LocalAlloc( LPTR, bytesRequired );

					if ( moduleArrayBytes )
					{
						unsigned int moduleCount;

						moduleCount = bytesRequired / sizeof( HMODULE );
						moduleArray = ( HMODULE* ) moduleArrayBytes;

						if ( EnumProcessModules( processHandle, moduleArray, bytesRequired, &bytesRequired ) )
						{
							baseAddress = ( DWORD_PTR ) moduleArray[ 0 ];
						}

						LocalFree( moduleArrayBytes );
					}
				}
			}

			CloseHandle( processHandle );
		}

		return baseAddress;
	}

	uintptr_t get_process_module_base( const char* lpModuleName )
	{
		MODULEENTRY32 lpModEntryPoint = { 0 };
		HANDLE handleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, get_process_id( "Game.exe" ) );
		if ( !handleSnap )	return NULL;
		lpModEntryPoint.dwSize = sizeof( lpModEntryPoint );
		BOOL bModule = Module32First( handleSnap, &lpModEntryPoint );
		while ( bModule )
		{
			std::string test = lpModEntryPoint.szModule;

			std::transform( test.begin( ), test.end( ), test.begin( ), ::tolower );

			if ( strstr( test.c_str(), lpModuleName ) )
			{
				CloseHandle( handleSnap );
				return ( uintptr_t ) lpModEntryPoint.modBaseAddr;
			}
			bModule = Module32Next( handleSnap, &lpModEntryPoint );
		}
		CloseHandle( handleSnap );
		return NULL;
	}

	uintptr_t get_proc_address( HANDLE handle, uintptr_t module, std::string_view func )
	{
		if ( !module )
			return 0;

		IMAGE_DOS_HEADER dos_header{};
		if ( !syscall::read( handle, module, &dos_header, sizeof( dos_header ) ) )
		{
			printf_s( "[ - ] failed to read dos header" );
			return 0;
		}

		if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE )
			return 0;

		IMAGE_NT_HEADERS nt_header{};
		if ( !syscall::read( handle, module + dos_header.e_lfanew, &nt_header, sizeof( nt_header ) ) )
		{
			printf_s( "[ - ] failed to read nt header" );
			return 0;
		}

		if ( nt_header.Signature != IMAGE_NT_SIGNATURE )
		{
			return {};
		}

		IMAGE_EXPORT_DIRECTORY exp_dir{};
		auto exp_va = nt_header.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ]
			.VirtualAddress;
		auto exp_dir_size =
			nt_header.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

		auto exp_dir_start = module + exp_va;
		auto exp_dir_end = exp_dir_start + exp_dir_size;

		if ( !syscall::read( handle, exp_dir_start, &exp_dir, sizeof( exp_dir ) ) )
		{
			printf_s( "failed to read export dir" );
			return {};
		}

		auto funcs = module + exp_dir.AddressOfFunctions;
		auto ords = module + exp_dir.AddressOfNameOrdinals;
		auto names = module + exp_dir.AddressOfNames;

		for ( int i = 0; i < exp_dir.NumberOfFunctions; ++i )
		{
			uint32_t name_rva{};
			uint32_t func_rva{};
			uint16_t ordinal{};

			if ( !syscall::read( handle, names + ( i * sizeof( uint32_t ) ), &name_rva, sizeof( uint32_t ) ) )
			{
				continue;
			}
			std::string name;
			name.resize( func.size( ) );

			if ( !syscall::read( handle, module + name_rva, &name[ 0 ], name.size( ) ) )
			{
				continue;
			}

			if ( name == func )
			{
				if ( !syscall::read( handle, ords + ( i * sizeof( uint16_t ) ), &ordinal, sizeof( uint16_t ) ) )
				{
					return {};
				}

				if ( !syscall::read( handle, funcs + ( ordinal * sizeof( uint32_t ) ), &func_rva, sizeof( uint32_t ) ) )
				{
					return {};
				}

				auto proc_addr = module + func_rva;
				if ( proc_addr >= exp_dir_start && proc_addr < exp_dir_end )
				{
					std::array<char, 255> forwarded_name;
					syscall::read( handle, proc_addr, &forwarded_name[ 0 ], forwarded_name.size( ) );

					std::string name_str( forwarded_name.data( ) );

					size_t delim = name_str.find( '.' );
					if ( delim == std::string::npos ) return {};

					std::string fwd_mod_name = name_str.substr( 0, delim + 1 );
					fwd_mod_name += "dll";

					std::transform( fwd_mod_name.begin( ), fwd_mod_name.end( ), fwd_mod_name.begin( ), ::tolower );

					std::string fwd_func_name = name_str.substr( delim + 1 );

					return get_proc_address( handle, get_process_module_base( fwd_mod_name.c_str( ) ), fwd_func_name );
				}

				return proc_addr;
			}
		}

	}
}