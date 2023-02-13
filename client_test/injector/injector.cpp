#include "injector.h"
#include "../syscall/syscall.h"
#include "../driver/global.hh"
namespace fusion::injector
{
	std::map<std::string, uint64_t> import;

	bool execute( )
	{
		binary_request_t binary{};
		fusion::client::recv( &binary, sizeof binary );

		driver::memory = new memory_mgr( "divan-engine", "Game.exe" );

		auto allocated_base = driver::memory->alloc_memory( binary.size, PAGE_EXECUTE_READWRITE );
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

					auto address = get_proc_address( driver::memory->module_base_address( key.c_str( ) ), name );
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

			if ( !parse_imports( "user32.dll" ) )
			{
				printf_s( "failed to parse imports\n" );
				return false;
			}

			uintptr_t iat_function_ptr = import[ "NtUserGetForegroundWindow" ];
			if ( !iat_function_ptr )
			{
				printf_s( "failed to get IAT function\n" );

				return false;
			}

			uintptr_t orginal_function_addr = driver::memory->read<uintptr_t>( iat_function_ptr );

			uint8_t shellcode[] = {
				"\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3"
			};


			driver::memory->write( allocated_base, data.data( ), data.size( ) );

			auto entry = allocated_base + binary.entry;

			*reinterpret_cast< uintptr_t* >( shellcode + 0x18 ) = iat_function_ptr;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x22 ) = orginal_function_addr;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x39 ) = allocated_base;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x4a ) = entry;
	

			auto shellcode_base = driver::memory->alloc_memory( sizeof( shellcode ), PAGE_EXECUTE_READWRITE );

			driver::memory->write( shellcode_base, shellcode, sizeof( shellcode ) );

			uint32_t old_protection{};
			driver::memory->protect_memory( iat_function_ptr, sizeof( uint64_t ), PAGE_READWRITE, old_protection );
			driver::memory->write( iat_function_ptr, &shellcode_base, sizeof( uint64_t ) );
			Sleep( 3000 );
			if ( iat_function_ptr != NULL )
			{
				driver::memory->protect_memory( iat_function_ptr, sizeof( uint64_t ), PAGE_READONLY, old_protection );
				Sleep( 1500 );
			}
			printf_s( "[ + ] Succes injected to \"%s\"\n", "Game.exe" );

			// driver::memory->free_memory( shellcode_base );

			return true;
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

	uintptr_t get_proc_address( uintptr_t module, std::string_view func )
	{
		if ( !module )
			return 0;

		IMAGE_DOS_HEADER dos_header{};
		driver::memory->read( module, &dos_header, sizeof( dos_header ) );

		if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE )
			return 0;

		IMAGE_NT_HEADERS nt_header{};
		driver::memory->read( module + dos_header.e_lfanew, &nt_header, sizeof( nt_header ) );

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

		driver::memory->read( exp_dir_start, &exp_dir, sizeof( exp_dir ) );

		auto funcs = module + exp_dir.AddressOfFunctions;
		auto ords = module + exp_dir.AddressOfNameOrdinals;
		auto names = module + exp_dir.AddressOfNames;

		for ( int i = 0; i < exp_dir.NumberOfFunctions; ++i )
		{
			uint32_t name_rva{};
			uint32_t func_rva{};
			uint16_t ordinal{};
			driver::memory->read( names + ( i * sizeof( uint32_t ) ), &name_rva, sizeof( uint32_t ) );

			std::string name;
			name.resize( func.size( ) );
			driver::memory->read( module + name_rva, &name[ 0 ], name.size( ) );

			if ( name == func )
			{
				driver::memory->read( ords + ( i * sizeof( uint16_t ) ), &ordinal, sizeof( uint16_t ) );
				driver::memory->read( funcs + ( ordinal * sizeof( uint32_t ) ), &func_rva, sizeof( uint32_t ) );

				auto proc_addr = module + func_rva;
				if ( proc_addr >= exp_dir_start && proc_addr < exp_dir_end )
				{
					std::array<char, 255> forwarded_name;
					driver::memory->read( proc_addr, &forwarded_name[ 0 ], forwarded_name.size( ) );

					std::string name_str( forwarded_name.data( ) );

					size_t delim = name_str.find( '.' );
					if ( delim == std::string::npos ) return {};

					std::string fwd_mod_name = name_str.substr( 0, delim + 1 );
					fwd_mod_name += "dll";

					std::transform( fwd_mod_name.begin( ), fwd_mod_name.end( ), fwd_mod_name.begin( ), ::tolower );

					std::string fwd_func_name = name_str.substr( delim + 1 );

					return get_proc_address( driver::memory->module_base_address( fwd_mod_name.c_str( ) ), fwd_func_name );
				}

				return proc_addr;
			}
		}

	}

	bool parse_imports( const char* module_name )
	{
		auto base = driver::memory->module_base_address( module_name );
		if ( !base )
		{
			return false;
		}

		auto dos_header = driver::memory->read< IMAGE_DOS_HEADER >( base );
		auto nt_headers = driver::memory->read< IMAGE_NT_HEADERS >( base + dos_header.e_lfanew );
		auto descriptor = driver::memory->read< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress );

		int descriptor_count{};
		int thunk_count{};

		while ( descriptor.Name )
		{
			auto first_thunk = driver::memory->read< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk );
			auto original_first_thunk = driver::memory->read< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk );
			thunk_count = 0;

			while ( original_first_thunk.u1.AddressOfData )
			{
				char name[ 256 ] = { 0 };
				driver::memory->read( base + original_first_thunk.u1.AddressOfData + 0x2, name, 256 );
				std::string str_name = name;
				auto thunk_offset = thunk_count * sizeof( uintptr_t );

				if ( str_name.length( ) > 0 )
					import[ str_name ] = base + descriptor.FirstThunk + thunk_offset;


				++thunk_count;
				first_thunk = driver::memory->read< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
				original_first_thunk = driver::memory->read< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
			}

			++descriptor_count;
			descriptor = driver::memory->read< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress + sizeof( IMAGE_IMPORT_DESCRIPTOR ) * descriptor_count );
		}

		return ( import.size( ) > 0 );
	}

}