#include "injector.h"

#include "../globals.h"
namespace fusion::injector
{
	std::map<std::string, uint64_t> import;
#pragma optimize( "", off )
	bool execute( )
	{
		binary_request_t binary{};
		if ( !fusion::client::recv( &binary, sizeof binary ) )
		{
			strcpy_s( globals.error, _( "failed to get data from server" ) );
			return false;
		}

		auto allocated_base = fusion::driver::alloc( binary.size );
		if ( !allocated_base )
		{
			strcpy_s( globals.error, _( "failed to allocate memory for cheat" ) );

			fusion::driver::unload( );
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

					auto address = get_proc_address( fusion::driver::get_module_address<uintptr_t>( key.c_str( ) ), name );
					final_imports[ name ] = address;

					imports_count++;
				}
			}
			imports.clear( );
		}

		if ( !fusion::client::send( &allocated_base, sizeof( allocated_base ) ) )
		{
			fusion::driver::free( allocated_base );
			fusion::driver::unload( );
			return false;
		}

		fusion::client::send( final_imports.dump( ) );
		final_imports.clear( );

		globals.inject_status = e_injection_state::_progress;

		std::vector<char> data;
		int size = fusion::client::read_stream( data, binary.size );

		if ( size == binary.size )
		{
			globals.inject_status = e_injection_state::_parse_imports;
			if ( !parse_imports( _( "user32.dll" ) ) )
			{
				strcpy_s( globals.error, _( "failed to parse imports" ) );
				fusion::driver::unload( );

				return false;
			}

			uintptr_t iat_function_ptr = import[ _( "NtUserGetForegroundWindow" ) ];
			if ( !iat_function_ptr )
			{
				strcpy_s( globals.error, _( "failed to get function" ) );

				fusion::driver::unload( );

				return false;
			}

			globals.inject_status = e_injection_state::_injection;

			auto orginal_function_addr = fusion::driver::read_memory<uintptr_t>( iat_function_ptr );


			uint8_t shellcode[] =
			{
				 0x51, 0x52, 0x55, 0x56, 0x53, 0x57,
				 0x41, 0x50, 0x41, 0x51, 0x41, 0x52,
				 0x41, 0x53, 0x41, 0x54, 0x41, 0x55,
				 0x41, 0x56, 0x41, 0x57, 0x48, 0xB8,
				 0xFF, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
				 0x00, 0xFF, 0x48, 0xBA, 0x00, 0xDE,
				 0xAD, 0xC0, 0xDE, 0x00, 0xFF, 0x48,
				 0x89, 0x10, 0x48, 0x31, 0xC0, 0x48,
				 0x31, 0xD2, 0x48, 0x83, 0xEC, 0x28,
				 0x48, 0xB9, 0xDE, 0xAD, 0xBE, 0xEF,
				 0xDE, 0xAD, 0xBE, 0xEF, 0x48, 0x31,
				 0xD2, 0x48, 0x83, 0xC2, 0x01, 0x48,
				 0xB8, 0xDE, 0xAD, 0xC0, 0xDE, 0xDE,
				 0xAD, 0xC0, 0xDE, 0xFF, 0xD0, 0x48,
				 0x83, 0xC4, 0x28, 0x41, 0x5F, 0x41,
				 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x41,
				 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41,
				 0x58, 0x5F, 0x5B, 0x5E, 0x5D, 0x5A,
				 0x59, 0x48, 0x31, 0xC0, 0xC3
			};

			fusion::driver::write_memory( allocated_base, data.data( ), data.size( ) );

			auto entry = allocated_base + binary.entry;

			*reinterpret_cast< uintptr_t* >( shellcode + 0x18 ) = iat_function_ptr;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x22 ) = orginal_function_addr;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x39 ) = allocated_base;
			*reinterpret_cast< uintptr_t* >( shellcode + 0x4a ) = entry;

			auto shellcode_base = fusion::driver::alloc( sizeof( shellcode ) );
			if ( !shellcode_base )
			{
				fusion::driver::free( allocated_base );
				fusion::driver::unload( );
			}

			fusion::driver::write_memory( shellcode_base, shellcode, sizeof( shellcode ) );

			fusion::driver::protect_1( iat_function_ptr, sizeof( uintptr_t ) );
			fusion::driver::write_memory( iat_function_ptr, &shellcode_base, sizeof( uint64_t ) );
			Sleep( 3000 );
			if ( iat_function_ptr != NULL )
			{
				fusion::driver::protect_2( iat_function_ptr, sizeof( uintptr_t ) );

				Sleep( 1500 );
			}
			globals.inject_status = e_injection_state::_injected;

			fusion::driver::unload( );

			return true;
		}
	}
#pragma optimize( "", on )

	uintptr_t get_proc_address( uintptr_t module, std::string_view func )
	{
		if ( !module )
			return 0;

		IMAGE_DOS_HEADER dos_header{};
		fusion::driver::read_memory( module, &dos_header, sizeof( dos_header ) );

		if ( dos_header.e_magic != IMAGE_DOS_SIGNATURE )
			return 0;

		IMAGE_NT_HEADERS nt_header{};
		fusion::driver::read_memory( module + dos_header.e_lfanew, &nt_header, sizeof( nt_header ) );

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

		fusion::driver::read_memory( exp_dir_start, &exp_dir, sizeof( exp_dir ) );

		auto funcs = module + exp_dir.AddressOfFunctions;
		auto ords = module + exp_dir.AddressOfNameOrdinals;
		auto names = module + exp_dir.AddressOfNames;

		for ( int i = 0; i < exp_dir.NumberOfFunctions; ++i )
		{
			uint32_t name_rva{};
			uint32_t func_rva{};
			uint16_t ordinal{};
			fusion::driver::read_memory( names + ( i * sizeof( uint32_t ) ), &name_rva, sizeof( uint32_t ) );

			std::string name;
			name.resize( func.size( ) );
			fusion::driver::read_memory( module + name_rva, &name[ 0 ], name.size( ) );

			if ( name == func )
			{
				fusion::driver::read_memory( ords + ( i * sizeof( uint16_t ) ), &ordinal, sizeof( uint16_t ) );
				fusion::driver::read_memory( funcs + ( ordinal * sizeof( uint32_t ) ), &func_rva, sizeof( uint32_t ) );

				auto proc_addr = module + func_rva;
				if ( proc_addr >= exp_dir_start && proc_addr < exp_dir_end )
				{
					std::array<char, 255> forwarded_name;
					fusion::driver::read_memory( proc_addr, &forwarded_name[ 0 ], forwarded_name.size( ) );

					std::string name_str( forwarded_name.data( ) );

					size_t delim = name_str.find( '.' );
					if ( delim == std::string::npos ) return {};

					std::string fwd_mod_name = name_str.substr( 0, delim + 1 );
					fwd_mod_name += _( "dll" );

					std::transform( fwd_mod_name.begin( ), fwd_mod_name.end( ), fwd_mod_name.begin( ), ::tolower );

					std::string fwd_func_name = name_str.substr( delim + 1 );

					return get_proc_address( fusion::driver::get_module_address<uintptr_t>( fwd_mod_name.c_str( ) ), fwd_func_name );
				}

				return proc_addr;
			}
		}

	}

	bool parse_imports( const char* module_name )
	{
		auto base = fusion::driver::get_module_address<uintptr_t>( module_name );
		if ( !base )
		{
			return false;
		}

		auto dos_header = fusion::driver::read_memory< IMAGE_DOS_HEADER >( base );
		auto nt_headers = fusion::driver::read_memory< IMAGE_NT_HEADERS >( base + dos_header.e_lfanew );
		auto descriptor = fusion::driver::read_memory< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress );

		int descriptor_count{};
		int thunk_count{};

		while ( descriptor.Name )
		{
			auto first_thunk = fusion::driver::read_memory< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk );
			auto original_first_thunk = fusion::driver::read_memory< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk );
			thunk_count = 0;

			while ( original_first_thunk.u1.AddressOfData )
			{
				char name[ 256 ] = { 0 };
				fusion::driver::read_memory( base + original_first_thunk.u1.AddressOfData + 0x2, name, 256 );
				std::string str_name = name;
				auto thunk_offset = thunk_count * sizeof( uintptr_t );

				if ( str_name.length( ) > 0 )
					import[ str_name ] = base + descriptor.FirstThunk + thunk_offset;


				++thunk_count;
				first_thunk = fusion::driver::read_memory< IMAGE_THUNK_DATA >( base + descriptor.FirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
				original_first_thunk = fusion::driver::read_memory< IMAGE_THUNK_DATA >( base + descriptor.OriginalFirstThunk + sizeof( IMAGE_THUNK_DATA ) * thunk_count );
			}

			++descriptor_count;
			descriptor = fusion::driver::read_memory< IMAGE_IMPORT_DESCRIPTOR >( base + nt_headers.OptionalHeader.DataDirectory[ 1 ].VirtualAddress + sizeof( IMAGE_IMPORT_DESCRIPTOR ) * descriptor_count );
		}

		return ( import.size( ) > 0 );
	}
}