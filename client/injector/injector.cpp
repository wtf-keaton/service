#include "injector.h"

namespace fusion::injector
{
	bool execute( )
	{
		binary_request_t binary{};
		fusion::client::recv( &binary, sizeof binary );

		auto allocated_base = fusion::driver::alloc( binary.size );
		if ( !allocated_base )
		{
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

					auto address = get_proc_address( key.c_str( ), HASH( name.c_str( ) ) );
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

		std::vector<char> data;
		int size = fusion::client::read_stream( data );

		if ( size == binary.size )
		{

		}
	}

	uintptr_t get_proc_address( const char* module, hash_t hash )
	{

	}
}