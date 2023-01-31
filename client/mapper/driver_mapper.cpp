#include "../connection/connection.h"
#include "../helpers/structs.h"
#include "../json/json.h"

#include "intel_wrapper.h"
#include "driver_mapper.h"

#include "../syscall/syscall.h"

bool drv_mapper::map_driver( const char* key )
{
	binary_request_t binary{};
	fusion::client::recv( &binary, sizeof binary );

	uint64_t allocated_base = g_intel_wrapper->allocate_pool( POOL_TYPE::NonPagedPool, binary.size );
	if ( !allocated_base )
	{
		g_intel_wrapper->free_pool( allocated_base );
		g_intel_wrapper->unload( );

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
				auto addr = alloc_import( 
					g_intel_wrapper->get_kernel_export( 
						g_intel_wrapper->get_kernel_module_base( key.c_str( ) ), HASH( name.c_str( ) ) ), HASH( name.c_str( ) ) );
				final_imports[ name ] = addr;

				imports_count++;
			}
		}
		imports.clear( );
	}

	if ( !fusion::client::send( &allocated_base, sizeof( allocated_base ) ) )
	{
		g_intel_wrapper->free_pool( allocated_base );
		g_intel_wrapper->unload( );
		return false;
	}

	fusion::client::send( final_imports.dump( ) );
	final_imports.clear( );

	std::vector<char> data;
	int size = fusion::client::read_stream( data );

	if ( size == binary.size )
	{
		if ( !g_intel_wrapper->write_memory( allocated_base, reinterpret_cast< void* >( data.data( ) ), data.size( ) ) )
		{
			g_intel_wrapper->free_pool( allocated_base );
			g_intel_wrapper->unload( );

			return false;
		}
		data.clear( );

		auto entry = allocated_base + binary.entry;

		NTSTATUS result = 0;
		if ( !g_intel_wrapper->call_function_at_kernel( &result, entry, 0xffffff78504887, 0 ) )
		{
			g_intel_wrapper->free_pool( allocated_base );
			g_intel_wrapper->unload( );

			return false;
		}

		if ( !NT_SUCCESS( result ) )
		{
			g_intel_wrapper->free_pool( allocated_base );
			g_intel_wrapper->unload( );

			fusion::syscall::reboot_pc( );

			return false;
		}

		g_intel_wrapper->unload( );

		return true;
	}

	return false;
}

uint64_t drv_mapper::alloc_import( uint64_t address, uint64_t hash )
{
	if ( hash == HASH( "PsProcessType" ) || hash == HASH( "PsThreadType" ) || hash == HASH( "IoFileObjectType" ) )
		return address;

	uint8_t shell[] = { 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x66, 0x48, 0x0F, 0x6E, 0xC0, 0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x66, 0x48, 0x0F, 0x6E, 0xC8, 0x66, 0x0F, 0xEF, 0xC1, 0x66, 0x48, 0x0F, 0x7E, 0xC0, 0xFF, 0xE0 };

	*reinterpret_cast< uint64_t* >( &shell[ 2 ] ) = address ^ hash;
	*reinterpret_cast< uint64_t* >( &shell[ 17 ] ) = hash;

	uint64_t allocated = g_intel_wrapper->allocate_pool( POOL_TYPE::NonPagedPool, sizeof( shell ), static_cast< uint32_t >( address ) );
	if ( !allocated )
		return 0;

	g_intel_wrapper->write_memory( allocated, shell, sizeof( shell ) );
	return allocated;
}
