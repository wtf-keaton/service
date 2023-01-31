#include <windows.h>

#include "connection/connection.h"
#include "helpers/structs.h"
#include "syscall/syscall.h"
#include "mapper/driver_mapper.h"

#include "json/json.h"
#include "hwid/hwid.h"

#include "security/baka/anti_main.hh"
#include "utils/utils.h"
#include "security/remapping/remapping.h"

#include <iostream>
#pragma comment(linker, "/ALIGN:0x10000")

#include "driver/driver.h"

//int main( )
//{
//	if ( !fusion::driver::init_driver( ) )
//		return 0xDEAD;
//
//	auto test = fusion::driver::get_module_address<void*>( "ntdll.dll" );
//
//	printf_s( "test = 0x%llx\n", test );
//
//	fusion::driver::unload( );
//
//	//auto test_memory = fusion::driver::read_memory( reinterpret_cast< uintptr_t >( GetModuleHandleA( NULL ) ) + 0x20 );
//	//printf_s( "test_memory: 0x%llx\n", test_memory );
//}

int main( )
{
	
	SetConsoleTitleA( fusion::utils::get_random_string( fusion::utils::get_random_len( ) ).c_str( ) );

	//if ( !fusion::anti_debug::RmpRemapImage( ( ULONG_PTR ) GetModuleHandleA( NULL ) ) )
	//{
	//	fusion::syscall::printf( _( "ERROR[01] FAILED TO INIT LOADER\n" ) );
	//	fusion::syscall::sleep( 5000 );
	//	return 1;
	//}

	//if ( !fusion::syscall::nt_create_thread( security::debug_thread ) || 
	//	 !fusion::syscall::nt_create_thread( security::drivers_thread ) )
	//{
	//	fusion::syscall::printf( _( "ERROR[02] FAILED TO INIT LOADER\n" ) );
	//	fusion::syscall::sleep( 5000 );
	//	return 1;
	//}

	if ( !fusion::client::connect( 1488 ) )
	{
		fusion::syscall::printf( _( "ERROR[03] FAILED TO CONNECT TO SERVER\n" ) );
		fusion::syscall::sleep( 5000 );
		return 1;
	}

	char key[ 32 ];
	fusion::syscall::printf( _( "ENTER YOUR KEY: " ) );
	std::cin >> key;

	request_t request{};
	request.active_hwid_hash = HASH( "current_hwid" );
	request.request_type = e_request_type::_authorization;

	strcpy_s( request.key, key );

	fusion::client::send( &request, sizeof request );

	uintptr_t result = 0;
	fusion::client::recv( &result, sizeof result );

	switch ( result )
	{
		case e_request_result::_success:
			memset( &request, 0, sizeof request );
			request.active_hwid_hash = HASH( "current_hwid" );
			request.request_type = e_request_type::_get_binary;
			request.binary_type = e_binary_type::_driver;

			strcpy_s( request.key, key );

			fusion::client::send( &request, sizeof request );

			g_intel_wrapper = reinterpret_cast< c_intel_wrapper* >( malloc( sizeof( c_intel_wrapper ) ) );
			__stosb( reinterpret_cast< PBYTE >( g_intel_wrapper ), 0, sizeof( c_intel_wrapper ) );

			if ( !g_intel_wrapper->load( ) )
			{
				g_intel_wrapper->unload( );
				free( g_intel_wrapper );
				fusion::syscall::sleep( 5000 );
				return 1;
			}

			if ( !drv_mapper::map_driver( key ) )
			{
				g_intel_wrapper->unload( );
				free( g_intel_wrapper );
				fusion::syscall::sleep( 5000 );
				return 0;
			}

			fusion::syscall::printf( _( "SUCCESS[43] SPOOFER SUCCESS STARTED\n" ) );
			fusion::syscall::sleep( 5000 );
			return 43;

			break;
		case e_request_result::_error_userkey:
			fusion::syscall::printf( _( "ERROR[32] KEY NOT FOUND\n" ) );
			fusion::syscall::sleep( 5000 );
			return 32;

			break;
		case e_request_result::_error_hwid_missmatch:
			fusion::syscall::printf( _( "ERROR[34] HWID MISSMATCH\n" ) );
			fusion::syscall::sleep( 5000 );
			return 34;

			break;
		case e_request_result::_error_subscribe_end:
			fusion::syscall::printf( _( "ERROR[31] SUBSCRIBE END\n" ) );
			fusion::syscall::sleep( 5000 );
			return 31;

			break;
		case e_request_result::_error_banned:
			fusion::syscall::printf( _( "ERROR[52] BANNED\n" ) );
			fusion::syscall::sleep( 5000 );
			return 52;
			break;
		default:
			fusion::syscall::printf( _( "ERROR[12] UNKNOWN ERROR\n" ) );
			fusion::syscall::sleep( 5000 );
			return 12;
			break;
	}
 
	return 0;
}