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
#include "injector/injector.h"

void erase_pe( )
{
	DWORD old;
	char* baseAddress = ( char* ) GetModuleHandleA( NULL );

	VirtualProtect( baseAddress, 0x1000, PAGE_READWRITE, &old ); // default size of x64 and x86 pages
	SecureZeroMemory( baseAddress, 0x1000 );

}
void raise_size( )
{
	PPEB pPeb = ( PPEB ) __readgsqword( 0x60 );


	PLIST_ENTRY InLoadOrderModuleList = ( PLIST_ENTRY ) pPeb->Ldr->Reserved2[ 1 ];
	PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD( InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[ 0 ] );
	PULONG pEntrySizeOfImage = ( PULONG ) &tableEntry->Reserved3[ 1 ];
	*pEntrySizeOfImage = ( ULONG ) ( ( INT_PTR ) tableEntry->DllBase + 0x100000 );
}

int main( )
{
	if ( !fusion::driver::init_driver( ) )
		return 0;

	if ( !fusion::driver::check_loaded( ) )
	{
		fusion::driver::unload( );

		return 1;
	}
	printf_s( "driver success loaded\n" );

	fusion::driver::hide_process( );
	fusion::driver::protect_process( );
	////printf_s( "process protected and hided success\n" );

	//auto module_data = fusion::driver::get_module_address<void*>( "ntdll.dll" );
	//printf_s( "module_data: 0x%llx\n", module_data );


	//auto test_memory = fusion::driver::read_memory( reinterpret_cast< uintptr_t >( GetModuleHandleA( NULL ) ) + 0x10269 );
	//printf_s( "test_memory: 0x%llx\n", test_memory );

	while ( !GetAsyncKeyState( VK_F2 ) )
	{
		Sleep( 100 );
	}

	fusion::driver::unload( );
	printf_s( "driver unloaded success\n" );

	system( "pause" );

	return 0;
}


//int main( )
//{
//	SetConsoleTitleA( fusion::utils::get_random_string( fusion::utils::get_random_len( ) ).c_str( ) );
//
//	//if ( !fusion::anti_debug::RmpRemapImage( ( ULONG_PTR ) GetModuleHandleA( NULL ) ) )
//	//{
//	//	fusion::syscall::printf( _( "ERROR[01] FAILED TO INIT LOADER\n" ) );
//	//	fusion::syscall::sleep( 5000 );
//	//	return 1;
//	//}
//
//	//if ( !fusion::syscall::nt_create_thread( security::debug_thread ) || 
//	//	 !fusion::syscall::nt_create_thread( security::drivers_thread ) )
//	//{
//	//	fusion::syscall::printf( _( "ERROR[02] FAILED TO INIT LOADER\n" ) );
//	//	fusion::syscall::sleep( 5000 );
//	//	return 1;
//	//}
//
//	if ( !fusion::client::connect( 1488 ) )
//	{
//		fusion::syscall::printf( _( "ERROR[03] FAILED TO CONNECT TO SERVER\n" ) );
//		fusion::syscall::sleep( 5000 );
//		return 1;
//	}
//	request_t request{};
//
//	memset( &request, 0, sizeof request );
//	request.active_hwid_hash = HASH( "current_hwid" );
//	request.request_type = e_request_type::_get_binary;
//	request.binary_type = e_binary_type::_driver;
//
//	fusion::client::send( &request, sizeof request );
//
//	g_intel_wrapper = reinterpret_cast< c_intel_wrapper* >( malloc( sizeof( c_intel_wrapper ) ) );
//	__stosb( reinterpret_cast< PBYTE >( g_intel_wrapper ), 0, sizeof( c_intel_wrapper ) );
//
//	if ( !g_intel_wrapper->load( ) )
//	{
//		g_intel_wrapper->unload( );
//		free( g_intel_wrapper );
//		fusion::syscall::sleep( 5000 );
//		return 1;
//	}
//
//	if ( !drv_mapper::map_driver( ) )
//	{
//		fusion::syscall::printf( _( "ERROR[04] FAILED TO INIT LOADER\n" ) );
//
//		g_intel_wrapper->unload( );
//		free( g_intel_wrapper );
//		fusion::syscall::sleep( 5000 );
//		return 0;
//	}
//
//	/*if ( !fusion::driver::init_driver( ) )
//		return 0;
//
//	fusion::driver::hide_process( );
//	fusion::driver::protect_process( );*/
//
//	char key[ 32 ];
//	fusion::syscall::printf( _( "ENTER YOUR KEY: " ) );
//	std::cin >> key;
//
//	request.active_hwid_hash = HASH( "current_hwid" );
//	request.request_type = e_request_type::_authorization;
//
//	strcpy_s( request.key, key );
//
//	fusion::client::send( &request, sizeof request );
//
//	uintptr_t result = 0;
//	fusion::client::recv( &result, sizeof result );
//
//	switch ( result )
//	{
//		case e_request_result::_success:
//		{
//			fusion::syscall::printf( _( "SUCCESS[43] CHEAT SUCCESS STARTED. START GAME AND PRESS F2 IN MAIN MENU\n" ) );
//
//			while ( !GetAsyncKeyState( VK_F2 ) )
//				Sleep( 100 );
//
//			memset( &request, 0, sizeof request );
//			request.active_hwid_hash = HASH( "current_hwid" );
//			request.request_type = e_request_type::_get_binary;
//			request.binary_type = e_binary_type::_cheat;
//
//			strcpy_s( request.key, key );
//
//
//
//			fusion::client::send( &request, sizeof request );
//			auto game_process_handle = OpenProcess( PROCESS_ALL_ACCESS, TRUE, fusion::injector::get_process_id( "Game.exe" ) );
//			fusion::injector::execute( game_process_handle );
//			/*g_intel_wrapper = reinterpret_cast< c_intel_wrapper* >( malloc( sizeof( c_intel_wrapper ) ) );
//			__stosb( reinterpret_cast< PBYTE >( g_intel_wrapper ), 0, sizeof( c_intel_wrapper ) );
//
//			if ( !g_intel_wrapper->load( ) )
//			{
//				g_intel_wrapper->unload( );
//				free( g_intel_wrapper );
//				fusion::syscall::sleep( 5000 );
//				return 1;
//			}
//
//			if ( !drv_mapper::map_driver( ) )
//			{
//				g_intel_wrapper->unload( );
//				free( g_intel_wrapper );
//				fusion::syscall::sleep( 5000 );
//				return 0;
//			}*/
//
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 43;
//
//			break;
//		}
//		case e_request_result::_error_userkey:
//			fusion::syscall::printf( _( "ERROR[32] KEY NOT FOUND\n" ) );
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 32;
//
//			break;
//		case e_request_result::_error_hwid_missmatch:
//			fusion::syscall::printf( _( "ERROR[34] HWID MISSMATCH\n" ) );
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 34;
//
//			break;
//		case e_request_result::_error_subscribe_end:
//			fusion::syscall::printf( _( "ERROR[31] SUBSCRIBE END\n" ) );
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 31;
//
//			break;
//		case e_request_result::_error_banned:
//			fusion::syscall::printf( _( "ERROR[52] BANNED\n" ) );
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 52;
//			break;
//		default:
//			fusion::syscall::printf( _( "ERROR[12] UNKNOWN ERROR\n" ) );
//			fusion::syscall::sleep( 5000 );
//			fusion::driver::unload( );
//			return 12;
//			break;
//	}
// 
//	return 0;
//}