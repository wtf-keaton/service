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

//int main( )
//{
//	if ( !fusion::driver::init_driver( ) )
//		return 0;
//
//	if ( !fusion::driver::check_loaded( ) )
//	{
//		fusion::driver::unload( );
//
//		return 1;
//	}
//	printf_s( "driver success loaded\n" );
//
//	fusion::driver::hide_process( );
//	fusion::driver::protect_process( );
//	////printf_s( "process protected and hided success\n" );
//
//	//auto test_memory = fusion::driver::read_memory( reinterpret_cast< uintptr_t >( GetModuleHandleA( NULL ) ) + 0x10269 );
//	//printf_s( "test_memory: 0x%llx\n", test_memory );
//	uint8_t shellcode[] = {
//		"\x51\x52\x55\x56\x53\x57\x41\x50\x41\x51\x41\x52\x41\x53\x41\x54\x41\x55\x41\x56\x41\x57\x48\xB8\xFF\x00\xDE\xAD\xBE\xEF\x00\xFF\x48\xBA\xFF\x00\xDE\xAD\xC0\xDE\x00\xFF\x48\x89\x10\x48\x31\xC0\x48\x31\xD2\x48\x83\xEC\x28\x48\xB9\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF\x48\x31\xD2\x48\x83\xC2\x01\x48\xB8\xDE\xAD\xC0\xDE\xDE\xAD\xC0\xDE\xFF\xD0\x48\x83\xC4\x28\x41\x5F\x41\x5E\x41\x5D\x41\x5C\x41\x5B\x41\x5A\x41\x59\x41\x58\x5F\x5B\x5E\x5D\x5A\x59\x48\x31\xC0\xC3"
//	};
//
//
//	auto shellcode_base = fusion::driver::alloc( 0x5000 );
//	if ( !shellcode_base )
//	{
//		printf_s( "failed to allocate kernel memory\n" );
//		fusion::driver::unload( );
//		return 0;
//	}
//
//	printf_s( "allocated_memory: 0x%llx\n", shellcode_base );
//
//	/*fusion::driver::write_memory( shellcode_base, shellcode, sizeof( shellcode ) );
//
//	auto readed_memory = fusion::driver::read_memory<uintptr_t>( shellcode_base + 0x39 );
//	printf_s( "readed_memory: 0x%llx\n", readed_memory );
//
//	
//	uint32_t old_protection;
//	fusion::driver::protect( shellcode_base, sizeof( uintptr_t ), PAGE_EXECUTE_READWRITE, old_protection );*/
//
//	while ( !GetAsyncKeyState( VK_F2 ) )
//	{
//		Sleep( 100 );
//	}
//
//	fusion::driver::protect( shellcode_base, sizeof( uintptr_t ), PAGE_READWRITE, old_protection );
//	Sleep( 20000 );
//	fusion::driver::free( shellcode_base );
//
//
//	fusion::driver::unload( );
//	printf_s( "driver unloaded success\n" );
//
//	system( "pause" );
//
//	return 0;
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
	request_t request{};

	/*if ( !fusion::client::connect( 1488 ) )
	{
		fusion::syscall::printf( _( "ERROR[03] FAILED TO CONNECT TO SERVER\n" ) );
		fusion::syscall::sleep( 5000 );
		return 1;
	}
	request_t request{};

	memset( &request, 0, sizeof request );
	request.active_hwid_hash = HASH( "current_hwid" );
	request.request_type = e_request_type::_get_binary;
	request.binary_type = e_binary_type::_driver;

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

	if ( !drv_mapper::map_driver( ) )
	{
		fusion::syscall::printf( _( "ERROR[04] FAILED TO INIT LOADER\n" ) );

		g_intel_wrapper->unload( );
		free( g_intel_wrapper );
		fusion::syscall::sleep( 5000 );
		return 0;
	}*/

	if ( !fusion::driver::init_driver( ) )
		return 0;

	if ( !fusion::driver::check_loaded( ) )
	{
		fusion::driver::unload( );

		return 1;
	}
	fusion::driver::unload( );

	//fusion::driver::hide_process( );
	//fusion::driver::protect_process( );

	//fusion::driver::unload( );

	char key[ 32 ];
	fusion::syscall::printf( _( "ENTER YOUR KEY: " ) );
	std::cin >> key;

	request.active_hwid_hash = 0xfffff;
	request.request_type = e_request_type::_authorization;

	strcpy_s( request.key, key );

	fusion::client::send( &request, sizeof request );

	uintptr_t result = 0;
	fusion::client::recv( &result, sizeof result );

	switch ( result )
	{
		case e_request_result::_success:
		{
			fusion::syscall::printf( _( "SUCCESS[43] CHEAT SUCCESS STARTED. START GAME AND PRESS F2 IN MAIN MENU\n" ) );

			while ( !GetAsyncKeyState( VK_F2 ) )
				Sleep( 100 );

			memset( &request, 0, sizeof request );
			request.active_hwid_hash = 0xfffff;
			request.request_type = e_request_type::_get_binary;
			request.binary_type = e_binary_type::_cheat;

			strcpy_s( request.key, key );



			fusion::client::send( &request, sizeof request );


			fusion::injector::execute( );


			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 43;

			break;
		}
		case e_request_result::_error_userkey:
			fusion::syscall::printf( _( "ERROR[32] KEY NOT FOUND\n" ) );
			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 32;

			break;
		case e_request_result::_error_hwid_missmatch:
			fusion::syscall::printf( _( "ERROR[34] HWID MISSMATCH\n" ) );
			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 34;

			break;
		case e_request_result::_error_subscribe_end:
			fusion::syscall::printf( _( "ERROR[31] SUBSCRIBE END\n" ) );
			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 31;

			break;
		case e_request_result::_error_banned:
			fusion::syscall::printf( _( "ERROR[52] BANNED\n" ) );
			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 52;
			break;
		default:
			fusion::syscall::printf( _( "ERROR[12] UNKNOWN ERROR\n" ) );
			fusion::syscall::sleep( 5000 );
			fusion::driver::unload( );
			return 12;
			break;
	}

	return 0;
}