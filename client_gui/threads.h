#pragma once
#include "globals.h"
#include "connection/connection.h"
#include "driver/driver.h"
#include "injector/injector.h"

#include "mapper/driver_mapper.h"
#include "security/remapping/remapping.h"

#include "security/baka/anti_main.hh"
#pragma comment(linker, "/ALIGN:0x10000")


static e_page_state page = e_page_state::_loading_bar;

void initializing_test( )
{

	strcpy_s( globals.status, _( "Loading" ) );
	Sleep( 2000 );
	strcpy_s( globals.status, _( "Connecting to the server" ) );
	if ( !fusion::client::connect( 1488 ) )
	{
		strcpy_s( globals.error, _( "Failed to connect to server" ) );
		page = e_page_state::_error;
		Sleep( 5000 );
		exit( 1 );
	}
	else
	{
		strcpy_s( globals.status, _( "Connected" ) );
		Sleep( 2000 );
		strcpy_s( globals.status, _( "Loading driver [stage #1]" ) );

		request_t request{};

		memset( &request, 0, sizeof request );
		request.active_hwid_hash = 0xffff;
		request.request_type = e_request_type::_get_binary;
		request.binary_type = e_binary_type::_driver;

		fusion::client::send( &request, sizeof request );

		g_intel_wrapper = reinterpret_cast< c_intel_wrapper* >( malloc( sizeof( c_intel_wrapper ) ) );
		__stosb( reinterpret_cast< PBYTE >( g_intel_wrapper ), 0, sizeof( c_intel_wrapper ) );

		if ( !g_intel_wrapper->load( ) )
		{
			g_intel_wrapper->unload( );
			free( g_intel_wrapper );
			page = e_page_state::_error;
			fusion::syscall::sleep( 5000 );

			fusion::syscall::exit( );
		}
		strcpy_s( globals.status, _( "Loading driver [stage #2]" ) );

		if ( !drv_mapper::map_driver( ) )
		{
			g_intel_wrapper->unload( );
			free( g_intel_wrapper );

			page = e_page_state::_error;
			fusion::syscall::sleep( 5000 );

			fusion::syscall::exit( );
		}

		strcpy_s( globals.status, _( "Loading driver [stage #3]" ) );

		fusion::driver::init_driver( );

		if ( !fusion::driver::check_loaded( ) )
		{
			fusion::driver::unload( );
			strcpy_s( globals.error, _( "Failed to load driver" ) );

			page = e_page_state::_error;

		}
		globals.is_loaded = true;

		strcpy_s( globals.status, _( "Driver loaded" ) );
		fusion::syscall::sleep( 3000 );

		strcpy_s( globals.status, _( "Starting" ) );
		fusion::syscall::sleep( 2000 );

		//fusion::syscall::nt_create_thread( security::code_int_check );
		//fusion::syscall::nt_create_thread( security::is_bad_hide_thread );
		//fusion::syscall::nt_create_thread( security::is_bds_library );
		//fusion::syscall::nt_create_thread( security::is_debug_flag );
		//fusion::syscall::nt_create_thread( security::is_debug_port );
		//fusion::syscall::nt_create_thread( security::is_debug_object_handle );
		//fusion::syscall::nt_create_thread( security::is_hyper_hide_debugging_process );
		//fusion::syscall::nt_create_thread( security::without_dse );
		//fusion::syscall::nt_create_thread( security::drivers_thread );

		//fusion::driver::hide_process( );
		//fusion::driver::protect_process( );
	}
	page = e_page_state::_auth;
}

void inject_thread( )
{
	if ( !fusion::injector::execute( ) )
	{
		page = e_page_state::_error;
		fusion::syscall::sleep( 5000 );

		fusion::syscall::exit( );
	}
	
	fusion::driver::unload( );

	fusion::syscall::sleep( 5000 );

	fusion::syscall::exit( );
}
