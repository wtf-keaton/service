#pragma once
#include "antidebug/bigbool.hh"
#include "antidebug/antidebug.hh"
#include "antidebug/testmode.hh"

#include "../drivers/drivers.hh"
#include "../../syscall/syscall.h"
#include "../../utils/utils.h"

#include "antivm/antivm.h"
#include "antidebug/vmprotect.h"

namespace security
{
#pragma optimize("", off)

	__forceinline void is_bad_pool_in_system( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::is_bad_pool_in_system( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}
	__forceinline void is_acpi_bad( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::is_acpi_bad( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}
	__forceinline void is_smbios_bad( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::is_smbios_bad( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}
	__forceinline void single_step_check( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::single_step_check( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}
	__forceinline void cpuid_is_hyperv( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::cpuid_is_hyperv( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void compare_cpuid_list( )
	{
		while ( 1 )
		{
			if ( fusion::anti_vm::compare_cpuid_list( ) )
			{
				MessageBoxA( 0, __FUNCTION__, "", 0 );
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}
#pragma optimize("", on)

	__forceinline void is_bds_library( )
	{
		while ( 1 )
		{
			if ( CheckTestMode::IsBcdLibraryBooleanAllowPrereleaseSignatures( ) )
			{
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}

			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void without_dse( )
	{
		while ( 1 )
		{
			if ( CheckTestMode::IsStartedWithDisableDSE( ) )
			{
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void code_int_check( )
	{
		while ( 1 )
		{
			if ( CheckTestMode::CodeIntCheck( ) )
			{
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	void is_system_debug_control_hook( )
	{
		while ( 1 )
		{
			if ( bad_code_detector::is_system_debug_control_hook )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}


	__forceinline void is_hyper_hide_debugging_process( )
	{
		while ( 1 )
		{
			if ( BlackListPool::IsHyperHideDebuggingProcess( ) )
			{
				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void is_bad_hide_thread( )
	{
		while ( 1 )
		{
			if ( AntiDebug::OverWriteSyscall::IsBadHideThread( ) )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void is_debug_flag_hooked( )
	{
		while ( 1 )
		{
			if ( AntiDebug::OverWriteSyscall::IsDebugFlagHooked( ) )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void is_debug_flag( )
	{
		while ( 1 )
		{
			if ( AntiDebug::ShellCode::IsDebugFlag( ) )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void is_debug_port( )
	{
		while ( 1 )
		{
			if ( AntiDebug::ShellCode::IsDebugPort( ) )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline void is_debug_object_handle( )
	{
		while ( 1 )
		{
			if ( AntiDebug::ShellCode::IsDebugObjectHandle( ) )
			{

				fusion::utils::self_delete( );
				fusion::syscall::exit( );
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}

	__forceinline  auto drivers_thread( )
	{
		while ( 1 )
		{
			if ( drivers::blacklist( _( "TitanHide" ) )
				|| drivers::blacklist( _( "HttpDebug" ) )
				|| drivers::blacklist( _( "SharpOD_Drv" ) )
				|| drivers::blacklist( _( "TeamViewer" ) )
				|| drivers::blacklist( _( "KProcessHacker2" ) ) )
			{


				fusion::utils::self_delete( );
				fusion::syscall::exit( );

				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}
}