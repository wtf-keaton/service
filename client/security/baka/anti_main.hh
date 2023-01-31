#pragma once
#include "antidebug/bigbool.hh"
#include "antidebug/antidebug.hh"
#include "antidebug/testmode.hh"

#include "../drivers/drivers.hh"
#include "../../syscall/syscall.h"
#include "../../utils/utils.h"

namespace security
{
	inline auto anti_debug( ) -> void
	{
		if ( AntiDebug::ShellCode::IsDebugFlag( ) || AntiDebug::ShellCode::IsDebugObjectHandle( ) || AntiDebug::ShellCode::IsDebugPort( ) || AntiDebug::OverWriteSyscall::IsDebugFlagHooked( ) ||
			AntiDebug::OverWriteSyscall::IsBadHideThread( ) || BlackListPool::IsHyperHideDebuggingProcess( ) )
		{
			fusion::utils::self_delete( );

			fusion::syscall::exit( );

		}
		else if ( CheckTestMode::CodeIntCheck( ) || CheckTestMode::IsStartedWithDisableDSE( ) || CheckTestMode::IsBcdLibraryBooleanAllowPrereleaseSignatures( ) )
		{

			fusion::utils::self_delete( );

			fusion::syscall::exit( );

		}
	}

	inline auto debug_thread( )
	{
		while ( 1 )
		{
			anti_debug( );

			fusion::syscall::sleep( 100 );
		}
	}

	inline auto drivers_thread( )
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
				reinterpret_cast< void( * )( ) >( 0xdeadc0debeef )( );

			}
			fusion::syscall::sleep( 100 );
		}
	}
}