#include "include.h"

NTSTATUS driver_entry( uintptr_t magic_key, PDRIVER_OBJECT driver_object )
{
	UNREFERENCED_PARAMETER( driver_object );

	if ( magic_key != 0xffffff78504887 )
	{
		fusion::logging::message( _( "failed to load driver with code: 0x982\n" ) );

		return STATUS_ABANDONED;
	}

	PLARGE_INTEGER timeStamp;
	LARGE_INTEGER localTimeStamp;
	KeQueryTickCount( &timeStamp );

	TRACE( "time stamp %d", timeStamp );


	ExSystemTimeToLocalTime( timeStamp, &localTimeStamp );
	TRACE( "local time stamp %d", localTimeStamp );

	/*if ( fusion::winapi::offsets::setup( ) )
	{
		auto ntoskrnl = fusion::winapi::get_module_handle<void*>( _( "win32k.sys" ) );
		TRACE( "ntoskrnl: 0x%llx", ntoskrnl );

		auto function = fusion::winapi::find_pattern<uintptr_t>( ntoskrnl,
			_( "\x48\x8B\x05\x91\x05\x06\x00" ), _( "xxxxxx?" ) );
			
		if ( !function )
		{
			fusion::logging::message( _( "failed to load driver with code: 0x250\n" ) );

			return STATUS_ABANDONED;
		}

		address = RVA( function, 7 );
		TRACE( "address: 0x%llx", address );


		*( void** ) &o_ntuserexcludeupdatergn = InterlockedExchangePointer( ( volatile PVOID* ) address, hk_ntuserexcludeupdatergn );

		return STATUS_SUCCESS;
	}*/

	return STATUS_ACCESS_DENIED;
}