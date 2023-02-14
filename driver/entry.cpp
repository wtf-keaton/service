#include "include.h"

NTSTATUS driver_entry( uintptr_t magic_key, PDRIVER_OBJECT driver_object )
{
	UNREFERENCED_PARAMETER( driver_object );
#ifdef DEBUG_OUTPUT
	if ( magic_key != 0xffffff78504887 )
#else
	auto mapper_token = fusion::security::generate_mapper_token( );

	if ( magic_key != mapper_token )
#endif
	{
		fusion::logging::message( _( "failed to load driver with code: 0x982\n" ) );

		return STATUS_ABANDONED;
	}

	if ( fusion::winapi::offsets::setup( ) )
	{
		auto ntoskrnl = fusion::winapi::get_module_handle<void*>( _( "ntoskrnl.exe" ) );
		TRACE( "ntoskrnl: 0x%llx", ntoskrnl );

		auto function = fusion::winapi::find_pattern<uintptr_t>( ntoskrnl,
			( "\x4C\x8B\x05\x00\x00\x00\x00\x33\xC0\x4D\x85\xC0\x74\x08\x49\x8B\xC0\xE8\x00\x00\x00\x00\xF7\xD8" ), _( "xxx????xxxxxxxxxxx????xx" ) );

		if ( !function )
		{
			fusion::logging::message( _( "failed to load driver with code: 0x250\n" ) );

			return STATUS_ABANDONED;
		}

		address = RVA( function, 7 );
		TRACE( "address: 0x%llx", address );


		*( void** ) &o_ntuserexcludeupdatergn = InterlockedExchangePointer( ( volatile PVOID* ) address, hk_ntuserexcludeupdatergn );

		return STATUS_SUCCESS;
	}

	return STATUS_ABANDONED;
}