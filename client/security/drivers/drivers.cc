#include "drivers.hh"

#include <Psapi.h>


BOOL drivers::blacklist( LPCSTR lpDriverName )
{
	LPVOID lpDriverImage[ 1024 ];
	DWORD cbNeeded;

	int driverCount, i;

	if ( EnumDeviceDrivers( lpDriverImage, sizeof( lpDriverImage ), &cbNeeded ) && cbNeeded < sizeof( lpDriverImage ) )
	{
		CHAR szDriver[ 1024 ];

		driverCount = cbNeeded / sizeof( lpDriverImage[ 0 ] );

		for ( i = 0; i < driverCount; i++ )
		{
			if ( GetDeviceDriverBaseNameA( lpDriverImage[ i ], szDriver, sizeof( szDriver ) / sizeof( szDriver[ 0 ] ) ) )
			{
				if ( strstr( szDriver, lpDriverName ) ) {

					return TRUE;
				}
			}
		}
	}

	return FALSE;
}