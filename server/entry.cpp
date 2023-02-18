#include "connection/connection.h"
#include "encryption/encryption.h"

int main( )
{
#ifdef SSL_ENABLE
	fusion::logger::warn( "starting tls server" );
#else
	fusion::logger::warn( "starting tcp server" );
#endif
	
	if ( !fusion::server::setup_server( 1488 ) )
	{
		fusion::logger::error( "failed to start server with error: {}", GetLastError( ) );
		system( "pause" );

		return 0;
	}

	while ( true )
	{
		try
		{
			fusion::server::listen( );
		}
		catch ( ... )
		{
			fusion::logger::error( "server get exception" );
		}
	}
	return 0;
}