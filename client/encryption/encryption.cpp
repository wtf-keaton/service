#include "encryption.h"


namespace fusion::encrypt
{
	void crypt( void* buf, void** crypted, size_t size )
	{
		*crypted = malloc( size * 2 );

		if ( !*crypted )
			return;

		for ( int i = 0; i < size / 4; ++i )
			*( ( uint64_t* ) ( *crypted ) + i ) = ~_byteswap_uint64( _rotl64( *( ( uint32_t* ) buf + i ), 7 ) );
	}

	void decrypt( void* buf, void** decrypted, size_t size )
	{
		if ( !*decrypted )
			return;

		for ( int i = 0; i < size / 8; ++i )
			*( ( uint32_t* ) ( *decrypted ) + i ) = ( uint32_t ) ( _rotr64( _byteswap_uint64( ~*( ( uint64_t* ) ( buf ) +i ) ), 7 ) );
	}
}