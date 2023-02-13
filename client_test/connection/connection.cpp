#include "connection.h"
#include "ca.h"

#include "../encryption/encryption.h"
#include "test.h"

namespace fusion::client
{
	SOCKET m_socket;
	WSADATA m_wsa_data;

#ifdef SSL_ENABLE
	WOLFSSL* m_ssl;
	WOLFSSL_CTX* m_ssl_ctx;
#endif

	bool connect( int port )
	{
#ifdef SSL_ENABLE

		wolfSSL_library_init( );

		m_ssl_ctx = wolfSSL_CTX_new( wolfTLS_client_method( ) );

		auto ret = wolfSSL_CTX_load_verify_buffer( m_ssl_ctx, cert_data, sizeof( cert_data ), SSL_FILETYPE_PEM );
		if ( ret != 1 )
		{
			printf_s( _( "[ - ] failed to load certificate\n" ) );
			return false;
		}
		wolfSSL_CTX_set_verify( m_ssl_ctx, SSL_VERIFY_PEER, 0 );
#endif

		if ( WSAStartup( MAKEWORD( 2, 1 ), &m_wsa_data ) )
		{
			return false;
		}

		m_socket = socket( AF_INET, SOCK_STREAM, 0 );

		if ( m_socket < 0 )
		{
			printf_s( _( "[ - ] failed to setup m_socket\n" ) );
			return false;
		}

		sockaddr_in server_info;
		memset( &server_info, 0, sizeof server_info );

		server_info.sin_family = AF_INET;
		server_info.sin_port = htons( port );

		if ( inet_pton( AF_INET, _( "127.0.0.1" ), &server_info.sin_addr ) <= 0 )
		{
			return false;
		}

		if ( connect( m_socket, reinterpret_cast< const sockaddr* >( &server_info ), sizeof server_info ) != 0 )
		{
			return false;
		}
#ifdef SSL_ENABLE

		m_ssl = wolfSSL_new( m_ssl_ctx );
		wolfSSL_set_fd( m_ssl, m_socket );

		if ( !wolfSSL_connect( m_ssl ) )
		{
			printf_s( _( "[ - ] ssl connection error: %d\n" ), wolfSSL_get_error( m_ssl, ret ) );
			return false;
		}
#endif
		return true;
	}
#ifdef SSL_ENABLE

	bool send( void* buf, size_t size )
	{
		//void* tmp = nullptr;
		//fusion::encrypt::crypt( buf, &tmp, size );
		bool ret = wolfSSL_send( m_ssl, buf, size, 0 ) > 0;
		//free( tmp );

		return ret;
	}

	bool recv( void* buf, size_t size )
	{
		//void* tmp = malloc( size * 2 );
		bool ret = wolfSSL_recv( m_ssl, buf, size, MSG_WAITALL ) > 0;
		//fusion::encrypt::decrypt( tmp, &buf, size * 2 );
		//free( tmp );

		return ret;
	}

#else
	bool send( void* buf, size_t size )
	{
		return ::send( m_socket, reinterpret_cast< const char* >( buf ), size, 0 ) > 0;
	}

	bool recv( void* buf, size_t size )
	{
		return ::recv( m_socket, reinterpret_cast< char* >( buf ), size, MSG_WAITALL ) > 0;
	}
#endif

	int stream( std::vector<char>& data, float* dur /*= nullptr*/ )
	{
		auto size = data.size( );

		auto networked_size = htonl( size );
		send( &networked_size, sizeof( networked_size ) );

		// with 4kb chunk size, speed peaks at 90mb/s without enc
		// speed is at ~75mb/s with xor
		constexpr size_t chunk_size = 4096;
		size_t sent = 0;

		auto start = std::chrono::steady_clock::now( );
		while ( size > 0 )
		{
			auto to_send = std::min( size, chunk_size );

			int ret = send( &data[ sent ], to_send );
			if ( ret <= 0 )
			{
				break;
			}
			sent += ret;
			size -= ret;
		}

		auto end = std::chrono::steady_clock::now( );
		std::chrono::duration<float> time = end - start;
		if ( dur ) *dur = time.count( );

		return sent;
	}

	int read_stream( std::vector<char>& out, size_t full_size )
	{
		size_t size;
		recv( &size, sizeof( size ) );

		size = ntohl( size );
		out.resize( size );

		constexpr size_t chunk_size = 4096;
		size_t total = 0;
		float progress = 0.f;
		int current_pos = 0;
		while ( size > 0 )
		{
			auto to_read = std::min( size, chunk_size );

			int ret = recv( &out[ total ], to_read );
			if ( ret <= 0 )
			{
				break;
			}

			size -= ret;
			total += ret;

			printf_s( "\rdownloaded bytes: %d%% / 100%% ( %d / %d )", 100 * total / full_size, total, full_size );
 		}
		return total;
	}


	bool send( std::string data )
	{
		std::vector<char> vec( data.begin( ), data.end( ) );
		return stream( vec );
	}

}