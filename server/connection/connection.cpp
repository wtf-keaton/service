#include "connection.h"
#include "../logger/logger.h"
#include "../hash/hash.h"
#include "../encryption/encryption.h"

namespace fusion::server
{
	SOCKET m_socket;
	WSADATA m_wsa_data;
	sockaddr_in client_info{};
	pe::c_image<true> binary_t;
#ifdef SSL_ENABLE
	WOLFSSL* m_ssl;
	WOLFSSL_CTX* ssl_ctx;

	void shutdown_ssl( )
	{
		SSL_shutdown( m_ssl );
		SSL_free( m_ssl );
	}
#endif

	bool setup_server( int port )
	{
#ifdef SSL_ENABLE
		wolfSSL_library_init( );

		ssl_ctx = wolfSSL_CTX_new( wolfTLS_server_method( ) );
#endif

#ifdef _WIN32
		if ( WSAStartup( MAKEWORD( 2, 1 ), &m_wsa_data ) != 0 )
		{
			fusion::logger::error( "failed to startup WSA with error: {}", GetLastError( ) );
			return false;
		}
		fusion::logger::debug( "winsock startup success" );
#endif
		m_socket = socket( AF_INET, SOCK_STREAM, NULL );
		if ( m_socket < 0 )
		{
			logger::error( "failed to init socket with error: {}", GetLastError( ) );
			return false;
		}
		fusion::logger::debug( "m_socket success inited" );

		sockaddr_in server_info{};
		server_info.sin_addr.s_addr = INADDR_ANY; // 127.0.0.1
		server_info.sin_family = AF_INET;
		server_info.sin_port = htons( port );

		::bind( m_socket, reinterpret_cast< SOCKADDR* >( &server_info ), sizeof server_info );

		::listen( m_socket, 0 );
		fusion::logger::info( "server success inited, waiting connections" );

		return true;
	}

	void listen( )
	{
		int client_len = sizeof client_info;

		auto m_client_socket = accept( m_socket, ( sockaddr* ) &client_info, &client_len );

#ifdef SSL_ENABLE
		auto cert = SSL_CTX_use_certificate_file( ssl_ctx, "D:\\for sell\\loader-service\\service\\service\\bin\\release\\cert.pem", SSL_FILETYPE_PEM );
		auto key = SSL_CTX_use_PrivateKey_file( ssl_ctx, "D:\\for sell\\loader-service\\service\\service\\bin\\release\\key.pem", SSL_FILETYPE_PEM );

		m_ssl = SSL_new( ssl_ctx );
		SSL_set_fd( m_ssl, m_client_socket );

		auto ssl_error = SSL_accept( m_ssl );
		if ( ssl_error < 0 )
		{
			shutdown_ssl( );
		}

		std::thread thread( handle_connections, m_ssl );
#else
		std::thread thread( handle_connections, m_client_socket );
#endif
		thread.detach( );
		std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
	}

#ifdef SSL_ENABLE
	void handle_connections( WOLFSSL* ssl )
#else
	void handle_connections( int ssl )
#endif
	{		
		if ( !ssl ) return;

		auto user_ip = inet_ntoa( client_info.sin_addr );

		fusion::logger::warn( "user \"{}\" connected", user_ip );

		request_t request;
		uintptr_t result = 0;

	start:
		if ( !fusion::server::recv( ssl, &request, sizeof( request ) ) ) return;

		fusion::logger::info( "[ {} ] user key -> {}", user_ip, request.key );
		fusion::logger::info( "[ {} ] user actual hwid -> 0x{:x}", user_ip, request.active_hwid_hash );

		switch ( request.request_type )
		{
			case e_request_type::_authorization:
				if ( strstr( request.key, "inject_key" ) )
				{
					if ( request.active_hwid_hash != HASH( "current_hwid" ) )
					{
						fusion::logger::error( "\"{}\" Hwid missmatch", user_ip );
						result = e_request_result::_error_hwid_missmatch;
						fusion::server::send( ssl, &result, sizeof( result ) );
					}
					else
					{
						fusion::logger::debug( "All okay" );

						result = e_request_result::_success;
						fusion::server::send( ssl, &result, sizeof( result ) );
					}
					goto start;
				}
				else
				{
					fusion::logger::error( "Key invalid" );
					result = e_request_result::_error_userkey;
					fusion::server::send( ssl, &result, sizeof( result ) );
				}


				wolfSSL_free( ssl );
				break;

			case e_request_type::_get_binary:

				fusion::logger::debug( "user \"{}\" requested binary", user_ip );

				switch ( request.binary_type )
				{
					case e_binary_type::_driver:
					{
						fusion::pe::c_image<true> binary;
						if ( !binary.initialize( "D:\\for sell\\loader-service\\service\\service\\bin\\release\\test.sys" ) )
						{
							goto start;
						}
						binary_request_t binary_request{};
						binary_request.size = binary.image( )->get_nt_headers( )->optional_header.size_image;
						binary_request.entry = binary.image( )->get_nt_headers( )->optional_header.entry_point;
						strcpy_s( binary_request.imports, binary.get_imports( ).c_str( ) );

						fusion::server::send( ssl, &binary_request, sizeof( binary_request ) );


						uint64_t allocated_base = 0;
						fusion::server::recv( ssl, &allocated_base, sizeof allocated_base );

						fusion::logger::debug( "user \"{}\" allocated memory: 0x{:x}\n", user_ip, allocated_base );

						if ( allocated_base )
						{
							std::string imports;
							fusion::server::recv( ssl, imports );

							std::vector<char> data;
							binary.get_binary( data );
							binary.relocate( data, allocated_base );
							binary.fix_imports( data, imports );

							if ( fusion::server::send( ssl, data ) == data.size( ) )
							{
								fusion::logger::info( "Image success sended to user \"{}\"", user_ip );
							}
						}
						goto start;
						break;
					}
					case e_binary_type::_cheat:
					{
						fusion::pe::c_image<true> binary;
						if ( !binary.initialize( "test.dll" ) )
						{
							goto start;
						}
						binary_request_t binary_request{};
						binary_request.size = binary.image( )->get_nt_headers( )->optional_header.size_image;
						binary_request.entry = binary.image( )->get_nt_headers( )->optional_header.entry_point;

						strcpy_s( binary_request.imports, binary.get_imports( ).c_str( ) );

						fusion::server::send( ssl, &binary_request, sizeof( binary_request ) );


						uint64_t allocated_base = 0;
						fusion::server::recv( ssl, &allocated_base, sizeof allocated_base );

						fusion::logger::warn( "user \"{}\" allocated memory: 0x{:x}\n", user_ip, allocated_base );

						if ( allocated_base )
						{
							std::string imports;
							fusion::server::recv( ssl, imports );

							std::vector<char> data{};
							binary.get_binary( data );
							binary.relocate( data, allocated_base );
							binary.fix_imports( data, imports );

							if ( fusion::server::send( ssl, data ) == data.size( ) )
							{
								fusion::logger::info( "Image success sended to user \"{}\"", user_ip );
							}
						}

 
						goto start;
						break;
					}
				}

				break;

			case e_request_type::_ban_user:
			{
				fusion::logger::info( "user \"{}\" banned hwid {:x}", user_ip, request.active_hwid_hash );
				break;
			}
		}
	}

#ifdef SSL_ENABLE
	bool send( WOLFSSL* con_socket, void* buf, size_t size )
	{
		//void* tmp = nullptr;
		//fusion::encrypt::crypt( buf, &tmp, size );
		bool ret = wolfSSL_send( con_socket, buf, size, 0 ) > 0;
		//free( tmp );

		return ret;
	}

	bool recv( WOLFSSL* con_socket, void* buf, size_t size )
	{
		//void* tmp = malloc( size * 2 );
		bool ret = wolfSSL_recv( con_socket, buf, size, MSG_WAITALL ) > 0;
		//fusion::encrypt::decrypt( tmp, &buf, size * 2 );
		//free( tmp );

		return ret;
	}

#else
	bool send( int con_socket, void* buf, size_t size )
	{
		return ::send( con_socket, reinterpret_cast< const char* > ( buf ), size, 0 ) > 0;
	}

	bool recv( int con_socket, void* buf, size_t size )
	{
		return ::recv( con_socket, reinterpret_cast< char* >( buf ), size, MSG_WAITALL ) > 0;
	}
#endif

#ifdef SSL_ENABLE
	int send( WOLFSSL* ssl, std::vector<char>& data, float* dur /*= nullptr*/ )
#else
	int send( int ssl, std::vector<char>& data, float* dur /*= nullptr*/ )
#endif
	{
		auto size = data.size( );

		auto networked_size = htonl( size );
		send( ssl, &networked_size, sizeof( networked_size ) );

		// with 4kb chunk size, speed peaks at 90mb/s without enc
		// speed is at ~75mb/s with xor
		constexpr size_t chunk_size = 4096;
		size_t sent = 0;

		auto start = std::chrono::steady_clock::now( );
		while ( size > 0 )
		{
			auto to_send = std::min( size, chunk_size );

			int ret = send( ssl, &data[ sent ], to_send );
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

#ifdef SSL_ENABLE
	int recv( WOLFSSL* ssl, std::vector<char>& out )
#else
	int recv( int ssl, std::vector<char>& out )
#endif
	{
		size_t size;
		recv( ssl, &size, sizeof( size ) );

		size = ntohl( size );
		out.resize( size );

		constexpr size_t chunk_size = 4096;
		size_t total = 0;

		while ( size > 0 )
		{
			auto to_read = std::min( size, chunk_size );

			int ret = recv( ssl, &out[ total ], to_read );
			if ( ret <= 0 )
			{
				break;
			}

			size -= ret;
			total += ret;
		}

		return total;
	}

#ifdef SSL_ENABLE
	int recv( WOLFSSL* ssl, std::string& str )
#else
	int recv( int ssl, std::string& str )
#endif
	{
		std::vector<char> out;
		int ret = recv( ssl, out );
		str.assign( out.begin( ), out.end( ) );
		return ret;
	}
#ifdef SSL_ENABLE
	bool send( WOLFSSL* ssl, std::string data )
#else
	bool send( int ssl, std::string data )
#endif
	{
		std::vector<char> vec( data.begin( ), data.end( ) );
		return send( ssl, vec );
	}
}