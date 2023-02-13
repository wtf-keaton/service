#pragma once
#include <Windows.h>
#include <thread>

#ifdef _WIN32
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#ifdef SSL_ENABLE
#include <wolfssl/IDE/WIN/user_settings.h>
#include <wolfssl/ssl.h>
#endif

#include "../pe/pe.h"

#include "../helpers/structs.h"

namespace fusion::server
{
	bool setup_server( int );

	void listen( );
#ifdef SSL_ENABLE
	void handle_connections( WOLFSSL* ssl );
#else
	void handle_connections( int ssl );
#endif

#ifdef SSL_ENABLE
	bool send( WOLFSSL* con_socket, void* buf, size_t size );

	bool recv( WOLFSSL* con_socket, void* buf, size_t size );

	int send( WOLFSSL* ssl, std::vector<char>& data, float* dur = nullptr );

	int recv( WOLFSSL* ssl, std::vector<char>& out );

	int recv( WOLFSSL* ssl, std::string& str );

	bool send( WOLFSSL* ssl, std::string data );

#else
	bool send( int con_socket, void* buf, size_t size );

	bool recv( int con_socket, void* buf, size_t size );

	int stream( int con_socket, std::vector<char>& data, float* dur = nullptr );

	int read_stream( int con_socket, std::vector<char>& out );

	int read_stream( int con_socket, std::string& str );

	bool send( int con_socket, std::string data );
#endif
}