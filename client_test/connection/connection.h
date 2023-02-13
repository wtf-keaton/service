#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <chrono>

#include <WinSock2.h>
#include <ws2tcpip.h>

#include <wolfssl/IDE/WIN/user_settings.h>
#include <wolfssl/ssl.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#include "../xorstr/xorstr.h"

namespace fusion::client
{
	bool connect( int port );

	bool send( void* buf, size_t size );

	int stream( std::vector<char>& data, float* dur = nullptr );
	int read_stream( std::vector<char>& out, size_t full_size = 0 );

	bool send( std::string data );

	bool recv( void* buf, size_t size );
}