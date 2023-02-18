#pragma once
#include <Windows.h>
#include <string>
#include <ctime>

#include <TlHelp32.h>
#include <shellapi.h>

#include "../xorstr/xorstr.h"

namespace fusion::utils
{
	int get_random_len( );

	std::string get_random_string( int len );

	void self_delete( );

	uint64_t generate_mapper_token( );

}