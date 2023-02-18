#pragma once
#include "../httplib/httplib.h"
#include "../json/json.h"

namespace fusion::api
{
	uint64_t auth( const char* key, const char* hwid );
	std::string get_info( const char* key );
	std::string get_path( const char* key );
}