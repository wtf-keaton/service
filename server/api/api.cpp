#include "api.h"

#include "../helpers/structs.h"

namespace fusion::api
{
	uint64_t auth( const char* key, const char* hwid )
	{
		httplib::Client client( "http://127.0.0.1:4090" );

		char buf[ 256 ];
		sprintf_s( buf, "key=%s&hwid=%s", key, hwid );
		if ( auto res = client.Post( "/api/server/auth", buf, "application/x-www-form-urlencoded" ) )
		{
			auto parse = nlohmann::json::parse( res->body );

			auto result = parse[ "Status" ].get<std::string>( );

			if ( result == "success" )
			{
				return e_request_result::_success;
			}
			else if ( result == "cheat_freezed" )
			{
				return e_request_result::_error_freezed;
			}
			else if ( result == "wrong_hwid" )
			{
				return e_request_result::_error_hwid_missmatch;
			}	
			else if ( result == "invalid_key" )
			{
				return e_request_result::_error_userkey;
			}
			else if ( result == "expired" )
			{
				return e_request_result::_error_subscribe_end;
			}
			else if ( result == "banned" )
			{
				return e_request_result::_error_banned;
			}
		}

		return e_request_result::_error_userkey;
	}

	std::string get_info( const char* key )
	{
		httplib::Client client( "http://127.0.0.1:4090" );

		char buf[ 256 ];
		sprintf_s( buf, "key=%s", key );
		if ( auto res = client.Post( "/api/server/get_info", buf, "application/x-www-form-urlencoded" ) )
		{
			return res->body;
		}
	}

	std::string get_path( const char* key )
	{
		httplib::Client client( "http://127.0.0.1:4090" );

		char buf[ 256 ];
		sprintf_s( buf, "key=%s", key );
		if ( auto res = client.Post( "/api/server/get_path", buf, "application/x-www-form-urlencoded" ) )
		{
			auto parse = nlohmann::json::parse( res->body );

			auto result = parse[ "Status" ].get<std::string>( );

			return result;
		}
	}
}