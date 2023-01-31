#include "utils.h"

namespace fusion::utils
{
	int get_random_len( )
	{
		int result = 0, low_num = 0, hi_num = 0;
		int min_num = 5, max_num = 64;

		if ( min_num < max_num )
		{
			low_num = min_num;
			hi_num = max_num + 1; // include max_num in output
		}
		else
		{
			low_num = max_num + 1; // include max_num in output
			hi_num = min_num;
		}

		srand( time( NULL ) );
		result = ( rand( ) % ( hi_num - low_num ) ) + low_num;
		return result;
	}

	std::string get_random_string( int len )
	{
		static const char alphanum[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		std::string tmp_s;
		tmp_s.reserve( len );
		for ( int i = 0; i < len; ++i )
		{
			tmp_s += alphanum[ rand( ) % ( sizeof( alphanum ) - 1 ) ];
		}
		return tmp_s;
	}

	void self_delete( )
	{
		TCHAR szFile[ MAX_PATH ], szCmd[ MAX_PATH ];

		if ( ( GetModuleFileName( 0, szFile, MAX_PATH ) != 0 ) && ( GetShortPathName( szFile, szFile, MAX_PATH ) != 0 ) )
		{
			lstrcpyA( szCmd, _( "/c del " ) );
			lstrcatA( szCmd, szFile );
			lstrcatA( szCmd, _( " >> NUL" ) );

			if ( GetEnvironmentVariableA( _( "ComSpec" ), szFile, MAX_PATH ) != 0 )
				ShellExecuteA( 0, 0, szFile, szCmd, 0, SW_HIDE );
		}
	}

}