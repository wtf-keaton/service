#pragma once

namespace fusion::string
{
	__forceinline int tolower( int c )
	{
		if ( c >= 'A' && c <= 'Z' ) return c - 'A' + 'a';
		return c;
	}
	__forceinline int stricmp( const char* cs, const char* ct )
	{
		if ( cs && ct )
		{
			while ( tolower( *cs ) == tolower( *ct ) )
			{
				if ( *cs == 0 && *ct == 0 ) return 0;
				if ( *cs == 0 || *ct == 0 ) break;
				cs++;
				ct++;
			}
			return tolower( *cs ) - tolower( *ct );
		}
		return -1;
	}

}