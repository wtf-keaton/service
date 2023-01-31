#pragma once
#include <vector>
#include <string>

#include <fstream>

namespace fusion::file
{
	__forceinline bool read_file( const std::string name, std::vector<char>& out )
	{
		std::ifstream file( name.data( ), std::ios::binary );

		if ( !file.good( ) )
		{
			return false;
		}

		file.unsetf( std::ios::skipws );

		file.seekg( 0, std::ios::end );
		const size_t size = file.tellg( );
		file.seekg( 0, std::ios::beg );

		out.resize( size );

		file.read( out.data( ), size );

		file.close( );

		return true;
	}

	__forceinline bool read_file( const std::string name, std::string& out )
	{
		std::vector<char> vec;
		if ( !read_file( name, vec ) ) return false;

		out.assign( vec.begin( ), vec.end( ) );
		return true;
	}
}