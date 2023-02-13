#include <Windows.h>
#include <wincrypt.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <intrin.h>


namespace hwid
{
	extern std::string GetCpuid( );
	extern std::string GetCompUserName( bool User );
	extern std::string StringToHex( const std::string input );
	extern std::string GetSerialKey( );
	extern std::string GetHashText( const void* data, const size_t data_size );
	extern std::string GetHashSerialKey( );
	extern std::string GetHashCpuid( );
	extern std::string get_key( );
}