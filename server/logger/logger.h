#pragma once
#include <Windows.h>
#include <cstdio>
#include <format>

enum color_t
{
	black = 0,
	dark_blue,
	dark_green,
	light_blue,
	dark_red,
	magenta,
	orange,
	light_gray,
	gray,
	blue,
	green,
	cyan,
	red,
	pink,
	yellow,
	white
};


namespace fusion::logger
{
	inline HANDLE consoleHandle = GetStdHandle( STD_OUTPUT_HANDLE );

	__forceinline void reset( )
	{
		SetConsoleTextAttribute( consoleHandle, color_t::light_gray );
	}

	__forceinline void write( const char* format, ... )
	{
		va_list _ArgList;
		__crt_va_start( _ArgList, format );
		_vfprintf_l( __acrt_iob_func( 1 ), format, nullptr, _ArgList );
		__crt_va_end( _ArgList );
	}

	template< typename ...Args >
	std::string format( std::string_view test, Args... args )
	{
		return std::vformat( test, std::make_format_args( args... ) );
	}

	template< typename ...Args >
	void print( const char* prefix, const char* fmt, color_t color, Args... args )
	{
		SetConsoleTextAttribute( consoleHandle, color );
		write( prefix );
		SetConsoleTextAttribute( consoleHandle, color_t::white );
		write( fmt, args... );
		write( "\n" );
		reset( );
	}

	template< typename ...Args >
	void warn( const char* fmt, Args... args )
	{
		print( "warning >> ", fusion::logger::format( fmt, args... ).c_str( ), color_t::orange );
	}

	template< typename ...Args >
	void error( const char* fmt, Args... args )
	{
		print( "error >> ", fusion::logger::format( fmt, args... ).c_str( ), color_t::red );
	}	
	
	template< typename ...Args >
	void info( const char* fmt, Args... args )
	{
		print( "info >> ", fusion::logger::format( fmt, args... ).c_str( ), color_t::dark_green );
	}

	template< typename ...Args >
	void debug( const char* fmt, Args... args )
	{
#ifdef DEBUG_OUTPUT
		print( "debug >> ", fusion::logger::format( fmt, args... ).c_str( ), color_t::gray );
#endif
	}
}

