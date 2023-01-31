#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include "../syscall/syscall.h"

enum e_request_method
{
	_read = 0x854,
	_write = 0x747,
	_alloc = 0x2048,
	_free = 0x1488,
	_base = 0x342,
	_thread = 0x2874,
	_init = 0x8324,
	_unload = 0x8361

};

struct driver_request_t
{
	e_request_method request_method;
};

struct read_memory_t
{
	HANDLE process_id;
	void* address;
	void* buffer;
	size_t size;
};

struct write_memory_t
{
	HANDLE process_id;
	void* address;
	void* buffer;
	size_t size;
};

struct base_request_t
{
	int process_id;
	const char* module_name;
	uintptr_t address;
};

inline NTSTATUS( *NtCompareSigningLevels )( PVOID, PVOID ) = nullptr;

#define send_cmd( ... ) NtCompareSigningLevels( __VA_ARGS__ )
#pragma optimize( "", off )
namespace fusion::driver
{

	__forceinline bool init_driver( )
	{
		auto win32u = LoadLibraryA( "ntdll.dll" );
		if ( !win32u )
		{
			printf_s( "failed to load ntdll.dll\n" );
			return false;
		}

		auto address = GetProcAddress( win32u, "NtCompareSigningLevels" );
		if ( !address )
		{
			printf_s( "failed to get NtCompareSigningLevels\n" );
			return false;
		}

		*( void** )&NtCompareSigningLevels = address;
		return true;
	}

	__forceinline uintptr_t read_memory( uintptr_t address )
	{
		read_memory_t read_memory{};

		uintptr_t read_data{};

		read_memory.process_id = (HANDLE)GetCurrentProcessId( );
		read_memory.address = reinterpret_cast< void* >( address );
		read_memory.buffer = reinterpret_cast< void* >( &read_data );
		read_memory.size = sizeof( uintptr_t );

		driver_request_t request{};
		request.request_method = e_request_method::_read;

		send_cmd( &request, &read_memory );

		return read_data;
	}

	template<typename _ty> _ty get_module_address( const char* module )
	{
		base_request_t base_request{};

		base_request.module_name = module;
		base_request.process_id = GetCurrentProcessId( );
		base_request.address = 0x0;

		driver_request_t request{};
		request.request_method = e_request_method::_base;

		send_cmd( &request, &base_request );

		return reinterpret_cast< _ty >( base_request.address );
	}

	__forceinline uintptr_t alloc( size_t size )
	{

	}

	__forceinline bool free( uintptr_t address )
	{

	}

	__forceinline void unload( )
	{
		driver_request_t request;
		request.request_method = e_request_method::_unload;

		send_cmd( &request, 0 );

	}
}
#pragma optimize( "", on )