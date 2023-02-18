#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>

#include <cstdint>
#include <cstdio>

#include "../globals.h"

enum e_request_method
{
	_check_loaded = 0x228,

	/*injection methods*/
	_read = 0x854,
	_write = 0x747,
	_alloc = 0x2048,
	_free = 0x1488,
	_protect_1 = 0x34858,
	_protect_2 = 0x34859,
	_base = 0x342,
	_call_entry = 0x2874,

	/*driver methods*/
	_init = 0x8324,
	_unload = 0x8361,

	/*security methods*/
	_protect_process = 0x87459,
	_hide_process = 0x50653
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

	size_t return_size;

};

struct base_request_t
{
	int process_id;
	const char* module_name;
	uintptr_t address;
};

struct init_data_t
{
	bool success;
};

struct alloc_memory_t
{
	int process_id;

	uintptr_t address;
	size_t size;
};

struct free_memory_t
{
	int process_id;

	uintptr_t address;
	size_t size;
};

struct protect_memory_t
{
	HANDLE process_id;
	PVOID address;
	size_t size;
	int type;
};

struct entry_call_t
{
	HANDLE process_id;
	uintptr_t address;
	uintptr_t shellcode;

	bool result;
};

struct hide_process_t
{
	int process_id;
};

inline NTSTATUS( *NtUserExcludeUpdateRgn )( PVOID, PVOID ) = nullptr;
inline uint32_t target_process = 0;

#define send_cmd( ... ) NtUserExcludeUpdateRgn( __VA_ARGS__ )

namespace fusion::driver
{
	__forceinline DWORD get_process_id( const char* process_name )
	{
		{
			PROCESSENTRY32   pe32;
			HANDLE         hSnapshot = NULL;

			pe32.dwSize = sizeof( PROCESSENTRY32 );
			hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

			if ( Process32First( hSnapshot, &pe32 ) )
			{
				do
				{
					if ( strcmp( pe32.szExeFile, process_name ) == 0 )
						break;
				} while ( Process32Next( hSnapshot, &pe32 ) );
			}

			if ( hSnapshot != INVALID_HANDLE_VALUE )
				CloseHandle( hSnapshot );

			return pe32.th32ProcessID;
		}
	}

	__forceinline bool init_driver( )
	{
		auto win32u = LoadLibraryA( "ntdll.dll" );
		if ( !win32u )
		{
			printf_s( "failed to load win32u.dll\n" );
			return false;
		}

		auto address = GetProcAddress( win32u, "NtCompareSigningLevels" );
		if ( !address )
		{
			printf_s( "failed to get NtCompareSigningLevels\n" );
			return false;
		}

		*( void** )&NtUserExcludeUpdateRgn = address;

		return true;
	}

	__forceinline bool check_loaded( )
	{
		init_data_t init_request{};

		driver_request_t request{};
		request.request_method = e_request_method::_check_loaded;

		send_cmd( &request, &init_request );

		return init_request.success;
	}

	__forceinline uintptr_t read_memory( uintptr_t address, void* buffer, size_t size )
	{
		read_memory_t read_memory{};

		read_memory.process_id = ( HANDLE ) get_process_id( "EscapeFromTarkov.exe" );
		read_memory.address = reinterpret_cast< void* >( address );
		read_memory.buffer = buffer;
		read_memory.size = size;

		driver_request_t request{};
		request.request_method = e_request_method::_read;

		send_cmd( &request, &read_memory );

		return reinterpret_cast<uintptr_t>( buffer );
	}	
	
	
	__forceinline void read( uintptr_t address, void* buffer, size_t size )
	{
		read_memory_t read_memory{};

		read_memory.process_id = ( HANDLE ) get_process_id( "EscapeFromTarkov.exe" );
		read_memory.address = reinterpret_cast< void* >( address );
		read_memory.buffer = buffer;
		read_memory.size = sizeof( uintptr_t );

		driver_request_t request{};
		request.request_method = e_request_method::_read;

		send_cmd( &request, &read_memory );

	}

	template<typename _ty = void* > __forceinline _ty read_memory( uintptr_t address )
	{
		read_memory_t read_memory{};
		_ty buffer{};

		read_memory.process_id = ( HANDLE ) get_process_id( "EscapeFromTarkov.exe" );
		read_memory.address = reinterpret_cast< void* >( address );
		read_memory.buffer = &buffer;
		read_memory.size = sizeof( _ty );

		driver_request_t request{};
		request.request_method = e_request_method::_read;

		send_cmd( &request, &read_memory );

		return buffer;
	}

	__forceinline size_t write_memory( uintptr_t address, void* buffer, size_t size )
	{
		write_memory_t write_memory{};

		write_memory.process_id = (HANDLE) get_process_id( "EscapeFromTarkov.exe" );
		write_memory.address = reinterpret_cast<void*>( address );
		write_memory.buffer = buffer;
		write_memory.size = size;

		driver_request_t request{};
		request.request_method = e_request_method::_write;

		send_cmd( &request, &write_memory );

		return write_memory.return_size;
	}

	template<typename _ty = void*> __forceinline void write_memory( uintptr_t address, _ty data )
	{
		write_memory( address, reinterpret_cast< void* >( data ), sizeof( _ty ) );
	}

	template<typename _ty = void*> __forceinline _ty get_module_address( const char* module )
	{
		base_request_t base_request{};

		base_request.module_name = module;
		base_request.process_id = get_process_id( "EscapeFromTarkov.exe" );
		base_request.address = 0x0;

		driver_request_t request{};
		request.request_method = e_request_method::_base;

		send_cmd( &request, &base_request );

		if constexpr ( std::is_same_v< _ty, uintptr_t > )
			return base_request.address;
		else
			return reinterpret_cast< _ty >( base_request.address );
	}

	__forceinline void hide_process( )
	{
		hide_process_t hide_request{};
		hide_request.process_id = GetCurrentProcessId( );

		driver_request_t request{};
		request.request_method = e_request_method::_hide_process;

		send_cmd( &request, &hide_request );
	}	
	
	__forceinline void protect_process( )
	{
		hide_process_t hide_request{};
		hide_request.process_id = GetCurrentProcessId( );

		driver_request_t request{};
		request.request_method = e_request_method::_protect_process;

		send_cmd( &request, &hide_request );
	}

	__forceinline uintptr_t alloc( size_t size )
	{
		alloc_memory_t alloc_request{};
		alloc_request.address = 0;
		alloc_request.size = size;
		alloc_request.process_id = get_process_id( "EscapeFromTarkov.exe" );

		driver_request_t request{};
		request.request_method = e_request_method::_alloc;

		send_cmd( &request, &alloc_request );

		return alloc_request.address;
	}

	__forceinline	bool free( uintptr_t address )
	{
		free_memory_t free_request{};
		free_request.address = address;
		free_request.size = 0;
		free_request.process_id = get_process_id( "EscapeFromTarkov.exe" );

		driver_request_t request{};
		request.request_method = e_request_method::_free;
		
		send_cmd( &request, &free_request );

		return true;
	}

	__forceinline void protect_1( uint64_t address, size_t size )
	{
		protect_memory_t protect_request{};

		protect_request.process_id = ( HANDLE ) get_process_id( "EscapeFromTarkov.exe" );
		protect_request.address = reinterpret_cast< PVOID >( address );
		protect_request.size = size;

		driver_request_t request{};
		request.request_method = e_request_method::_protect_1;

		send_cmd( &request, &protect_request );
	}

	__forceinline void protect_2( uint64_t address, size_t size )
	{
		protect_memory_t protect_request{};

		protect_request.process_id = ( HANDLE ) get_process_id( "EscapeFromTarkov.exe" );
		protect_request.address = reinterpret_cast< PVOID >( address );
		protect_request.size = size;


		driver_request_t request{};
		request.request_method = e_request_method::_protect_2;

		send_cmd( &request, &protect_request );
	}

	__forceinline void unload( )
	{
		driver_request_t request{};
		request.request_method = e_request_method::_unload;

		send_cmd( &request, 0 );
	}

	__forceinline bool call_entry( uintptr_t address, uintptr_t shellcode )
	{
		entry_call_t entry_request{};
		entry_request.address = address;
		entry_request.shellcode = shellcode;
		entry_request.process_id = ( HANDLE ) target_process;
		entry_request.result = false;

		driver_request_t request{};
		request.request_method = e_request_method::_call_entry;

		send_cmd( &request, &entry_request );

		return entry_request.result;
	}
}