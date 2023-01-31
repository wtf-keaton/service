#pragma once
#include <Windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>

#include "../hash/hash.h"
#include "../xorstr/xorstr.h"

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI LdrGetDllHandle( PWORD path, PVOID, PUNICODE_STRING module_file_name, PHANDLE out_base );
extern "C" NTSTATUS NTAPI RtlAdjustPrivilege( ULONG privilege, BOOLEAN enable, BOOLEAN  current_thread, PBOOLEAN was_enabled );
extern "C" NTSTATUS NTAPI NtLoadDriver( UNICODE_STRING * reg_path );
extern "C" NTSTATUS NTAPI NtUnloadDriver( UNICODE_STRING * reg_path );
extern "C" NTSTATUS NTAPI NtDelayExecution( BOOLEAN alert, LARGE_INTEGER * interval );
extern "C" NTSTATUS NTAPI NtShutdownSystem( int );

extern "C" void do_syscall( );

namespace fusion::syscall
{
	extern uint64_t get_proc_address( uint64_t mod_base, uint64_t function_hash );
	extern uint64_t get_module_base( const wchar_t* module_name );

	template< typename _ty, typename... args >
	static inline auto call_helper( const void* fn, args... a )
	{
		return reinterpret_cast< _ty( * )( args... ) >( fn )( a... );
	}

	template< size_t args_count, typename >
	struct arg_remap
	{
		template< typename _ty, typename a1, typename a2, typename a3, typename a4, typename... o >
		static auto call( const void* fn, void* param, a1 first, a2 second, a3 third, a4 fourth, o... others ) -> _ty
		{
			return call_helper< _ty, a1, a2, a3, a4, void*, void*, o... >( fn, first, second, third, fourth, param, nullptr, others... );
		}
	};

	template< size_t args_count >
	struct arg_remap< args_count, std::enable_if_t< args_count <= 4 > >
	{
		template< typename _ty, typename a1 = void*, typename a2 = void*, typename a3 = void*, typename a4 = void* >
		static auto call( const void* fn, void* param, a1 first = a1{ }, a2 second = a2{ }, a3 third = a3{ }, a4 fourth = a4{ } ) -> _ty
		{
			return call_helper< _ty, a1, a2, a3, a4, void*, void* >( fn, first, second, third, fourth, param, nullptr );
		}
	};

	template< typename _ty, typename ...args >
	_ty sys_call( uint64_t function_hash, args... arguments )
	{
		uint64_t function = get_proc_address( get_module_base( _( L"ntdll.dll" ) ), function_hash );
		uint32_t index = *reinterpret_cast< uint32_t* >( function + 4 );
		using mapper = arg_remap<sizeof...( args ), void>;
		return mapper::template call< _ty, args... >( reinterpret_cast< const void* >( &do_syscall ), &index, arguments... );
	}

	__forceinline void sleep( uint32_t ms )
	{
		LARGE_INTEGER interval;
		interval.QuadPart = -10000 * static_cast< int64_t >( ms );
		sys_call< NTSTATUS, BOOLEAN, LARGE_INTEGER* >( HASH( "NtDelayExecution" ), FALSE, &interval );
	}

	__forceinline bool device_io_control( HANDLE device, uint32_t code, void* in_buffer, uint32_t in_buf_size, void* out_buffer, uint32_t out_buf_size, uint32_t* bytes_returned )
	{
		_IO_STATUS_BLOCK status_block;
		__stosb( reinterpret_cast< PBYTE >( &status_block ), 0, sizeof( _IO_STATUS_BLOCK ) );
		NTSTATUS status = sys_call< NTSTATUS, HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG >(
			HASH( "NtDeviceIoControlFile" ), device, nullptr, nullptr, nullptr, &status_block, code, in_buffer, in_buf_size, out_buffer, out_buf_size );

		if ( !NT_SUCCESS( status ) )
			return false;

		if ( status == 0x103 )
			if ( !NT_SUCCESS( ( sys_call< NTSTATUS, HANDLE, BOOLEAN, LARGE_INTEGER* >( HASH( "NtWaitForSingleObject" ), device, FALSE, nullptr ) ) ) )
				return false;

		if ( bytes_returned )
			*bytes_returned = status_block.Information;

		return true;
	}

	__forceinline void* alloc( size_t size )
	{
		void* allocated = nullptr;

		auto status = sys_call<NTSTATUS, HANDLE, void*, ULONG_PTR, PSIZE_T, ULONG, ULONG >( HASH( "NtAllocateVirtualMemory" ), reinterpret_cast< HANDLE >( -1 ), &allocated, 0ull, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

		if ( !NT_SUCCESS( status ) )
		{
			return 0;
		}

		return allocated;
	}


	__forceinline bool free( void* address )
	{
		size_t size = 0;
		auto status = sys_call<NTSTATUS, HANDLE, void*, PSIZE_T, ULONG>( HASH( "NtFreeVirtualMemory" ), reinterpret_cast< HANDLE >( -1 ), address, &size, MEM_RELEASE );

		if ( !NT_SUCCESS( status ) )
			return false;

		return true;
	}

	__forceinline int reboot_pc( )
	{
		HANDLE            hToken;
		LUID              takeOwnershipValue;
		TOKEN_PRIVILEGES  tkp;
		if ( !OpenProcessToken( GetCurrentProcess( ),
			TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
			return 0;
		if ( !LookupPrivilegeValue( 0, SE_SHUTDOWN_NAME, &takeOwnershipValue ) )
			return 0;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[ 0 ].Luid = takeOwnershipValue;
		tkp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges( hToken, false, &tkp, sizeof( TOKEN_PRIVILEGES ), 0, 0 );
		if ( GetLastError( ) )
			return 0;

		//перезагрузка
		return ExitWindowsEx( EWX_FORCE | EWX_REBOOT, 0 );
	}

	__forceinline void printf( const char* format, ... )
	{
		va_list _ArgList;
		__crt_va_start( _ArgList, format );
		_vfprintf_l( __acrt_iob_func( 1 ), format, nullptr, _ArgList );
		__crt_va_end( _ArgList );
	}

	__forceinline bool nt_create_thread( PVOID address )
	{
		HANDLE thread_handle = NULL;

		auto status = sys_call<NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PTHREAD_START_ROUTINE, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID>(
			HASH( "NtCreateThreadEx" ),
			&thread_handle, THREAD_ALL_ACCESS,
			NULL, ( HANDLE ) -1, reinterpret_cast< PTHREAD_START_ROUTINE >( address ),
			NULL, 0x00000004, NULL, NULL, NULL, nullptr );

		if ( !NT_SUCCESS( status ) )
		{
			MessageBoxA( 0, "crash", "", MB_OK );
			return false;
		}
		return true;
	}

	__forceinline bool exit( )
	{
		auto status = sys_call<NTSTATUS, HANDLE, NTSTATUS>( HASH( "NtTerminateProcess" ), reinterpret_cast< HANDLE >( -1 ), STATUS_ACCESS_VIOLATION );

		if ( !NT_SUCCESS( status ) )
		{
			return false;
		}

		return true;
	}
}