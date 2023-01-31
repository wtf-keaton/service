#pragma once

namespace fusion::memory
{
	__forceinline NTSTATUS read_memory( HANDLE process_handle, void* address, void* target, size_t size )
	{
		size_t bytes{};
		PEPROCESS target_process{};

		PsLookupProcessByProcessId( process_handle, &target_process );

		return MmCopyVirtualMemory( target_process, address, PsGetCurrentProcess( ), target, size, KernelMode, &bytes );
	}

	__forceinline NTSTATUS write_memory( HANDLE process_handle, void* address, void* target, size_t size )
	{
		size_t bytes{};
		PEPROCESS target_process{};

		PsLookupProcessByProcessId( process_handle, &target_process );
		return MmCopyVirtualMemory( PsGetCurrentProcess( ), address, target_process, target, size, KernelMode, &bytes );
	}

	__forceinline BOOL get_request_data( void* dest, void* src, size_t size )
	{
		size_t bytes{};
		if ( NT_SUCCESS( MmCopyVirtualMemory( PsGetCurrentProcess( ), src, 	PsGetCurrentProcess( ), dest, size, KernelMode, &bytes ) ) && size == bytes )
		{
			return true;
		}

		return false;
	}

	__forceinline NTSTATUS start_routine( HANDLE handle, uintptr_t address )
	{

		return STATUS_SUCCESS;
	}
}