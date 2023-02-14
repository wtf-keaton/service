#pragma once

namespace fusion::memory
{
	NTSTATUS read_memory( HANDLE process_handle, void* address, void* buffer, size_t size )
	{
		size_t bytes{};
		PEPROCESS target_process{};

		fusion::imports::ps_lookup_process_by_process_id( process_handle, &target_process );
		return fusion::imports::mm_copy_virutal_memory( target_process, address, PsGetCurrentProcess( ), buffer, size, KernelMode, &bytes );

	}

	NTSTATUS write_memory( HANDLE process_handle, void* address, void* buffer, size_t size )
	{
		size_t bytes{};
		PEPROCESS target_process{};

		fusion::imports::ps_lookup_process_by_process_id( process_handle, &target_process );
		return fusion::imports::mm_copy_virutal_memory( IoGetCurrentProcess( ), buffer, target_process, address, size, KernelMode, &bytes );
	}

	BOOL get_request_data( void* dest, void* src, size_t size )
	{
		size_t bytes{};
		if ( NT_SUCCESS( fusion::imports::mm_copy_virutal_memory( PsGetCurrentProcess( ), src, 	PsGetCurrentProcess( ), dest, size, KernelMode, &bytes ) ) && size == bytes )
		{
			return true;
		}

		return false;
	}
}