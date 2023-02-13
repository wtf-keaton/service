#pragma once

namespace fusion::imports
{
	NTSTATUS mm_copy_virutal_memory( PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize )
	{
		using fn = NTSTATUS( * )( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T );
		auto fn_mm_copy_virtual_memory = ( fn ) ( fusion::winapi::get_proc_address( fusion::winapi::get_module_handle<uintptr_t>( _( "ntoskrnl.exe" ) ), _( "MmCopyVirtualMemory" ) ) );

		return fn_mm_copy_virtual_memory( SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize );
	}

	NTSTATUS ps_lookup_process_by_process_id( HANDLE process_id, PEPROCESS* process )
	{
		using fn = NTSTATUS( * )( HANDLE, PEPROCESS* );
		auto fn_ps_lookup_process_by_process_id = ( fn ) ( fusion::winapi::get_proc_address( fusion::winapi::get_module_handle<uintptr_t>( _( "ntoskrnl.exe" ) ), _( "PsLookupProcessByProcessId" ) ) );

		return fn_ps_lookup_process_by_process_id( process_id, process );
	}
}