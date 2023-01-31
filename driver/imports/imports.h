#pragma once

namespace fusion::imports
{
	//NTSTATUS mm_copy_virutal_memory( PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize )
	//{
	//	static NTSTATUS( __fastcall * fn_mm_copy_virutal_memory )( PEPROCESS, PVOID, PEPROCESS, PVOID, SIZE_T, KPROCESSOR_MODE, PSIZE_T ) = nullptr;
	//	if ( !fn_mm_copy_virutal_memory )
	//		fn_mm_copy_virutal_memory = 
	//			reinterpret_cast<decltype( fn_mm_copy_virutal_memory )>(
	//				fusion::winapi::get_proc_address( fusion::winapi::get_module_handle<uintptr_t>( _( "ntoskrnl.exe" ) ), _( "MmCopyVirtualMemory" ) ) );

	//	return fn_mm_copy_virutal_memory( SourceProcess, SourceAddress, TargetProcess, TargetAddress, BufferSize, PreviousMode, ReturnSize );
	//}

}