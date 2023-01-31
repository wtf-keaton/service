#pragma once

namespace fusion::winapi
{
	template<typename _ty> __forceinline _ty get_module_handle( const char* module_name = nullptr )
	{
		void* moduleBase = NULL;
		ULONG info = 0;
		NTSTATUS status = ZwQuerySystemInformation( SystemModuleInformation, 0, info, &info );

		if ( !info )
		{
			return reinterpret_cast< _ty >( moduleBase );
		}

		PRTL_PROCESS_MODULES modules = ( PRTL_PROCESS_MODULES ) ExAllocatePoolWithTag( NonPagedPool, info, 'NAZI' );

		status = ZwQuerySystemInformation( SystemModuleInformation, modules, info, &info );

		if ( !NT_SUCCESS( status ) )
		{
			return reinterpret_cast< _ty >( moduleBase );
		}

		PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
		if ( modules->NumberOfModules > 0 )
		{
			if ( !module_name )
			{
				moduleBase = modules->Modules[ 0 ].ImageBase;
			}
			else
			{
				for ( auto i = 0; i < modules->NumberOfModules; i++ )
				{
					if ( strstr( ( CHAR* ) module[ i ].FullPathName, module_name ) )
					{
						moduleBase = module[ i ].ImageBase;
					}
				}
			}
		}

		if ( modules )
		{
			ExFreePoolWithTag( modules, 'NAZI' );
		}

		return reinterpret_cast< _ty >( moduleBase );
	}

	__forceinline PIMAGE_NT_HEADERS get_nt_header( PVOID module )
	{
		return ( PIMAGE_NT_HEADERS ) ( ( PBYTE ) module + PIMAGE_DOS_HEADER( module )->e_lfanew );
	}

	template<typename _ty> __forceinline _ty find_pattern( PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask )
	{

		auto checkMask = []( PBYTE buffer, LPCSTR pattern, LPCSTR mask ) -> BOOL
		{
			for ( auto x = buffer; *mask; pattern++, mask++, x++ )
			{
				auto addr = *( BYTE* ) ( pattern );
				if ( addr != *x && *mask != '?' )
					return FALSE;
			}

			return TRUE;
		};

		for ( auto x = 0; x < size - strlen( mask ); x++ )
		{

			auto addr = ( PBYTE ) module + x;
			if ( checkMask( addr, pattern, mask ) )
				return reinterpret_cast< _ty >( addr );
		}

		return NULL;
	}

	template<typename _ty> __forceinline _ty find_pattern( void* base_address, const char* pattern, const char* mask )
	{
		auto header = get_nt_header( base_address );
		auto section = IMAGE_FIRST_SECTION( header );

		for ( auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++ )
		{
			if ( !memcmp( section->Name, ".text", 5 ) || !memcmp( section->Name, "PAGE", 4 ) )
			{
				auto addr = find_pattern<PBYTE>( ( PBYTE ) base_address + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask );
				if ( addr )
				{
					return reinterpret_cast< _ty >( addr );
				}
			}
		}

		return NULL;
	}

	__forceinline NTSTATUS get_module_base_address( int process_id, const char* module_name, uintptr_t* base_address )
	{
		ANSI_STRING ansiString;
		UNICODE_STRING compareString;
		KAPC_STATE state;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		PEPROCESS process = NULL;
		PPEB pPeb = NULL;

		RtlInitAnsiString( &ansiString, module_name );
		RtlAnsiStringToUnicodeString( &compareString, &ansiString, TRUE );

		if ( !NT_SUCCESS( PsLookupProcessByProcessId( ( HANDLE ) process_id, &process ) ) )
			return STATUS_UNSUCCESSFUL;

		KeStackAttachProcess( process, &state );
		pPeb = PsGetProcessPeb( process );

		if ( pPeb )
		{
			PPEB_LDR_DATA pLdr = ( PPEB_LDR_DATA ) pPeb->Ldr;

			if ( pLdr )
			{
				for ( PLIST_ENTRY list = ( PLIST_ENTRY ) pLdr->InMemoryOrderModuleList.Flink; list != &pLdr->InMemoryOrderModuleList; list = ( PLIST_ENTRY ) list->Flink )
				{
					PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD( list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

					if ( RtlCompareUnicodeString( &pEntry->BaseDllName, &compareString, TRUE ) == 0 )
					{
						*base_address = ( uint64_t ) pEntry->DllBase;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
		}
		KeUnstackDetachProcess( &state );
		RtlFreeUnicodeString( &compareString );
		return status;
	}

	//__forceinline uintptr_t	get_proc_address( const uintptr_t imageBase, const char* exportName )
	//{
	//	if ( !imageBase )
	//		return 0;

	//	if ( reinterpret_cast< PIMAGE_DOS_HEADER >( imageBase )->e_magic != 0x5A4D )
	//		return 0;

	//	const auto ntHeader = reinterpret_cast< PIMAGE_NT_HEADERS64 >( imageBase + reinterpret_cast< PIMAGE_DOS_HEADER >( imageBase )->e_lfanew );
	//	const auto exportDirectory = reinterpret_cast< PIMAGE_EXPORT_DIRECTORY >( imageBase + ntHeader->OptionalHeader.DataDirectory[ 0 ].VirtualAddress );
	//	if ( !exportDirectory )
	//		return 0;

	//	const auto exportedFunctions = reinterpret_cast< DWORD* >( imageBase + exportDirectory->AddressOfFunctions );
	//	const auto exportedNames = reinterpret_cast< DWORD* >( imageBase + exportDirectory->AddressOfNames );
	//	const auto exportedNameOrdinals = reinterpret_cast< UINT16* >( imageBase + exportDirectory->AddressOfNameOrdinals );

	//	for ( size_t i{}; i < exportDirectory->NumberOfNames; ++i )
	//	{
	//		const auto functionName = reinterpret_cast< const char* >( imageBase + exportedNames[ i ] );
	//		if ( fusion::string::stricmp( exportName, functionName ) == 0 )
	//		{
	//			return imageBase + exportedFunctions[ exportedNameOrdinals[ i ] ];
	//		}
	//	}

	//	return 0;
	//}

}