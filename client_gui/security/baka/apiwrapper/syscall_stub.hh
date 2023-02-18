#pragma once
#include "../ntapi.hh"
#include "apiwrapper.hh" 

namespace SyscallStub
{

	/*
	* https://github.com/fengjixuchui/khaleesi/blob/e75a5f117eadaa67db178981745370bae3184ca0/khaleesi/Shared/Helpers.h#L87
	*/
	__forceinline NTSTATUS RemapModule( const  wchar_t* ModuleName, PVOID* ModuleBaseAddress )
	{
		NTSTATUS status = STATUS_NOT_SUPPORTED;
		HANDLE sectionHandle = nullptr;
		SIZE_T viewSize = NULL;
		UNICODE_STRING usSectionName{};
		OBJECT_ATTRIBUTES objAttrib{};


		wchar_t buffer[ MAX_PATH ];
		memset( buffer, 0, MAX_PATH );
#ifdef _WIN64
		auto str_KnowDll = L"\\KnownDlls\\";
#else 

		auto str_KnowDll = L"\\KnownDlls32\\";
#endif  

		wcscat( buffer, str_KnowDll );

		wcscat( buffer, ModuleName );


		usSectionName = ApiWrapper::InitUnicodeString( buffer );


		InitializeObjectAttributes( &objAttrib, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL );

		auto ZwOpenSection = ( t_ZwOpenSection ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "ZwOpenSection" ) );
		auto ZwMapViewOfSection = ( t_ZwMapViewOfSection ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "ZwMapViewOfSection" ) );
		auto NtClose = ( t_NtClose ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "NtClose" ) );

		if ( !NtClose || !ZwMapViewOfSection || !ZwOpenSection )
		{
			return FALSE;

		}


		status = ZwOpenSection( &sectionHandle, SECTION_MAP_READ, &objAttrib );

		if ( !NT_SUCCESS( status ) )
		{
			return status;
		}


		status = ZwMapViewOfSection( sectionHandle, NtCurrentProcess, ModuleBaseAddress, NULL, NULL, nullptr,
			&viewSize, ( SECTION_INHERIT ) 1, NULL, PAGE_READONLY );


		if ( !NT_SUCCESS( status ) )
		{
			return status;
		}

		if ( sectionHandle )
		{
			status = NtClose( sectionHandle );
			if ( !NT_SUCCESS( status ) )
			{
				return status;
			}
		}
		return status;
	}

	// Try get  safe syscall number
	__forceinline short GetSyscallNumber( const  wchar_t* nameModule, const char* ApiName )
	{

		int original_syscall = 0;

		PVOID mapped_dll = nullptr;
		RemapModule( nameModule, &mapped_dll );

		auto baseNtDll = ApiWrapper::GetModuleBaseAddress( _( L"ntdll.dll" ) );
		if ( !mapped_dll || !baseNtDll )
		{

			return 0;
		}

		auto originalFunc = ApiWrapper::GetProcAddress( ( DWORD64 ) mapped_dll, ApiName );


		auto ZwUnmapViewOfSection = ( t_ZwUnmapViewOfSection ) ApiWrapper::GetProcAddress( baseNtDll, _( "ZwUnmapViewOfSection" ) );


		// SharpOD(use hook x64 functhion) and ShyllaHide(use wow64 hook) and we can get unsafe syscall
#ifndef _WIN64
		if ( !originalFunc )
		{
			originalFunc = ApiWrapper::GetProcAddress( nameModule, ApiName );
		}

#endif


		if ( !originalFunc ) //check for prevent SEH
		{
			//under debugger(x32 only)  return 0 ?????

			ZwUnmapViewOfSection( NtCurrentProcess, mapped_dll );
			return FALSE;
		}
#ifdef _WIN64
		original_syscall = *( short* ) ( originalFunc + 4 );
#else 
		original_syscall = *( short* ) ( originalFunc + 1 );
#endif 


		ZwUnmapViewOfSection( NtCurrentProcess, mapped_dll );
		return original_syscall;

	}
}
