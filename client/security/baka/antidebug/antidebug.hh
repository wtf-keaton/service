﻿#pragma once

#include "../apiwrapper/syscall_stub.hh"


typedef unsigned char byte;


namespace AntiDebug
{

	namespace ShellCode
	{

		__forceinline bool IsDebugPort( )
		{
			DWORD64  DebugPort = NULL;
			NTSTATUS status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto SyscallNumber = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtQueryInformationProcess" ) );// Get auto syscall number

			// can't find automatic sycall number ,so we get manual by Windows number
			if ( !SyscallNumber )
			{
				auto numberWindows = ApiWrapper::GetWindowsNumber( );
				if ( numberWindows > WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 25;

				}
				else if ( numberWindows == WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 24;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 23;
				}
				else if ( numberWindows < WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = ( t_NtQueryInformationProcess ) VirtualAlloc( 0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
			if ( !addressShellCode )
			{
				return FALSE;
			}

			memcpy( &shellSysCall64[ 1 ], &SyscallNumber, 2 ); //set syscall
			memcpy( ( void* ) addressShellCode, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode

#ifdef _WIN64

			status = addressShellCode( NtCurrentProcess, processdebugport, &DebugPort, sizeof( DebugPort ), 0 );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressShellCode,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugPort,
				( DWORD64 ) &DebugPort,
				( DWORD64 ) sizeof( DebugPort ),
				( DWORD64 ) 0 );


#endif // 

			//compare byte's
			if ( _memicmp( ( void* ) addressShellCode, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			VirtualFree( ( PVOID ) addressShellCode, 0, MEM_RELEASE );
			if ( NT_SUCCESS( status ) && DebugPort != 0 )
			{
				return TRUE;
			}
			return FALSE;
		}


		__forceinline	bool IsDebugObjectHandle( )
		{

			DWORD64	DebugObject = NULL;
			NTSTATUS  status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto SyscallNumber = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtQueryInformationProcess" ) );// Get auto syscall number

			// can't find automatic sycall number ,so we get manual by Windows number
			if ( !SyscallNumber )
			{
				auto numberWindows = ApiWrapper::GetWindowsNumber( );
				if ( numberWindows > WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 25;

				}
				else if ( numberWindows == WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 24;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 23;
				}
				else if ( numberWindows < WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = ( t_NtQueryInformationProcess ) VirtualAlloc( 0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
			if ( !addressShellCode )
			{
				return FALSE;
			}

			memcpy( &shellSysCall64[ 1 ], &SyscallNumber, 2 ); //set syscall
			memcpy( ( void* ) addressShellCode, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode

#ifdef _WIN64

			status = addressShellCode( NtCurrentProcess, processdebugobjecthandle, &DebugObject, sizeof( DebugObject ), 0 );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressShellCode,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugObjectHandle,
				( DWORD64 ) &DebugObject,
				( DWORD64 ) sizeof( DebugObject ),
				( DWORD64 ) 0 );


#endif // 

			//compare byte's
			if ( _memicmp( ( void* ) addressShellCode, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			VirtualFree( ( PVOID ) addressShellCode, 0, MEM_RELEASE );
			if ( NT_SUCCESS( status ) && DebugObject != 0 )
			{
				return TRUE;
			}
			return FALSE;
		}



		__forceinline bool IsDebugFlag( )
		{

			DWORD  DebugFlag = NULL;
			NTSTATUS  status = STATUS_UNSUCCESSFUL;


			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto SyscallNumber = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtQueryInformationProcess" ) );// Get auto syscall number


			/// can't find automatic sycall number ,so we get manual by Windows number
			if ( !SyscallNumber )
			{
				auto numberWindows = ApiWrapper::GetWindowsNumber( );
				if ( numberWindows > WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 25;

				}
				else if ( numberWindows == WINDOWS_NUMBER_8_1 )
				{
					SyscallNumber = 24;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 23;
				}
				else if ( numberWindows < WINDOWS_NUMBER_8 )
				{
					SyscallNumber = 22;
				}
			}

			auto addressShellCode = VirtualAlloc( 0, 0x1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
			if ( !addressShellCode )
			{
				return FALSE;
			}

			memcpy( &shellSysCall64[ 1 ], &SyscallNumber, 2 ); //set syscall
			memcpy( ( void* ) addressShellCode, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode

#ifdef _WIN64

			status = ( ( t_NtQueryInformationProcess ) addressShellCode )( NtCurrentProcess, processdebugflags, &DebugFlag, sizeof( DebugFlag ), 0 );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressShellCode,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugFlags,
				( DWORD64 ) &DebugFlag,
				( DWORD64 ) sizeof( DebugFlag ),
				( DWORD64 ) 0 );


#endif // 

			//compare byte's
			if ( _memicmp( ( void* ) addressShellCode, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			VirtualFree( ( PVOID ) addressShellCode, 0, MEM_RELEASE );
			if ( status == STATUS_SUCCESS && DebugFlag == 0 )
			{
				return TRUE;
			}
			return FALSE;
		}



	}


	namespace OverWriteSyscall
	{
		bool IsDebugFlagHooked( )
		{
			DWORD32  DebugFlag = NULL;
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			DWORD protect = NULL;
			BYTE safeByte[ 20 ];
			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};
			memset( safeByte, 0, sizeof( safeByte ) );
			auto syscallNumberQueryInformationProcess = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtQueryInformationProcess" ) );// Get auto syscall number
			auto syscallSetInformationProcess = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtSetInformationProcess" ) );// Get auto syscall number

			/// can't find automatic sycall number ,so we get manual by Windows number
			if ( !syscallNumberQueryInformationProcess || !syscallSetInformationProcess )
			{

				auto numberWindows = ApiWrapper::GetWindowsNumber( );
				if ( numberWindows > WINDOWS_NUMBER_8_1 )
				{
					syscallNumberQueryInformationProcess = 25;
					syscallSetInformationProcess = 28;

				}
				else if ( numberWindows == WINDOWS_NUMBER_8_1 )
				{
					syscallNumberQueryInformationProcess = 24;
					syscallSetInformationProcess = 27;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8 )
				{
					syscallNumberQueryInformationProcess = 23;
					syscallSetInformationProcess = 26;
				}
				else if ( numberWindows < WINDOWS_NUMBER_8 )
				{
					syscallNumberQueryInformationProcess = 22;
					syscallSetInformationProcess = 25;
				}
			}
			auto addressApi = ( DWORD64* ) ApiWrapper::GetRandomSyscallAddress( );
			if ( !addressApi )
			{
				return FALSE;
			}
			//We write shellcode in ntdll Api for present allocate memory
			VirtualProtect( addressApi, 0x1024, PAGE_EXECUTE_READWRITE, &protect );
			memcpy( &shellSysCall64[ 1 ], &syscallNumberQueryInformationProcess, 2 ); //set syscall
			memcpy( safeByte, addressApi, sizeof( safeByte ) );
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode

#ifdef _WIN64

			status = ( t_NtQueryInformationProcess( addressApi ) )( NtCurrentProcess, processdebugflags, &DebugFlag, sizeof( DebugFlag ), 0 );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressApi,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugFlags,
				( DWORD64 ) &DebugFlag,
				( DWORD64 ) sizeof( DebugFlag ),
				( DWORD64 ) 0 );


#endif // 

			if ( NT_SUCCESS( status ) && DebugFlag == 0 )
			{
				return TRUE;
			}

			//compare byte's
			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			memcpy( &shellSysCall64[ 1 ], &syscallSetInformationProcess, 2 ); //set syscall
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode
			DebugFlag = 0;

			/*
			We set DebugFlag and check this +
			TitanHide don't hook NtSetInformationProcess and return all time in NtQueryInformationProcess NoDebugInherit = TRUE,
			so we can detect this
			*/
#ifdef _WIN64

			status = ( t_NtSetInformationProcess( addressApi ) )( NtCurrentProcess, processdebugflags, &DebugFlag, sizeof( DebugFlag ) );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressApi,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugFlags,
				( DWORD64 ) &DebugFlag,
				( DWORD64 ) sizeof( DebugFlag ),
				( DWORD64 ) 0 );


#endif // 
			if ( !NT_SUCCESS( status ) )
			{
				memcpy( addressApi, safeByte, sizeof( safeByte ) );
				VirtualProtect( addressApi, 0x1024, protect, &protect );
				return FALSE;
			}
			//compare byte's
			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			DebugFlag = 1;
			memcpy( &shellSysCall64[ 1 ], &syscallNumberQueryInformationProcess, 2 ); //set syscall
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode
			// Goodbuy TitanHide
#ifdef _WIN64

			status = ( t_NtQueryInformationProcess( addressApi ) )( NtCurrentProcess, processdebugflags, &DebugFlag, sizeof( DebugFlag ), 0 );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressApi,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugFlags,
				( DWORD64 ) &DebugFlag,
				( DWORD64 ) sizeof( DebugFlag ),
				( DWORD64 ) 0 );


#endif // 
			if ( NT_SUCCESS( status ) && DebugFlag != 0 )
			{
				return TRUE;
			}

			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			memcpy( &shellSysCall64[ 1 ], &syscallSetInformationProcess, 2 ); //set syscall
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode
			DebugFlag = 1;
#ifdef _WIN64

			status = ( t_NtSetInformationProcess( addressApi ) )( NtCurrentProcess, processdebugflags, &DebugFlag, sizeof( DebugFlag ) );
#else

			status = WoW64Help::X64Call(
				( DWORD64 ) addressApi,
				5,
				( DWORD64 ) -1,	//NtCurrentProcess
				( DWORD64 ) ProcessDebugFlags,
				( DWORD64 ) &DebugFlag,
				( DWORD64 ) sizeof( DebugFlag ),
				( DWORD64 ) 0 );


#endif // 
			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			memcpy( addressApi, safeByte, sizeof( safeByte ) );
			VirtualProtect( addressApi, 0x1024, protect, &protect );

			return FALSE;



		}





		bool IsBadHideThread( )
		{

			NTSTATUS  status = STATUS_UNSUCCESSFUL;
			bool IsThreadHide = FALSE;
			DWORD64 badGuy = NULL;
			DWORD protect = NULL;
			BYTE safeByte[ 20 ];
			unsigned char shellSysCall64[] = {
				0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,syscallNumber
				0x4C, 0x8B, 0xD1,           // mov r10,rcx
				0x0F, 0x05,                 // syscall
				0xC3                        // retn
			};

			auto syscallNumberSetInformathion = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtSetInformationThread" ) );// Get auto syscall number

			auto syscallNumberQueryInfThread = SyscallStub::GetSyscallNumber( _( L"ntdll.dll" ), _( "NtQueryInformationThread" ) );// Get auto syscall number

			if ( !syscallNumberSetInformathion || !syscallNumberQueryInfThread )
			{
				// can't find automatic value ,so we get manual by Windows number
				auto numberWindows = ApiWrapper::GetWindowsNumber( );
				if ( numberWindows > WINDOWS_NUMBER_8_1 )
				{
					syscallNumberSetInformathion = 13;
					syscallNumberQueryInfThread = 37;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8_1 )
				{
					syscallNumberSetInformathion = 12;
					syscallNumberQueryInfThread = 36;
				}
				else if ( numberWindows == WINDOWS_NUMBER_8 )
				{
					syscallNumberSetInformathion = 11;
					syscallNumberQueryInfThread = 35;
				}
				else if ( numberWindows < WINDOWS_NUMBER_8 )
				{
					syscallNumberSetInformathion = 10;
					syscallNumberQueryInfThread = 34;
				}
			}
			auto addressApi = ( t_NtQueryInformationProcess ) ApiWrapper::GetRandomSyscallAddress( );
			if ( !addressApi )
			{
				return FALSE;
			}
			VirtualProtect( addressApi, 0x1024, PAGE_EXECUTE_READWRITE, &protect );
			memcpy( &shellSysCall64[ 1 ], &syscallNumberSetInformathion, 2 ); //set syscall
			memcpy( safeByte, addressApi, sizeof( safeByte ) );// sade byte
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode


			status = ( ( t_NtSetInformationThread ) addressApi )( NtCurrentThread, threadhidefromdebugger, &badGuy, 0x999 );


			if ( NT_SUCCESS( status ) )
			{
				return TRUE;
			}


			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}



			status = ( ( t_NtSetInformationThread ) addressApi )( NtCurrentThread, threadhidefromdebugger, 0, 0 );

			if ( !NT_SUCCESS( status ) )
			{
				return FALSE;
			}


			memcpy( &shellSysCall64[ 1 ], &syscallNumberQueryInfThread, 2 ); //set syscall
			memcpy( ( void* ) addressApi, shellSysCall64, sizeof( shellSysCall64 ) );// write shellcode

			status = ( ( t_NtQueryInformationThread ) addressApi )( NtCurrentThread, threadhidefromdebugger, &IsThreadHide, sizeof( bool ), 0 );


			if ( _memicmp( ( void* ) addressApi, &shellSysCall64, sizeof( shellSysCall64 ) ) )
			{
				return TRUE;
			}

			memcpy( addressApi, safeByte, sizeof( safeByte ) );
			VirtualProtect( addressApi, 0x1024, protect, &protect );
			if ( NT_SUCCESS( status ) && !IsThreadHide )
			{
				return TRUE;
			}
			return FALSE;
		}




	}

	namespace Util
	{

		//wallking in all known module end check PAGE_GUARD hook (x64dbg use this for memory page)
//		__forceinline bool IsGuardHook( )
//		{
//
//
//			MEMORY_BASIC_INFORMATION memory_info;
//
//
//#ifdef _WIN64
//			PEB* peb = ( PEB* ) __readgsqword( 0x60 );
//
//#else
//			PEB* peb = ( PEB* ) __readfsdword( 0x30 );
//#endif
//
//
//
//			LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
//
//			LIST_ENTRY curr = head;
//
//			for ( auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink )
//			{
//				LDR_DATA_TABLE_ENTRY* mod = ( LDR_DATA_TABLE_ENTRY* ) CONTAINING_RECORD( curr.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );
//
//				if ( mod->BaseDllName.Buffer )
//				{
//					auto* headers = reinterpret_cast< PIMAGE_NT_HEADERS >( static_cast< char* >( mod->DllBase ) + static_cast< PIMAGE_DOS_HEADER >( mod->DllBase )->e_lfanew );
//					auto* sections = IMAGE_FIRST_SECTION( headers );
//
//					for ( auto i = 0; i <= headers->FileHeader.NumberOfSections; i++ )
//					{
//						auto* section = &sections[ i ];
//
//						auto virtualAddress = static_cast< PBYTE >( mod->DllBase ) + section->VirtualAddress;
//
//						if ( VirtualQuery( virtualAddress, &memory_info, sizeof( MEMORY_BASIC_INFORMATION ) ) )
//						{
//							//know memory and  page have PAGE_GUARD protecthion
//							if ( memory_info.State == MEM_COMMIT && ( memory_info.Protect & PAGE_GUARD ) )
//								return TRUE;
//
//						}
//
//					}
//
//
//				}
//			}
//			return FALSE;
//		}

		/*
		Check only in execute module for present false detect
		 0xcc - can be code cave
		*/
		__forceinline bool IsModuleHaveBP( )
		{
			auto base = ( PVOID ) ApiWrapper::GetModuleBaseAddress( NULL );

			auto* headers = reinterpret_cast< PIMAGE_NT_HEADERS >( static_cast< char* >( base ) + static_cast< PIMAGE_DOS_HEADER >( base )->e_lfanew );
			auto* sections = IMAGE_FIRST_SECTION( headers );

			for ( auto i = 0; i <= headers->FileHeader.NumberOfSections; i++ )
			{
				auto* section = &sections[ i ];
				//Check secthion rules
				auto virtualAddress = static_cast< PBYTE >( base ) + section->VirtualAddress;
				if ( ( section->Characteristics & IMAGE_SCN_MEM_READ && section->Characteristics & IMAGE_SCN_MEM_EXECUTE ) && !( section->Characteristics & IMAGE_SCN_MEM_WRITE ) )
				{
					for ( size_t j = 0; j <= section->Misc.VirtualSize; j++ )
					{
#ifdef _WIN64


						if ( *( virtualAddress + j ) == 0x0f && *( virtualAddress + j + 1 ) == 0xb//ud2 breakpoint
							&& ( *( virtualAddress + j + 2 ) ) != NULL
							&& *( virtualAddress + j + 3 ) != NULL )
						{
							return TRUE;
						}

#else  //False detect by IsStartedWithDisableDSE@CheckTestMode
						if ( *( virtualAddress + j ) == 0xcd && *( virtualAddress + j + 1 ) == 0x3 //long int 
							&& ( *( virtualAddress + j + 2 ) ) != NULL
							&& *( virtualAddress + j + 3 ) != NULL )
						{
							return TRUE;
						}
#endif
					}
				}

			}
			return FALSE;
		}


		//We fast check hook in some ntapi 
		__forceinline bool IsNtApiCorrupted( )
		{


			auto base = ( DWORD64 ) ApiWrapper::GetModuleBaseAddress( _( L"ntdll.dll" ) );

			if ( !base )
				return 0;
			auto pDOS = ( PIMAGE_DOS_HEADER ) base;
			if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE )
				return 0;
			auto pNT = ( PIMAGE_NT_HEADERS ) ( ( DWORD64 ) base + ( DWORD ) pDOS->e_lfanew );
			if ( pNT->Signature != IMAGE_NT_SIGNATURE )
				return 0;
			auto pExport = ( PIMAGE_EXPORT_DIRECTORY ) ( base + pNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
			if ( !pExport )
				return 0;
			auto names = ( PDWORD ) ( base + pExport->AddressOfNames );
			auto ordinals = ( PWORD ) ( base + pExport->AddressOfNameOrdinals );
			auto functions = ( PDWORD ) ( base + pExport->AddressOfFunctions );

			for ( int j = 0, i = 0; i < pExport->NumberOfFunctions; ++i ) {
				auto name = ( LPCSTR ) ( base + names[ i ] );
				if ( name[ 0 ] == 'N' && name[ 1 ] == 't' )
				{
					if
						(
							//We check byte's syscall/sysentry for present false detect(like:NtGetTickCount)
#ifdef _WIN64			
							!ApiWrapper::IsNormalSyscallByte( base + functions[ ordinals[ i ] ] ) &&
							*( BYTE* ) ( base + functions[ ordinals[ i ] ] + 0x12 ) == 0x0F && //syscall
							*( BYTE* ) ( base + functions[ ordinals[ i ] ] + 0x13 ) == 0X05
#else
							!ApiWrapper::IsNormalSyscallByte( base + functions[ ordinals[ i ] ] ) &&
							*( BYTE* ) ( base + functions[ ordinals[ i ] ] + 0xA ) == 0xFF &&  //sysentry
							*( BYTE* ) ( base + functions[ ordinals[ i ] ] + 0xB ) == 0XD2
#endif // _WIN64
							)
					{
						return TRUE;
					}
				}
			}
			return FALSE;
		}

		/*
		Anti UM plugin change build number for bypass manual syscall in VMP and we will be check this
		*/
		__forceinline bool BuildNumberIsHooked( )
		{

			auto buildNumberNtdll = ApiWrapper::GetNtdllBuild( );

			//Check start check OSBuildNumber in PEB 
			if ( ApiWrapper::GetWindowsNumber( ) >= WINDOWS_NUMBER_10 )
			{
				// we can safe check by read  NtBuildNumber in KUSER_SHARED_DATA
				if ( ApiWrapper::GetNumberBuild( ) != ApiWrapper::PEBGetNumberBuild( ) )
				{
					return TRUE;
				}
				else if
					(
						ApiWrapper::GetNumberBuild( ) - buildNumberNtdll > 2000 ||
						buildNumberNtdll - ApiWrapper::GetNumberBuild( ) < 2000
						)
				{
					return TRUE;
				}

			}
			else
			{
				// windows number < 10 we check by RtlGetVersion
				RTL_OSVERSIONINFOW  lpVersionInformation;

				lpVersionInformation.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOW );


				auto   RtlGetVersion = ( t_RtlGetVersion ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "RtlGetVersion" ) );

				if ( RtlGetVersion )
				{
					RtlGetVersion( &lpVersionInformation );
					if ( lpVersionInformation.dwBuildNumber != ApiWrapper::PEBGetNumberBuild( ) )
					{
						return TRUE;
					}
					else if
						( ( lpVersionInformation.dwBuildNumber - buildNumberNtdll > 2000 ) ||
							( buildNumberNtdll - lpVersionInformation.dwBuildNumber < 2000 ) )
					{
						return TRUE;
					}

				}
			}


			return FALSE;
		}
	}

}
