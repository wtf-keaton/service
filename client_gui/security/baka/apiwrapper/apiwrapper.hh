#pragma once
#include "../struct.hh"

namespace ApiWrapper
{
    __forceinline    UNICODE_STRING InitUnicodeString( static const wchar_t* string_to_init )
    {

        UNICODE_STRING stringInit;
        if ( string_to_init )
        {
            stringInit.Length = wcslen( string_to_init ) * sizeof( wchar_t );
            stringInit.MaximumLength = stringInit.Length + 2;
            stringInit.Buffer = ( wchar_t* ) string_to_init;
        }
        return stringInit;

    }





    __forceinline  int CompareUnicodeString( UNICODE_STRING str_1, UNICODE_STRING str_2, bool case_int_sensitive = false )
    {

        //return 0 if equal
        if ( case_int_sensitive )
        {
            return wcscmp( str_1.Buffer, str_2.Buffer );
        }
        else
        {
            return _wcsicmp( str_1.Buffer, str_2.Buffer );
        }

    }



    __forceinline  void FreeUnicodeString( PUNICODE_STRING str )
    {

        str->Buffer = 0;
        str->Length = 0;
        str->MaximumLength = 0;
    }




    __forceinline  SIZE_T  NTAPI   RtlCompareMemory
    ( const VOID* Source1,
        const VOID* Source2,
        SIZE_T Length )
    {
        SIZE_T i;
        for ( i = 0; ( i < Length ) && ( ( ( PUCHAR ) Source1 )[ i ] == ( ( PUCHAR ) Source2 )[ i ] ); i++ )
            ;

        return i;
    }

    __forceinline  SIZE_T NTAPI  RtlCompareMemoryUlong
    (
        IN PVOID Source,
        IN SIZE_T Length,
        IN ULONG Value
    )
    {
        PULONG ptr = ( PULONG ) Source;
        ULONG_PTR len = Length / sizeof( ULONG );
        ULONG_PTR i;

        for ( i = 0; i < len; i++ )
        {
            if ( *ptr != Value )
                break;

            ptr++;
        }

        return ( SIZE_T ) ( ( PCHAR ) ptr - ( PCHAR ) Source );
    }




    __forceinline   VOID  NTAPI   MyZeroMemory
    (
        PVOID Destination,
        SIZE_T Length )
    {
        memset( Destination, 0, Length );
    }

    __forceinline  VOID NTAPI FillMemoryUlonglong
    (
        PVOID Destination,
        SIZE_T Length,
        ULONGLONG Fill )
    {
        PULONGLONG Dest = ( PULONGLONG ) Destination;
        SIZE_T Count = Length / sizeof( ULONGLONG );

        while ( Count > 0 )
        {
            *Dest = Fill;
            Dest++;
            Count--;
        }
    }


    __forceinline DWORD64 GetModuleBaseAddress( const wchar_t* modName )
    {


        ldr_data_table_entry* modEntry = nullptr;





#ifdef _WIN64
        PEB* peb = ( PEB* ) __readgsqword( 0x60 );

#else
        PEB* peb = ( PEB* ) __readfsdword( 0x30 );
#endif



        LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;

        LIST_ENTRY curr = head;

        for ( auto curr = head; curr.Flink != &peb->Ldr->InMemoryOrderModuleList; curr = *curr.Flink )
        {
            ldr_data_table_entry* mod = ( ldr_data_table_entry* ) CONTAINING_RECORD( curr.Flink, ldr_data_table_entry, InMemoryOrderLinks );

            if ( mod->BaseDllName.Buffer )
            {
                if ( !modName )
                {
                    modEntry = mod;
                    break;
                }


                if ( wcsstr( modName, mod->BaseDllName.Buffer ) )
                {
                    modEntry = mod;
                    break;
                }


            }
        }
        return ( DWORD64 ) modEntry->DllBase;

    }

    __forceinline DWORD64 GetProcAddress( const wchar_t* modName, const char* ApiName )
    {
        auto base = GetModuleBaseAddress( modName );
        if ( !base )
            return 0;
        auto pDOS = ( PIMAGE_DOS_HEADER ) base;
        if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;
        auto pNT = ( PIMAGE_NT_HEADERS ) ( base + ( DWORD ) pDOS->e_lfanew );
        if ( pNT->Signature != IMAGE_NT_SIGNATURE )
            return 0;
        auto pExport = ( PIMAGE_EXPORT_DIRECTORY ) ( base + pNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
        if ( !pExport )
            return 0;
        auto names = ( PDWORD ) ( base + pExport->AddressOfNames );
        auto ordinals = ( PWORD ) ( base + pExport->AddressOfNameOrdinals );
        auto functions = ( PDWORD ) ( base + pExport->AddressOfFunctions );

        for ( int i = 0; i < pExport->NumberOfFunctions; ++i ) {
            auto name = ( LPCSTR ) ( base + names[ i ] );
            if ( !strcmp( name, ApiName ) )
                return base + functions[ ordinals[ i ] ];
        }
        return 0;
    }

    __forceinline bool IsNormalSyscallByte( DWORD64 addressApi )
    {
#ifdef _WIN64

        return (
            *( BYTE* ) ( addressApi ) == 0x4C &&
            *( BYTE* ) ( addressApi + 1 ) == 0x8B &&
            *( BYTE* ) ( addressApi + 2 ) == 0xD1 &&
            *( BYTE* ) ( addressApi + 3 ) == 0xB8 &&
            *( BYTE* ) ( addressApi + 0x12 ) == 0x0F &&
            *( BYTE* ) ( addressApi + 0x13 ) == 0X05 );
#else 

        return (
            *( BYTE* ) ( addressApi ) == 0xB8 &&
            *( BYTE* ) ( addressApi + 5 ) == 0xBA &&
            *( BYTE* ) ( addressApi + 10 ) == 0xFF &&
            *( BYTE* ) ( addressApi + 11 ) == 0XD2 );
#endif // _WIN64


    }

    //We get randome ntapi and check for hook
    __forceinline    DWORD64 GetRandomSyscallAddress( )
    {


        auto base = ApiWrapper::GetModuleBaseAddress( _( L"ntdll.dll" ) );
        if ( !base )
            return 0;
        auto pDOS = ( PIMAGE_DOS_HEADER ) base;
        if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;
        auto pNT = ( PIMAGE_NT_HEADERS ) ( base + ( DWORD ) pDOS->e_lfanew );
        if ( pNT->Signature != IMAGE_NT_SIGNATURE )
            return 0;
        auto pExport = ( PIMAGE_EXPORT_DIRECTORY ) ( base + pNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
        if ( !pExport )
            return 0;
        auto names = ( PDWORD ) ( base + pExport->AddressOfNames );
        auto ordinals = ( PWORD ) ( base + pExport->AddressOfNameOrdinals );
        auto functions = ( PDWORD ) ( base + pExport->AddressOfFunctions );
        auto randomNumber = GetTickCount( ) % 30;

        for ( int j = 0, i = 0; i < pExport->NumberOfFunctions; ++i )
        {
            if ( IsNormalSyscallByte( base + functions[ ordinals[ i ] ] ) )
            {
                j++;
                if ( j == randomNumber )
                {
                    return base + functions[ ordinals[ i ] ];
                }
            }
        }

        return 0;
    }


    __forceinline DWORD64 GetProcAddress( DWORD64 base, const char* ApiName )
    {

        if ( !base )
            return 0;
        auto pDOS = ( PIMAGE_DOS_HEADER ) base;
        if ( pDOS->e_magic != IMAGE_DOS_SIGNATURE )
            return 0;
        auto pNT = ( PIMAGE_NT_HEADERS ) ( base + ( DWORD ) pDOS->e_lfanew );
        if ( pNT->Signature != IMAGE_NT_SIGNATURE )
            return 0;
        auto pExport = ( PIMAGE_EXPORT_DIRECTORY ) ( base + pNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
        if ( !pExport )
            return 0;
        auto names = ( PDWORD ) ( base + pExport->AddressOfNames );
        auto ordinals = ( PWORD ) ( base + pExport->AddressOfNameOrdinals );
        auto functions = ( PDWORD ) ( base + pExport->AddressOfFunctions );

        for ( int i = 0; i < pExport->NumberOfFunctions; ++i ) {
            auto name = ( LPCSTR ) ( base + names[ i ] );
            if ( !strcmp( name, ApiName ) )
                return base + functions[ ordinals[ i ] ];
        }
        return 0;
    }

    // Get Windows number by    KUSER_SHARED_DATA(support on Windows XP or leater)
    __forceinline  int GetWindowsNumber( )
    {

        auto NtMajorVersion = *( BYTE* ) 0x7FFE026C;
        if ( NtMajorVersion == 10 )
        {
            auto NtBuildNumber = *( int* ) 0x7FFE0260;//NtBuildNumber
            if ( NtBuildNumber >= 22000 )
            {
                return WINDOWS_NUMBER_11;
            }
            return WINDOWS_NUMBER_10;
        }
        else if ( NtMajorVersion == 5 )
        {
            return WINDOWS_NUMBER_XP;//Windows XP
        }
        else if ( NtMajorVersion == 6 )
        {
            /*
            https://www.godeye.club/2021/06/03/002-mhyprot-insider-callbacks.html
            */
            switch ( *( BYTE* ) 0x7FFE0270 )  //0x7FFE0270 NtMinorVersion
            {
            case 1:
                return WINDOWS_NUMBER_7;//windows 7
            case 2:
                return WINDOWS_NUMBER_8; //window 8
            case 3:
                return WINDOWS_NUMBER_8_1; //windows 8.1
            default:
                return WINDOWS_NUMBER_11;//windows 11
            }

        }

        return 0;
    }

    // Get windows numbe build by NtBuildNumber in KUSER_SHARED_DATA(support in Windows 10 or leater)
    __forceinline   int GetNumberBuild( )
    {
        if ( GetWindowsNumber( ) >= WINDOWS_NUMBER_10 )
        {
            return *( int* ) 0x00000007FFE0260; //NtBuildNumber

        }

        return 0;


    }
    __forceinline int wtoi( const wchar_t* nptr )
    {
        wchar_t* s = ( wchar_t* ) nptr;
        int acc = 0;
        int neg = 0;
        if ( nptr == 0 ) return 0;
        while ( *s = L' ' ) s++;
        if ( *s == L'-' )
        {
            neg = 1;
            s++;
        }
        else if ( *s == L'+' ) s++;
        while ( iswdigit( *s ) )
        {
            acc = 10 * acc + ( *s - L'0' );
            s++;
        }
        if ( neg ) acc *= -1;
        return acc;
    }
    __forceinline DWORD64 GetNtdllBuild( )
    {
        auto  pNative = ( wchar_t* ) ApiWrapper::GetModuleBaseAddress( _( L"ntdll.dll" ) );

        for ( ; ; pNative++ )
        {
            if ( wcscmp( pNative, _( L"FileVersion" ) ) == 0 )
            {

                return wtoi( pNative + 18 );
            }
        }
    }

    //Get OSBuildNumber in PEB
    __forceinline  int PEBGetNumberBuild( )
    {



#ifdef _WIN64
        return *( int* ) ( __readgsqword( 0x60 ) + 0x120 );

#else
        return *( int* ) ( __readfsdword( 0x30 ) + 0xAC );
#endif 

    }
}

