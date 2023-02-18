#ifndef ANTI_DEBUG_TOOL

#define ANTI_DEBUG_TOOL 1

#define BSOD_TITAN_HIDE 1 
#define BSOD_HYPER_HIDE 1 
#include "../../lazy_import.h"
#include "../ntapi.hh"  
#include "../apiwrapper/apiwrapper.hh"

#include <iostream>

#define BREAK_INFO() \
    HANDLE uniq_process_id = NtCurrentTeb()->ClientId.UniqueProcess; \
    HANDLE uniq_thread_id = NtCurrentTeb()->ClientId.UniqueThread; \
    NtCurrentTeb()->ClientId.UniqueProcess = reinterpret_cast<HANDLE>(1); \
    NtCurrentTeb()->ClientId.UniqueThread = reinterpret_cast<HANDLE>(1);  

#define RESTORE_INFO() \
    NtCurrentTeb()->ClientId.UniqueProcess = uniq_process_id; \
    NtCurrentTeb()->ClientId.UniqueThread = uniq_thread_id; 

namespace bad_code_detector
{
    namespace util
    {
        __forceinline auto strlen( const char* string ) -> INT
        {
            INT cnt = 0;
            if ( string )
            {
                for ( ; *string != 0; ++string ) ++cnt;
            }
            return cnt;
        }

        __forceinline auto wtolower( INT c ) -> INT
        {
            if ( c >= L'A' && c <= L'Z' ) return c - L'A' + L'a';
            if ( c >= L'À' && c <= L'ß' ) return c - L'À' + L'à';
            if ( c == L'¨' ) return L'¸';
            return c;
        }

        __forceinline int stricmp( const CHAR* cs, const CHAR* ct )
        {
            if ( cs && ct )
            {
                while ( tolower( *cs ) == tolower( *ct ) )
                {
                    if ( *cs == 0 && *ct == 0 ) return 0;
                    if ( *cs == 0 || *ct == 0 ) break;
                    cs++;
                    ct++;
                }
                return tolower( *cs ) - tolower( *ct );
            }
            return -1;
        }

        __forceinline auto wstricmp( const WCHAR* cs, const WCHAR* ct ) -> INT
        {
            if ( cs && ct )
            {
                while ( wtolower( *cs ) == wtolower( *ct ) )
                {
                    if ( *cs == 0 && *ct == 0 ) return 0;
                    if ( *cs == 0 || *ct == 0 ) break;
                    cs++;
                    ct++;
                }
                return wtolower( *cs ) - wtolower( *ct );
            }
            return -1;
        }

        __declspec( noinline ) auto get_windows_number( ) -> INT
        {

            auto NtMajorVersion = *reinterpret_cast< PBYTE >( 0x7FFE026C );
            if ( NtMajorVersion == 10 )
            {
                auto NtBuildNumber = *reinterpret_cast< PINT >( 0x7FFE0260 );//NtBuildNumber
                if ( NtBuildNumber >= 22000 )
                    return WINDOWS_NUMBER_11;
                return WINDOWS_NUMBER_10;
            }
            else if ( NtMajorVersion == 5 )
                return WINDOWS_NUMBER_XP;//Windows XP
            else if ( NtMajorVersion == 6 )
            {
                switch ( *reinterpret_cast< PBYTE >( 0x7FFE0270 ) )  //0x7FFE0270 NtMinorVersion
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
            return NULL;
        }

        __declspec( noinline ) auto get_address_driver( const CHAR* module_name ) -> uint64_t
        {
            PVOID buffer = NULL;
            DWORD ret_lenght = NULL;
            NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
            uint64_t base_address = NULL;
            prtl_process_modules module_info;
            auto NtQuerySystemInformation = ( t_NtQuerySystemInformation ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "NtQuerySystemInformation" ) );

            nt_status = NtQuerySystemInformation( systemmoduleinformation, buffer, ret_lenght, &ret_lenght );

            while ( nt_status == STATUS_INFO_LENGTH_MISMATCH )
            {
                if ( buffer != NULL )
                    VirtualFree( buffer, NULL, MEM_RELEASE );

                buffer = VirtualAlloc( nullptr, ret_lenght, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                nt_status = NtQuerySystemInformation( systemmoduleinformation, buffer, ret_lenght, &ret_lenght );
            }

            if ( !NT_SUCCESS( nt_status ) )
            {
                if ( buffer != NULL )
                    VirtualFree( buffer, NULL, MEM_RELEASE );
                return NULL;
            }

            module_info = static_cast< prtl_process_modules >( buffer );
            if ( !module_info )
                return NULL;

            for ( ULONG i = NULL; i < module_info->NumberOfModules; ++i )
            {
                if ( stricmp( reinterpret_cast< char* >( module_info->Modules[ i ].FullPathName ) + module_info->Modules[ i ].OffsetToFileName, module_name ) == NULL )
                {
                    base_address = reinterpret_cast< uint64_t >( module_info->Modules[ i ].ImageBase );
                    VirtualFree( buffer, NULL, MEM_RELEASE );
                    return base_address;
                }
            }
            VirtualFree( buffer, NULL, MEM_RELEASE );
            return NULL;
        }


    }

    __declspec( noinline ) void mem_function( )
    {
        __nop( );
    }

    /*
    * https://github.com/mrexodia/TitanHide/issues/44
    *Detect SharpOD,ScyllaHide ,TitanHide
    */
    __forceinline auto is_bad_hide_context( ) -> bool
    {
        MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );

        auto mem_address = reinterpret_cast< uint64_t >( &mem_function );
        MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );

        CONTEXT ctx = { 0 };
        CONTEXT ctx2 = { 0 };

        ctx.Dr0 = mem_address;
        ctx.Dr7 = 1;
        ctx.ContextFlags = 0x10;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );

        //Crash SharpOD/ScyllaHide
        if ( NT_SUCCESS( LI_FN( NtSetContextThread ).nt_cached( )( NtCurrentThread, reinterpret_cast< PCONTEXT >( 1 ) ) ) )
        {
         
            MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );
            return TRUE;
        }
        if ( NT_SUCCESS( LI_FN( NtGetContextThread ).nt_cached( )( NtCurrentThread, reinterpret_cast< PCONTEXT >( 1 ) ) ) )
        {
            MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );

            return TRUE;
        }

        if ( !NT_SUCCESS( LI_FN( NtSetContextThread ).nt_cached( )( NtCurrentThread, &ctx ) ) )
            return FALSE;
        if ( !NT_SUCCESS( LI_FN( NtGetContextThread ).nt_cached( )( NtCurrentThread, &ctx2 ) ) )
            return FALSE;
        if ( ctx2.Dr0 != ctx.Dr0 ||
            ctx2.Dr0 != mem_address ||
            ctx2.Dr1 ||
            ctx2.Dr2 ||
            ctx2.Dr3 ||
            !ctx2.Dr7 )
        {
            MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );
            return TRUE;
        }

#ifdef BSOD_HYPER_HIDE
        /*
        https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L874
        No check UM address?
        */
        uint64_t kernel_address = bad_code_detector::util::get_address_driver( _( "ntoskrnl.exe" ) );

        if ( kernel_address == NULL )
            kernel_address = 0xFFFFF80000000000;

        for ( size_t i = NULL, sucess_number = NULL; sucess_number != NULL || i < 0x100 * 0x100; kernel_address += 0x1000, i++ )
        {
            auto nt_status = LI_FN( NtGetContextThread ).nt_cached( )( NtCurrentThread, reinterpret_cast< PCONTEXT >( kernel_address ) );
            if ( STATUS_ACCESS_VIOLATION != nt_status )
                sucess_number++;
        }
#endif // BSOD_HYPER_HIDE


        ctx2.Dr0 = NULL;
        ctx2.Dr7 = NULL;
        ctx2.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        LI_FN( NtSetContextThread ).nt_cached( )( NtCurrentThread, &ctx2 );
        MessageBoxA( 0, std::to_string( __LINE__ ).c_str( ), "", MB_OK );

        return FALSE;
    }

#pragma optimize("", off)
    /*
    Detect   HyperHide and need check windows >= 8.1+
    https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L624
    */
    __declspec( noinline ) auto is_system_debug_control_hook( ) -> bool
    {
        auto nt_status = LI_FN( NtSystemDebugControl ).nt_cached( )( ( SYSDBG_COMMAND ) 0x25, NULL, NULL, NULL, NULL, NULL );

        if ( util::get_windows_number( ) >= WINDOWS_NUMBER_10 && nt_status == STATUS_DEBUGGER_INACTIVE )
            return TRUE;

        return FALSE;
    }
#pragma optimize("", on)

    /*
    Detect TitanHide, SharpOD  and ScyllaHide (+ break ScyllaHide)
    https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ps/psquery.c#L2784=
    can add check by  OpenProcess with PROCESS_TERMINATE
    */
    __declspec( noinline ) auto is_debug_flag_hooked( ) -> bool
    {
        HANDLE bug_handle = NULL;
        uint32_t debug_flag = NULL;
        uint32_t  safe_value = NULL;
        NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

        //Crash ScyllaHide 
        auto NtSetInformationProcess = ( t_NtSetInformationProcess ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "NtSetInformationProcess" ) );
        auto NtQueryInformationProcess = ( t_NtQueryInformationProcess ) ApiWrapper::GetProcAddress( _( L"ntdll.dll" ), _( "NtQueryInformationProcess" ) );

        nt_status = NtSetInformationProcess( NtCurrentProcess, processdebugflags, reinterpret_cast< PVOID >( 1 ), sizeof( debug_flag ) );
        if ( NT_SUCCESS( nt_status ) )
            return TRUE;

        bug_handle = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, ( DWORD ) nt_current_teb( )->ClientId.UniqueProcess );
        if ( bug_handle )
        {
            nt_status = NtSetInformationProcess( bug_handle, processdebugflags, &debug_flag, sizeof( debug_flag ) );
            LI_FN( NtClose ).nt_cached( )( bug_handle );
            if ( NT_SUCCESS( nt_status ) )
                return TRUE;
        }

        nt_status = NtQueryInformationProcess( NtCurrentProcess, processdebugflags, &debug_flag, sizeof( debug_flag ), NULL );
        safe_value = debug_flag; //Safe value for present some problem 

        if ( !NT_SUCCESS( nt_status ) )
            return FALSE;

        debug_flag = !debug_flag;

        nt_status = NtSetInformationProcess( NtCurrentProcess, processdebugflags, &debug_flag, sizeof( debug_flag ) );

        //Can't set value
        if ( !NT_SUCCESS( nt_status ) )
            return FALSE;

        nt_status = NtQueryInformationProcess( NtCurrentProcess, processdebugflags, &debug_flag, sizeof( debug_flag ), NULL );

        if ( NT_SUCCESS( nt_status ) && debug_flag != NULL )
            return TRUE;

        NtSetInformationProcess( NtCurrentProcess, processdebugflags, &safe_value, sizeof( safe_value ) );
        return FALSE;
    }

    ///*
    //Detect SharpOD,ScyllaHide,TitanHide,HyperHide
    //*/
    //__declspec( noinline ) auto is_bad_close_handle( ) -> bool
    //{
    //    bool is_bad_close_detect = FALSE;
    //    HANDLE dublicate_handle = NULL;
    //    NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
    //    PROCESS_HANDLE_TRACING_ENABLE tracing_handle = { 0 };
    //    OBJECT_HANDLE_FLAG_INFORMATION ObjectInformation = { 0 };

    //    __try
    //    {
    //        LI_FN( NtClose ).nt_cached( )( ( HANDLE ) ( L"I_love_colby_<3" ) );
    //    }
    //    __except ( EXCEPTION_EXECUTE_HANDLER )
    //    {
    //        return TRUE;
    //    }

    //    __try
    //    {
    //        ObjectInformation.ProtectFromClose = TRUE;
    //        LI_FN( NtDuplicateObject ).nt_cached( )( NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &dublicate_handle, NULL, FALSE, NULL );
    //        LI_FN( NtSetInformationObject ).nt_cached( )( dublicate_handle, ObjectHandleFlagInformation, &ObjectInformation, sizeof( OBJECT_HANDLE_FLAG_INFORMATION ) );
    //        LI_FN( NtDuplicateObject ).nt_cached( )( NtCurrentProcess, dublicate_handle, NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_CLOSE_SOURCE );
    //    }
    //    __except ( EXCEPTION_EXECUTE_HANDLER )
    //    {
    //        return TRUE;
    //    }
    //    ObjectInformation.ProtectFromClose = FALSE;
    //    LI_FN( NtSetInformationObject ).nt_cached( )( dublicate_handle, ObjectHandleFlagInformation, &ObjectInformation, sizeof( OBJECT_HANDLE_FLAG_INFORMATION ) );
    //    LI_FN( NtClose ).nt_cached( )( dublicate_handle );

    //    //Emable tracing
    //    nt_status = LI_FN( NtSetInformationProcess ).nt_cached( )( NtCurrentProcess, ProcessHandleTracing, &tracing_handle, sizeof( PROCESS_HANDLE_TRACING_ENABLE ) );
    //    if ( !NT_SUCCESS( nt_status ) )
    //        return FALSE;
    //    __try
    //    {
    //        LI_FN( NtClose ).nt_cached( )( ( HANDLE ) ( L"I_love_colby_<3" ) );
    //        is_bad_close_detect = TRUE;
    //    }
    //    __except ( EXCEPTION_EXECUTE_HANDLER )
    //    {
    //        is_bad_close_detect = FALSE;
    //    }
    //    __try
    //    {
    //        ObjectInformation.ProtectFromClose = TRUE;
    //        LI_FN( NtDuplicateObject ).nt_cached( )( NtCurrentProcess, NtCurrentProcess, NtCurrentProcess, &dublicate_handle, NULL, FALSE, NULL );
    //        LI_FN( NtSetInformationObject ).nt_cached( )( dublicate_handle, ObjectHandleFlagInformation, &ObjectInformation, sizeof( OBJECT_HANDLE_FLAG_INFORMATION ) );
    //        LI_FN( NtDuplicateObject ).nt_cached( )( NtCurrentProcess, dublicate_handle, NtCurrentProcess, &dublicate_handle, NULL, FALSE, DUPLICATE_CLOSE_SOURCE );
    //        is_bad_close_detect = TRUE;
    //    }
    //    __except ( EXCEPTION_EXECUTE_HANDLER )
    //    {
    //        is_bad_close_detect = FALSE;
    //    }
    //    ObjectInformation.ProtectFromClose = FALSE;
    //    LI_FN( NtSetInformationObject ).nt_cached( )( dublicate_handle, ObjectHandleFlagInformation, &ObjectInformation, sizeof( OBJECT_HANDLE_FLAG_INFORMATION ) );
    //    LI_FN( NtClose ).nt_cached( )( dublicate_handle );

    //    //Disable tracing
    //    nt_status = LI_FN( NtSetInformationProcess ).nt_cached( )( NtCurrentProcess, ProcessHandleTracing, &tracing_handle, NULL );

    //    return is_bad_close_detect;
    //}



    ///*
    //HyperHide bug:https://github.com/Air14/HyperHide/blob/11d9ebc7ce5e039e890820f8712e3c678f800370/HyperHideDrv/HookedFunctions.cpp#L594
    //ScyllaHide bug:https://github.com/x64dbg/ScyllaHide/blob/2276f1477132e99c96f31552bce7b4d2925fb918/HookLibrary/HookedFunctions.cpp#L1041
    //TitanHide bug:https://github.com/mrexodia/TitanHide/blob/77337790dac809bde3ff8d739deda24d67979668/TitanHide/hooks.cpp#L426
    //SharpOD -  detect
    //https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiDebug/NtQueryObject_AllTypesInformation.cpp
    //Explanation: we create a debug object, but go through all the objects and
    //if their number is less than 1 (we created at least 1), then there is a hook
    //*/
    //__declspec( noinline ) auto is_bad_number_object_system( ) -> bool
    //{
    //    HANDLE debug_object = NULL;
    //    uint8_t* object_location = NULL;
    //    uint64_t number_debug_object_system = NULL;
    //    uint64_t number_debug_handle_system = NULL;
    //    uint64_t number_debug_object_process = NULL;
    //    uint64_t number_debug_handle_process = NULL;
    //    uint64_t tmp = NULL;
    //    ULONG lenght = NULL;
    //    PVOID buffer = NULL;
    //    NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
    //    OBJECT_ATTRIBUTES object_attrib;
    //    POBJECT_TYPE_INFORMATION object_process = NULL;
    //    POBJECT_TYPE_INFORMATION object_type_info = NULL;
    //    POBJECT_ALL_INFORMATION  object_all_info = NULL;

    //    InitializeObjectAttributes( &object_attrib, NULL, NULL, NULL, NULL );
    //    nt_status = LI_FN( NtCreateDebugObject ).nt_cached( )( &debug_object, DEBUG_ALL_ACCESS, &object_attrib, 0 );
    //    if ( NT_SUCCESS( nt_status ) )
    //    {
    //        //TitanHide very bad hook https://github.com/mrexodia/TitanHide/blob/fb7085e5956bc04c4e3add3fbaf73b1bcd432728/TitanHide/hooks.cpp#L397

    //        //Get correct lenght
    //        nt_status = LI_FN( NtQueryObject ).nt_cached( )( debug_object, ObjectTypeInformation, &lenght, sizeof( ULONG ), &lenght );

    //        buffer = VirtualAlloc( NULL, lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    //        if ( buffer == NULL )
    //        {
    //            LI_FN( NtClose ).nt_cached( )( debug_object );
    //            return FALSE;
    //        }
    //        nt_status = LI_FN( NtQueryObject ).nt_cached( )( debug_object, ObjectTypeInformation, buffer, lenght, &lenght );
    //        object_process = reinterpret_cast< POBJECT_TYPE_INFORMATION >( buffer );
    //        //SharpOD don't hook ObjectTypeInformation
    //        if ( object_process->TotalNumberOfObjects != 1 && util::wstricmp( L"DebugObject", object_process->TypeName.Buffer ) == NULL )
    //        {
    //            VirtualFree( buffer, NULL, MEM_RELEASE );
    //            LI_FN( NtClose ).nt_cached( )( debug_object );
    //            return TRUE;
    //        }
    //        number_debug_handle_process = object_process->TotalNumberOfHandles;
    //        number_debug_object_process = object_process->TotalNumberOfObjects;
    //        VirtualFree( buffer, NULL, MEM_RELEASE );

    //        //Get correct lenght
    //        nt_status = LI_FN( NtQueryObject ).nt_cached( )( NULL, ObjectTypesInformation, &lenght, sizeof( ULONG ), &lenght );

    //        buffer = VirtualAlloc( NULL, lenght, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );
    //        if ( buffer == NULL )
    //        {
    //            LI_FN( NtClose ).nt_cached( )( debug_object );
    //            return FALSE;
    //        }
    //        //https://github.com/HighSchoolSoftwareClub/Windows-Research-Kernel-WRK-/blob/26b524b2d0f18de703018e16ec5377889afcf4ab/WRK-v1.2/base/ntos/ob/obquery.c#L406
    //        nt_status = LI_FN( NtQueryObject ).nt_cached( )( NtCurrentProcess, ObjectTypesInformation, buffer, lenght, NULL );

    //        if ( !NT_SUCCESS( nt_status ) )
    //        {
    //            LI_FN( NtClose ).nt_cached( )( debug_object );
    //            VirtualFree( buffer, NULL, MEM_RELEASE );
    //            return FALSE;
    //        }

    //        object_all_info = reinterpret_cast< POBJECT_ALL_INFORMATION >( buffer );
    //        object_location = reinterpret_cast< UCHAR* >( object_all_info->ObjectTypeInformation );
    //        for ( ULONG i = NULL; i < object_all_info->NumberOfObjectsTypes; i++ )
    //        {
    //            object_type_info = reinterpret_cast< POBJECT_TYPE_INFORMATION >( object_location );

    //            // The debug object will always be present
    //            if ( util::wstricmp( L"DebugObject", object_type_info->TypeName.Buffer ) == NULL )
    //            {
    //                if ( object_type_info->TotalNumberOfObjects > NULL )
    //                    number_debug_object_system += object_type_info->TotalNumberOfObjects;
    //                if ( object_type_info->TotalNumberOfHandles > NULL )
    //                    number_debug_handle_system += object_type_info->TotalNumberOfHandles;
    //            }

    //            object_location = ( uint8_t* ) object_type_info->TypeName.Buffer;
    //            object_location += object_type_info->TypeName.MaximumLength;
    //            tmp = ( ( uint64_t ) object_location ) & -( int ) sizeof( void* );

    //            if ( ( uint64_t ) tmp != ( uint64_t ) object_location )
    //                tmp += sizeof( PVOID );
    //            object_location = ( ( uint8_t* ) tmp );
    //        }
    //        VirtualFree( buffer, NULL, MEM_RELEASE );
    //        LI_FN( NtClose ).nt_cached( )( debug_object );
    //        return  number_debug_object_system < 1 ||
    //            number_debug_object_system < number_debug_object_process ||
    //            number_debug_handle_system < number_debug_handle_process;
    //    }
    //    return FALSE;
    //}

}
#endif // !ANTI_DEBUG_TOOL
