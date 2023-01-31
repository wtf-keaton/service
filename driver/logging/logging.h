#pragma once

namespace fusion::logging
{
    void message( char* text )
    {
        UNICODE_STRING     uniName;
        OBJECT_ATTRIBUTES  objAttr;

        RtlInitUnicodeString( &uniName, _( L"\\DosDevices\\C:\\fusion.log" ) );  // or L"\\SystemRoot\\example.txt"
        InitializeObjectAttributes( &objAttr, &uniName,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            NULL, NULL );

        HANDLE   handle;
        NTSTATUS ntstatus;
        IO_STATUS_BLOCK    ioStatusBlock;

        // Do not try to perform any file operations at higher IRQL levels.
        // Instead, you may use a work item or a system worker thread to perform file operations.

        if ( KeGetCurrentIrql( ) != PASSIVE_LEVEL ) return;
        //return STATUS_INVALID_DEVICE_STATE;

        ntstatus = ZwCreateFile( &handle,
            GENERIC_WRITE,
            &objAttr, &ioStatusBlock, NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN_IF,
            FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0 );

        CHAR     buffer[ 30 ];
        size_t  cb;

        if ( NT_SUCCESS( ntstatus ) )
        {
            ntstatus = RtlStringCbPrintfA( buffer, sizeof( buffer ), text, 0x0 );
            if ( NT_SUCCESS( ntstatus ) )
            {
                ntstatus = RtlStringCbLengthA( buffer, sizeof( buffer ), &cb );
                if ( NT_SUCCESS( ntstatus ) )
                {
                    ntstatus = ZwWriteFile( handle, NULL, NULL, NULL, &ioStatusBlock,
                        buffer, ( ULONG ) cb, NULL, NULL );
                }
            }
            ZwClose( handle );
        }
    }
}