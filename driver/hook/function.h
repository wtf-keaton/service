#pragma once

__int64( __fastcall* o_ntuserexcludeupdatergn )( PVOID, PVOID );
PBYTE address = 0x0;

__int64 __fastcall hk_ntuserexcludeupdatergn( PVOID a1, PVOID a2 )
{
	if ( ExGetPreviousMode( ) != UserMode )
	{
		return o_ntuserexcludeupdatergn( a1, a2 );
	}

	driver_request_t request{};
	if ( !fusion::memory::get_request_data( &request, a1, sizeof( driver_request_t ) ) )
	{
		return o_ntuserexcludeupdatergn( a1, a2 );
	}

	switch ( request.request_method )
	{
		case e_request_method::_check_loaded:
		{		
			auto init_request = reinterpret_cast< init_data_t* >( a2 );

			auto result = true;

			init_request->success = true;

			break;
		}
		case e_request_method::_read:
		{
			auto read_request = reinterpret_cast< read_memory_t* >( a2 );

			TRACE( "read_request->address = 0x%llx", read_request->address );
			TRACE( "read_request->buffer = 0x%llx", read_request->buffer );
			TRACE( "read_request->size = %d", read_request->size );
			TRACE( "read_request->process_id = 0x%x", read_request->process_id );

			void* buffer = nullptr;
			size_t bytes{};
			PEPROCESS target_process{};

			PsLookupProcessByProcessId( read_request->process_id, &target_process ); 

			if ( MmCopyVirtualMemory( target_process, read_request->address, IoGetCurrentProcess( ), read_request->buffer, read_request->size, KernelMode, &bytes ) != STATUS_SUCCESS || bytes != read_request->size )
			{
				ObDereferenceObject( target_process );
			}

			TRACE( "read_request->buffer = 0x%llx", read_request->buffer );

			ObDereferenceObject( target_process );

			break;

		}
		case e_request_method::_write:
		{
			auto write_request = reinterpret_cast< write_memory_t* >( a2 );


			TRACE( "write_request->address = 0x%llx", write_request->address );
			TRACE( "write_request->buffer = 0x%llx", write_request->buffer );
			TRACE( "write_request->size = %d", write_request->size );
			TRACE( "write_request->process_id = 0x%x", write_request->process_id );

			fusion::memory::write_memory( write_request->process_id, write_request->address, write_request->buffer, write_request->size );
			break;
		}
		case e_request_method::_base:
		{
			auto base_request = reinterpret_cast< base_request_t* >( a2 );

			uintptr_t address{};
			TRACE( "base_request: %s", base_request->module_name );

			if ( NT_SUCCESS( fusion::winapi::get_module_base_address( base_request->process_id, base_request->module_name, &address ) ) )
			{
				TRACE( "\"%s\" on process %d = 0x%llx", base_request->module_name, base_request->process_id, address );

				base_request->address = address;
			}
			else
			{
				TRACE( "failed to get \"%s\" on process %d", base_request->module_name, base_request->process_id );
			}
			break;
		}
		case e_request_method::_alloc:
		{

			break;
		}
		case e_request_method::_free:
		{

			break;
		}
		case e_request_method::_hide_process:
		{
			auto hide_request = reinterpret_cast< process_request_t* >( a2 );
			
			fusion::anti_debug::hide_process( hide_request->process_id );

			break;
		}
		case e_request_method::_protect_process:
		{
			auto protect_request = reinterpret_cast< process_request_t* >( a2 );

			fusion::anti_debug::protect_process( protect_request->process_id );
			break;
		}
		case e_request_method::_call_entry:
		{

			break;
		}
		case e_request_method::_unload:
		{
			InterlockedExchangePointer( ( void** ) address, ( void** ) o_ntuserexcludeupdatergn );
			break;
		}

		default: /*nope*/ break;
	}
	return NULL;
}
