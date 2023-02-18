#pragma once

__int64( __fastcall* o_ntuserexcludeupdatergn )( PVOID, PVOID );
PBYTE address = 0x0;
#pragma optimize("", off)

__int64 __fastcall hk_ntuserexcludeupdatergn( PVOID a1, PVOID a2 )
{

	if ( fusion::imports::ex_get_previous_mode( ) != UserMode )
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
			TRACE( "init_request->success = %x", init_request->success );

			init_request->success = true;

			TRACE( "init_request->success = %x", init_request->success );

			break;
		}
		case e_request_method::_read:
		{
			auto read_request = reinterpret_cast< read_memory_t* >( a2 );
			PVOID buffer = read_request->buffer;

			auto status = fusion::memory::read_memory( read_request->process_id, read_request->address, buffer, read_request->size );

			read_request->buffer = buffer;
			if ( !NT_SUCCESS( status ) )
			{
				TRACE( "status = 0x%llx", status );
			}

			break;

		}
		case e_request_method::_write:
		{
			auto write_request = reinterpret_cast< write_memory_t* >( a2 );


			TRACE( "write_request->address = 0x%llx", write_request->address );
			TRACE( "write_request->buffer = 0x%llx", write_request->buffer );
			TRACE( "write_request->size = %d", write_request->size );
			TRACE( "write_request->process_id = 0x%x", write_request->process_id );

			auto status = fusion::memory::write_memory( write_request->process_id, write_request->address, write_request->buffer, write_request->size );

			if ( !NT_SUCCESS( status ) )
			{
				TRACE( "status = 0x%llx", status );
			}

			TRACE( "status = 0x%llx", status );

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
			auto alloc_request = reinterpret_cast< alloc_memory_t* >( a2 );

			auto address = alloc_request->address;
			auto size = alloc_request->size;
			auto process_id = alloc_request->process_id;

			TRACE( "address = 0x%llx", alloc_request->address );
			TRACE( "size = 0x%llx", alloc_request->size );
			TRACE( "process_id = %d", alloc_request->process_id );

			KAPC_STATE apc_state{ };
			PEPROCESS process;
			if ( PsLookupProcessByProcessId( ( HANDLE ) process_id, &process ) == STATUS_SUCCESS )
			{
				KeStackAttachProcess( process, &apc_state );
				auto result = fusion::pte::allocate( size );

				KeUnstackDetachProcess( &apc_state );
				ObfDereferenceObject( process );

				alloc_request->address = result;
				TRACE( "alloc_request->address = 0x%llx", alloc_request->address );

			}
			break;
		}
		case e_request_method::_free:
		{
			auto free_request = reinterpret_cast< free_memory_t* >( a2 );

			auto address = free_request->address;
			auto size = free_request->size;
			auto process_id = free_request->process_id;

			KAPC_STATE apc_state{ };
			PEPROCESS process;
			if ( fusion::imports::ps_lookup_process_by_process_id( ( HANDLE ) process_id, &process ) == STATUS_SUCCESS )
			{
				fusion::imports::ke_stack_attach_process( process, &apc_state );
				{
					fusion::imports::nt_free_virtual_memory( ( ( HANDLE ) ( LONG_PTR ) -1 ), reinterpret_cast< PVOID* >( &address ), &size, MEM_RELEASE );
				}
				fusion::imports::ke_unstack_detach_process( &apc_state );
			}

			break;
		}

		case e_request_method::_protect_1:
		{
			auto protect_request = reinterpret_cast< protect_memory_t* >( a2 );
			auto address = protect_request->address;
			auto size = protect_request->size;
			auto process_id = protect_request->process_id;

			KAPC_STATE apc_state{ };
			PEPROCESS process{};
			if ( PsLookupProcessByProcessId( process_id, &process ) == STATUS_SUCCESS )
			{
				KeStackAttachProcess( process, &apc_state );
				{
					ULONG old_protect{};
					ZwProtectVirtualMemory( ( ( HANDLE ) ( LONG_PTR ) -1 ), &address, &size, PAGE_READWRITE, &old_protect );

				}
				KeUnstackDetachProcess( &apc_state );

			}
			break;
		}
		
		case e_request_method::_protect_2:
		{
			auto protect_request = reinterpret_cast< protect_memory_t* >( a2 );
			auto address = protect_request->address;
			auto size = protect_request->size;
			auto process_id = protect_request->process_id;

			KAPC_STATE apc_state{ };
			PEPROCESS process{};
			if ( PsLookupProcessByProcessId( process_id, &process ) == STATUS_SUCCESS )
			{
				KeStackAttachProcess( process, &apc_state );
				{
					ULONG old_protect{};
					ZwProtectVirtualMemory( ( ( HANDLE ) ( LONG_PTR ) -1 ), &address, &size, PAGE_READONLY, &old_protect );

				}
				KeUnstackDetachProcess( &apc_state );

			}
			break;
		}
		case e_request_method::_call_entry:
		{
			auto entry_request = reinterpret_cast< entry_call_t* >( a2 );

			auto address = reinterpret_cast<PVOID>( entry_request->address );
			auto shellcode = reinterpret_cast< PVOID >( entry_request->shellcode );
			auto process_id = entry_request->process_id;

			TRACE( "entry_request->address = 0x%llx", address );
			TRACE( "entry_request->shellcode = 0x%llx", shellcode );
			TRACE( "entry_request->process_id = %d", process_id );

			KAPC_STATE apc_state{ };
			PEPROCESS process{};
			bool result = false;

			if ( PsLookupProcessByProcessId( process_id, &process ) == STATUS_SUCCESS )
			{
				KeStackAttachProcess( process, &apc_state );
				{
					auto size = sizeof( uint64_t );

					ULONG old_protect{};
					ZwProtectVirtualMemory( ( ( HANDLE ) ( LONG_PTR ) -1 ), &address, &size, PAGE_READWRITE, &old_protect );
					if ( NT_SUCCESS( fusion::memory::write_memory( process_id, address, shellcode, sizeof( uint64_t ) ) ) )
					{
						if ( address != nullptr )
						{
							ZwProtectVirtualMemory( ( ( HANDLE ) ( LONG_PTR ) -1 ), &address, &size, PAGE_READONLY, &old_protect );
						}
						result = true;

					}
				}
				KeUnstackDetachProcess( &apc_state );

				entry_request->result = result;

			}
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
		case e_request_method::_unload:
		{
			InterlockedExchangePointer( ( void** ) address, ( void** ) o_ntuserexcludeupdatergn );
			break;
		}

		default: /*nope*/ break;
	}
	return NULL;
}

#pragma optimize("", on)
