#pragma once
#include "../syscall/syscall.h"

#include <Windows.h>
#include <cstdint>
#include <type_traits>

#include <string>

typedef struct _COPY_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t source;
	uint64_t destination;
	uint64_t length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef struct _FILL_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint32_t value;
	uint32_t reserved2;
	uint64_t destination;
	uint64_t length;
}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;
}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

typedef struct _RTL_BALANCED_LINKS
{
	struct _RTL_BALANCED_LINKS* Parent;
	struct _RTL_BALANCED_LINKS* LeftChild;
	struct _RTL_BALANCED_LINKS* RightChild;
	CHAR Balance;
	UCHAR Reserved[ 3 ];
} RTL_BALANCED_LINKS;
typedef RTL_BALANCED_LINKS* PRTL_BALANCED_LINKS;

typedef struct _SYSTEM_HANDLE
{
	PVOID Object;
	HANDLE m_unique_process_id;
	HANDLE HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR m_handle_count;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE Handles[ 1 ];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum class _POOL_TYPE
{
	NonPagedPool,
	NonPagedPoolExecute,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolBase,
	NonPagedPoolBaseMustSucceed,
	NonPagedPoolBaseCacheAligned,
	NonPagedPoolBaseCacheAlignedMustS,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession,
	NonPagedPoolNx,
	NonPagedPoolNxCacheAligned,
	NonPagedPoolSessionNx
} POOL_TYPE;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE m_section;
	PVOID m_mapped_base;
	PVOID m_image_base;
	ULONG m_image_size;
	ULONG m_flags;
	USHORT m_load_order_index;
	USHORT m_init_order_index;
	USHORT m_load_count;
	USHORT m_offset_to_file_name;
	UCHAR m_full_path_name[ 256 ];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ 1 ];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

class c_intel_wrapper
{
public:
	bool load( );
	bool unload( );

	bool copy_memory( uint64_t dst, uint64_t src, size_t size );
	bool read_memory( uint64_t address, void* buffer, size_t size );
	bool write_memory( uint64_t address, void* buffer, size_t size );

	uint64_t	get_kernel_export( uint64_t module_address, uint64_t function_hash );
	bool		write_to_read_only( uint64_t address, void* buffer, uint32_t size );
	uint64_t	get_physical_address( uint64_t address );

	uint64_t	map_io_space( uint64_t physical_address, uint32_t size );
	bool		unmap_io_space( uint64_t address, uint32_t size );

	uint64_t	allocate_pool( POOL_TYPE type, uint64_t size, uint32_t tag = 'huy1' );
	bool		free_pool( uint64_t address, uint32_t tag = 'huy1' );

	uint64_t get_kernel_module_base( const char* mod_name );

	template< typename _ty, typename ...args >
	bool call_function_at_kernel( _ty* out_result, uint64_t address_at_kernel, const args... arguments )
	{
		constexpr auto is_void_call = std::is_same_v< _ty, void >;

		if constexpr ( !is_void_call )
		{
			if ( !out_result )
				return false;
		}
		else
		{
			UNREFERENCED_PARAMETER( out_result );
		}

		if ( !address_at_kernel )
			return false;

		uint8_t jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		static uint8_t orig_bytes[ sizeof( jmp ) ];
		*reinterpret_cast< uint64_t* >( &jmp[ 2 ] ) = address_at_kernel;

		static uint64_t nt_shutdown_system = 0;

		if ( !nt_shutdown_system )
		{
			nt_shutdown_system = get_kernel_export( get_kernel_module_base( _( "ntoskrnl.exe" ) ), HASH( "NtAddAtom" ) );
			if ( !nt_shutdown_system )
				return 0;

			if ( !read_memory( nt_shutdown_system, orig_bytes, sizeof( jmp ) ) )
				return 0;
		}

		if ( *reinterpret_cast< uint16_t* >( jmp ) == *reinterpret_cast< uint16_t* >( orig_bytes ) &&
			*reinterpret_cast< uint16_t* >( &jmp[ sizeof( jmp ) - 2 ] ) == *reinterpret_cast< uint16_t* >( &orig_bytes[ sizeof( jmp ) - 2 ] ) )
			return 0;

		if ( !write_to_read_only( nt_shutdown_system, jmp, sizeof( jmp ) ) )
			return false;

		if constexpr ( !is_void_call )
			*out_result = fusion::syscall::sys_call< _ty, args... >( HASH( "NtAddAtom" ), arguments... );
		else
			fusion::syscall::sys_call< void, args... >( HASH( "NtAddAtom" ), arguments... );

		write_to_read_only( nt_shutdown_system, orig_bytes, sizeof( jmp ) );
		return true;
	}

	HANDLE m_driver;
	wchar_t m_driver_name[ 14 ];
	wchar_t m_full_path[ MAX_PATH ];
	wchar_t m_driver_registry_path[ MAX_PATH ];
	wchar_t m_serv_path[ MAX_PATH ];
};

inline c_intel_wrapper* g_intel_wrapper = nullptr;