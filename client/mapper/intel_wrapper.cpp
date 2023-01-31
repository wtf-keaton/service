
#include "intel_wrapper.h"
#include "driver.h"

#include <Windows.h>
#include <ctime>
#include <fstream>
#include <string>

#include <winternl.h>

#include <unordered_map>

bool c_intel_wrapper::load( )
{
	m_driver = CreateFileW( _( L"\\\\.\\Nal" ), 0, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );

	if ( m_driver && m_driver != INVALID_HANDLE_VALUE )
	{
		fusion::syscall::printf( _( "ERROR[92] FAILED TO START SPOOFER, CONTACT SUPPORT\n" ) );

		fusion::syscall::sys_call< NTSTATUS, HANDLE >( HASH( "NtClose" ), m_driver );
		return false;
	}

	srand( time( nullptr ) );
	for ( int i = 0; i < 14; ++i )
		m_driver_name[ i ] = static_cast< wchar_t >( ( int ) L'A' + rand( ) % 26 );
	m_driver_name[ 13 ] = 0;

	wchar_t temp_path[ MAX_PATH ];

	GetTempPathW( MAX_PATH, temp_path );

	wsprintfW( m_full_path, _( L"%s%s" ), temp_path, m_driver_name );

	DeleteFileW( m_full_path );

	std::ofstream file( m_full_path, std::ios::out | std::ios::binary );
	file.write( reinterpret_cast< const char* >( fusion::intel_drv::driver ), sizeof( fusion::intel_drv::driver ) );
	file.close( );

	__stosb( ( uint8_t* ) ( fusion::intel_drv::driver ), 0, sizeof( fusion::intel_drv::driver ) );

	HKEY reg_key;
	wcscpy_s( m_serv_path, std::wstring( std::wstring( _( L"SYSTEM\\CurrentControlSet\\Services\\" ) ) + m_driver_name ).c_str( ) );

	if ( RegCreateKeyW( HKEY_LOCAL_MACHINE, m_serv_path, &reg_key ) )
	{
		fusion::syscall::printf( _( "ERROR[86] UNKNOWN ERROR\n" ) );
		DeleteFileW( m_full_path );
		return false;
	}

	std::wstring image_path = std::wstring( _( L"\\??\\" ) ) + m_full_path;
	if ( RegSetKeyValueW( reg_key, nullptr, _( L"ImagePath" ), REG_EXPAND_SZ, image_path.c_str( ), image_path.size( ) * sizeof( wchar_t ) ) )
	{
		fusion::syscall::printf( _( "ERROR[87] UNKNOWN ERROR\n" ) );
		DeleteFileW( m_full_path );
		RegCloseKey( reg_key );
		return false;
	}

	unsigned long type_kernel = 1;

	if ( RegSetKeyValueW( reg_key, nullptr, _( L"Type" ), REG_DWORD, &type_kernel, sizeof( unsigned long ) ) )
	{
		fusion::syscall::printf( _( "ERROR[88] UNKNOWN ERROR\n" ) );
		DeleteFileW( m_full_path );
		RegCloseKey( reg_key );
		return false;
	}

	RegCloseKey( reg_key );

	wcscpy_s( m_driver_registry_path, std::wstring( std::wstring( _( L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" ) ) + m_driver_name ).c_str( ) );
	UNICODE_STRING driver_registry_path;
	RtlInitUnicodeString( &driver_registry_path, m_driver_registry_path );

	BOOLEAN old_priv = FALSE;
	if ( !NT_SUCCESS( RtlAdjustPrivilege( 10, TRUE, FALSE, &old_priv ) ) )
	{
		fusion::syscall::printf( _( "ERROR[89] UNKNOWN ERROR\n" ) );
		DeleteFileW( m_full_path );
		return false;
	}

	NTSTATUS load_status = fusion::syscall::sys_call< NTSTATUS, UNICODE_STRING* >( HASH( "NtLoadDriver" ), &driver_registry_path );
	if ( !NT_SUCCESS( ( load_status ) ) )
	{
		fusion::syscall::printf( _( "ERROR[90] FAILED TO LOAD DRIVER\n" ) );

		DeleteFileW( m_full_path );
		return false;
	}

	m_driver = CreateFileW( _( L"\\\\.\\Nal" ), 0, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
	if ( !m_driver || m_driver == INVALID_HANDLE_VALUE )
	{
		fusion::syscall::printf( _( "ERROR[91] UNKNOWN ERROR\n" ) );
		DeleteFileW( m_full_path );
		return false;
	}

	return true;
}

bool c_intel_wrapper::unload( )
{
	if ( m_driver && m_driver != INVALID_HANDLE_VALUE )
		fusion::syscall::sys_call< NTSTATUS, HANDLE >( HASH( "NtClose" ), m_driver );

	BOOLEAN old_priv = FALSE;
	if ( !NT_SUCCESS( RtlAdjustPrivilege( 10, TRUE, FALSE, &old_priv ) ) )
	{
		DeleteFileW( m_full_path );
		return false;
	}

	UNICODE_STRING driver_registry_path;
	RtlInitUnicodeString( &driver_registry_path, m_driver_registry_path );

	if ( !NT_SUCCESS( ( fusion::syscall::sys_call< NTSTATUS, UNICODE_STRING* >( HASH( "NtUnloadDriver" ), &driver_registry_path ) ) ) )
		return false;

	DeleteFileW( m_full_path );

	return RegDeleteKeyW( HKEY_LOCAL_MACHINE, m_serv_path ) == ERROR_SUCCESS;
}

bool c_intel_wrapper::copy_memory( uint64_t dst, uint64_t src, size_t size )
{
	COPY_MEMORY_BUFFER_INFO buf;
	__stosb( reinterpret_cast< PBYTE >( &buf ), 0, sizeof( buf ) );

	buf.case_number = 0x33;
	buf.source = src;
	buf.destination = dst;
	buf.length = size;

	uint32_t bytes_returned = 0;
	return fusion::syscall::device_io_control( m_driver, 0x80862007, &buf, sizeof( buf ), nullptr, 0, &bytes_returned );
}

bool c_intel_wrapper::read_memory( uint64_t address, void* buffer, size_t size )
{
	return copy_memory( reinterpret_cast< uint64_t >( buffer ), address, size );
}

bool c_intel_wrapper::write_memory( uint64_t address, void* buffer, size_t size )
{
	return copy_memory( address, reinterpret_cast< uint64_t >( buffer ), size );
}

uint64_t c_intel_wrapper::get_kernel_export( uint64_t module_address, uint64_t function_hash )
{
	if ( !module_address )
		return 0;

	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;

	if ( !read_memory( module_address, &dos, sizeof( IMAGE_DOS_HEADER ) ) || dos.e_magic != IMAGE_DOS_SIGNATURE ||
		!read_memory( module_address + dos.e_lfanew, &nt, sizeof( IMAGE_NT_HEADERS ) ) || nt.Signature != IMAGE_NT_SIGNATURE )
		return 0;

	IMAGE_EXPORT_DIRECTORY* export_directory = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( malloc( nt.OptionalHeader.DataDirectory[ 0 ].Size ) );

	if ( !export_directory )
		return 0;

	if ( !read_memory( module_address + nt.OptionalHeader.DataDirectory[ 0 ].VirtualAddress, export_directory, nt.OptionalHeader.DataDirectory[ 0 ].Size ) )
	{
		free( export_directory );
		return 0;
	}

	uint64_t delta = reinterpret_cast< uint64_t >( export_directory ) - nt.OptionalHeader.DataDirectory[ 0 ].VirtualAddress;

	uint32_t* functions = reinterpret_cast< uint32_t* >( export_directory->AddressOfFunctions + delta );
	uint32_t* names = reinterpret_cast< uint32_t* >( export_directory->AddressOfNames + delta );
	uint16_t* ordinals = reinterpret_cast< uint16_t* >( export_directory->AddressOfNameOrdinals + delta );

	for ( uint32_t i = 0; i < export_directory->NumberOfNames; ++i )
	{
		if ( HASH( reinterpret_cast< const char* >( names[ i ] + delta ) ) == function_hash )
		{
			uint64_t address = module_address + functions[ ordinals[ i ] ];
			free( export_directory );
			return address;
		}
	}

	free( export_directory );
	return 0;
}

bool c_intel_wrapper::write_to_read_only( uint64_t address, void* buffer, uint32_t size )
{
	uint64_t physical_address = get_physical_address( address );
	if ( !physical_address )
		return false;

	uint64_t mapped_physical_mem = map_io_space( physical_address, size );
	if ( !mapped_physical_mem )
		return false;

	bool result = write_memory( mapped_physical_mem, buffer, size );

	unmap_io_space( mapped_physical_mem, size );
	return result;
}

uint64_t c_intel_wrapper::get_physical_address( uint64_t address )
{
	GET_PHYS_ADDRESS_BUFFER_INFO buf;
	__stosb( reinterpret_cast< PBYTE >( &buf ), 0, sizeof( buf ) );

	buf.address_to_translate = address;
	buf.case_number = 0x25;

	uint32_t bytes_returned = 0;
	if ( !fusion::syscall::device_io_control( m_driver, 0x80862007, &buf, sizeof( buf ), nullptr, 0, &bytes_returned ) )
		return 0;

	return buf.return_physical_address;
}

uint64_t c_intel_wrapper::map_io_space( uint64_t physical_address, uint32_t size )
{
	MAP_IO_SPACE_BUFFER_INFO buf;
	__stosb( reinterpret_cast< PBYTE >( &buf ), 0, sizeof( buf ) );

	buf.case_number = 0x19;
	buf.physical_address_to_map = physical_address;
	buf.size = size;

	uint32_t bytes_returned = 0;
	if ( !fusion::syscall::device_io_control( m_driver, 0x80862007, &buf, sizeof( buf ), nullptr, 0, &bytes_returned ) )
		return 0;

	return buf.return_virtual_address;
}

bool c_intel_wrapper::unmap_io_space( uint64_t address, uint32_t size )
{
	UNMAP_IO_SPACE_BUFFER_INFO buf;
	__stosb( reinterpret_cast< PBYTE >( &buf ), 0, sizeof( buf ) );

	buf.case_number = 0x1a;
	buf.virt_address = address;
	buf.number_of_bytes = size;

	uint32_t bytes_returned = 0;
	return fusion::syscall::device_io_control( m_driver, 0x80862007, &buf, sizeof( buf ), nullptr, 0, &bytes_returned );
}

uint64_t c_intel_wrapper::allocate_pool( POOL_TYPE type, uint64_t size, uint32_t tag )
{
	static uint64_t ex_allocate_pool_with_tag = get_kernel_export( get_kernel_module_base( _( "ntoskrnl.exe" ) ), HASH( "ExAllocatePoolWithTag" ) );

	if ( !ex_allocate_pool_with_tag )
		return 0;

	uint64_t allocated_pool = 0;

	if ( !call_function_at_kernel( &allocated_pool, ex_allocate_pool_with_tag, type, size, tag ) )
		return 0;

	return allocated_pool;
}

bool c_intel_wrapper::free_pool( uint64_t address, uint32_t tag )
{
	static uint64_t ex_free_pool = get_kernel_export( get_kernel_module_base( _( "ntoskrnl.exe" ) ), HASH( "ExFreePoolWithTag" ) );

	return address && ex_free_pool && call_function_at_kernel< void >( nullptr, ex_free_pool, address, tag );
}

uint64_t c_intel_wrapper::get_kernel_module_base( const char* mod_name )
{
	static std::unordered_map< uint64_t, uint64_t > bases;

	if ( !bases.empty( ) && bases.find( HASH( mod_name ) ) != bases.end( ) )
		return bases[ HASH( mod_name ) ];

	unsigned long bytes = 0;
	fusion::syscall::sys_call< NTSTATUS, SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG* >( HASH( "NtQuerySystemInformation" ), ( SYSTEM_INFORMATION_CLASS ) 11, nullptr, bytes, &bytes );

	RTL_PROCESS_MODULES* buf = reinterpret_cast< RTL_PROCESS_MODULES* >( malloc( bytes ) );
	__stosb( reinterpret_cast< PBYTE >( buf ), 0, bytes );
	if ( !NT_SUCCESS( ( fusion::syscall::sys_call< NTSTATUS, SYSTEM_INFORMATION_CLASS, void*, ULONG, ULONG* >( HASH( "NtQuerySystemInformation" ), ( SYSTEM_INFORMATION_CLASS ) 11, buf, bytes, &bytes ) ) ) )
	{
		free( buf );
		unload( );
		return false;
	}

	uint64_t base = 0;

	for ( uint32_t i = 0; i < buf->NumberOfModules; ++i )
	{
		RTL_PROCESS_MODULE_INFORMATION& mod_info = buf->Modules[ i ];
		if ( !_stricmp( reinterpret_cast< char* >( mod_info.m_full_path_name + mod_info.m_offset_to_file_name ), mod_name ) )
		{
			base = reinterpret_cast< uint64_t >( mod_info.m_image_base );
			break;
		}
	}

	fusion::syscall::free( buf );

	if ( base )
		bases[ HASH( mod_name ) ] = base;

	return base;
}
