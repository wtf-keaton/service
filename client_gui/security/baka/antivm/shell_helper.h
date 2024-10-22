#ifndef SYSCALL_HELPER

#define SYSCALL_HELPER 1  
#include <Windows.h>
#include <cstdint>

namespace shell_code_util
{

	class shell_code
	{
	private:
		PVOID shell_address = NULL;


	public:
		auto set_syscall( uint32_t syscall_number ) -> VOID
		{
			memcpy( reinterpret_cast< PVOID >( reinterpret_cast< uint64_t >( shell_address ) + 1 ), &syscall_number, 4 ); //set syscall
		}


		template<typename ret_status, typename... Args>
		auto call_shell( Args... args ) -> ret_status
		{
			auto fun = reinterpret_cast< PVOID( * )( Args... ) >( shell_address );
			return reinterpret_cast< ret_status >( fun( args... ) );
		}

		auto init_shell( uint8_t* shell_code = NULL, uint32_t size_shell = NULL ) -> bool
		{
			shell_address = VirtualAlloc( NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
			if ( shell_address == NULL )
				return FALSE;
			if ( shell_code && size_shell )
				memcpy( shell_address, shell_code, size_shell );
			return TRUE;
		}

		auto de_init_shell( ) -> VOID
		{
			if ( shell_address )
				VirtualFree( shell_address, NULL, MEM_RELEASE );
		}

	};
}
#endif // !SYSCALL_HELPER