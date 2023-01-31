#pragma once
#include <windows.h>
#include <intrin.h>

#include <cstdint>

namespace fusion::encrypt
{
	void crypt( void* buf, void** crypted, size_t size );
	void decrypt( void* buf, void** decrypted, size_t size );

}