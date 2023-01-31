#pragma once

#include "intel_wrapper.h"

namespace drv_mapper
{
	bool map_driver( const char* key );
	uint64_t alloc_import( uint64_t address, uint64_t hash );
}