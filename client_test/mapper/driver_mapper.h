#pragma once

#include "intel_wrapper.h"

namespace drv_mapper
{
	bool map_driver( );
	uint64_t alloc_import( uint64_t address, uint64_t hash );
}