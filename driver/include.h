#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#pragma once( lib, "ntstrsafe.lib" )
//#define DEBUG_OUTPUT

#ifdef DEBUG_OUTPUT
#define TRACE(str, ...) DbgPrintEx(0, 0, str"\n", __VA_ARGS__)
#else
#define TRACE(...)
#endif

#include "vcruntime/cstdint.h"
#include "pe/pe.h"
#include "exports/exports.h"
#include "helpers/struct.h"

#include "xorstr/xorstr.h"
#include "hash/hash.h"

#include "vcruntime/string.h"
#include "winapi/winapi.h"

#include "imports/imports.h"

#include "memory/memory.h"

#include "logging/logging.h"

#include "security/hide_process.h"
#include "security/protect_process.h"

#include "hook/function.h"

#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))