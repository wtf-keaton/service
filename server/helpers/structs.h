#pragma once
#include <cstdint>

enum e_request_type
{
	_authorization = 0,
	_get_binary,
	_get_user_information,
	_ban_user
};

enum e_request_result
{
	_success = 42316 << 1,
	_error_hwid_missmatch = 78326 << 1,
	_error_userkey = 2386 << 1,
	_error_subscribe_end = 8641 << 1,
	_error_banned = 9043 << 1,
};

enum e_binary_type
{
	_cheat = 0,
	_loader,
	_driver,
	_spoofer
};

// server request structs
struct binary_request_t
{
	char imports[ 1024 ];
	uintptr_t entry;
	uintptr_t size;
};

struct user_info_request_t
{
	char game[ 64 ];
	char end_date[ 32 ];
};

struct request_t
{
	e_request_type request_type;

	char key[ 32 ];
	uintptr_t active_hwid_hash;

	char user_pc_info[ 256 ];

	e_binary_type binary_type;
};

struct mapper_info_t
{
	uint64_t allocated_base;
};

// portable executable structs 
struct import_t
{
	const char* name;
	uint32_t rva;
};

struct section_t
{
	const char* name;
	size_t size;
	uint32_t rva;
	uint32_t va;
};