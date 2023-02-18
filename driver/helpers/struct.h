#pragma once

enum e_request_method
{
	_check_loaded = 0x228,

	/*injection methods*/
	_read = 0x854,
	_write = 0x747,
	_alloc = 0x2048,
	_free = 0x1488,
	_protect_1 = 0x34858,
	_protect_2 = 0x34859,
	_base = 0x342,
	_call_entry = 0x2874,

	/*driver methods*/
	_init = 0x8324,
	_unload = 0x8361,

	/*security methods*/
	_protect_process = 0x87459,
	_hide_process = 0x50653
};

struct base_request_t
{
	int process_id;
	const char* module_name;
	uintptr_t address;
};

struct driver_request_t
{
	e_request_method request_method;
};

struct read_memory_t
{
	HANDLE process_id;
	void* address;
	void* buffer;
	size_t size;
};

struct write_memory_t
{
	HANDLE process_id;
	void* address;
	void* buffer;
	size_t size;

	size_t return_size;
};

struct process_request_t
{
	int process_id;
};


struct alloc_memory_t
{
	int process_id;

	uintptr_t address;
	size_t size;
};

struct free_memory_t
{
	int process_id;

	uintptr_t address;
	size_t size;
};

struct protect_memory_t
{
	HANDLE process_id;
	PVOID address;
	size_t size;
	int protect_type;
};

struct init_data_t
{
	bool success;
};

struct thread_init_t
{
	HANDLE game_handle;
	
	void* address;
};

struct entry_call_t
{
	HANDLE process_id;
	uintptr_t address;
	uintptr_t shellcode;

	bool result;
};