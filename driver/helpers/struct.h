#pragma once

enum e_request_method
{
	_read = 0x854,
	_write = 0x747,
	_alloc = 0x2048,
	_free = 0x1488,
	_base = 0x342,
	_thread = 0x2874,
	_init = 0x8324,
	_unload = 0x8361
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
};

struct alloc_memory_t
{

};

struct free_memory_t
{

};

struct init_data_t
{
	bool test;
};

struct thread_init_t
{
	HANDLE game_handle;
	
	void* address;
};