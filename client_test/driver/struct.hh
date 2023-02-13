#pragma once
#include <cstdint>

constexpr std::uintptr_t secret_key = 0x3a9fdb6;

enum operation_type
{
	operation_read = 0, // Чтение памяти
	operation_write, // Запись памяти
	operation_base, // Получение бейз адреса процесса
	operation_module_base, // Получение бейз адреса по имени модуля
	operation_protect,
	operation_allocate, // Обычное выделение памяти в драйвере
	operation_allocatenx, // Выделение памяти с RW+NX 
	operation_free // Освобождение памяти
};

struct operation
{
	std::uintptr_t virtual_address;
	std::uintptr_t size;
	std::uintptr_t buffer;
	std::uint32_t new_protection;
	std::uint32_t old_protection;
	const char* module_name;
	operation_type type;
};

struct operation_command
{
	std::uintptr_t local_id;
	std::uintptr_t remote_id;
	std::uintptr_t serial_key;
	const char* filepath;
	operation operation;
	std::uintptr_t operation_address;
};

inline uintptr_t proc_id{};