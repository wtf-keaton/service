#pragma once

class c_globals
{
public:
	bool active = true;
	bool is_loaded = false;

	char status[ 256 ];
	char error[ 256 ];
	char process_name[ 256 ];

	int inject_status = -1;
	float value = 0.f;
};

inline c_globals globals;

enum e_page_state
{
	_auth,
	_loading_bar,
	_inject,
	_error
};

enum e_injection_state
{
	_none = -1,
	_loading,
	_progress,
	_parse_imports,
	_injection,
	_injected
};