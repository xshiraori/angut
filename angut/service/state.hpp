#pragma once
#include <ntifs.h>
#include <cstdint>

class driver_state
{
public:
	static driver_state& get_instance()
	{
		static driver_state instance;
		return instance;
	}

public:
	std::uint32_t target_process_id;
};