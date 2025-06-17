#pragma once
#include <ntifs.h>
#include <cstdint>
#include "nt_internals.hpp"

static bool is_chosen_target(PEPROCESS process)
{
    if (!process)
        return false;

    const char* current_process_name = PsGetProcessImageFileName(process);
    return strstr(current_process_name, "KnightOnLine") != NULL;
}

namespace process {
	NTSTATUS create_handle_for_user(
		PEPROCESS caller,
		PEPROCESS target,
		ACCESS_MASK desired_access,
		PHANDLE out_handle
	);

	NTSTATUS get_process_base(std::uint32_t process_id, std::uint64_t& base_address);
}
