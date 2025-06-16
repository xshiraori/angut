#pragma once
#include <ntifs.h>
#include <cstdint>

namespace process {
	NTSTATUS create_handle_for_user(
		PEPROCESS caller,
		PEPROCESS target,
		ACCESS_MASK desired_access,
		PHANDLE out_handle
	);

	NTSTATUS get_process_base(std::uint32_t process_id, std::uint64_t& base_address);
}
