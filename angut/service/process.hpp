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
}
