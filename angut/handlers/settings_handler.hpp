#pragma once
#include <ssdt.hpp>
#include <hooks.hpp>

namespace ioctl::handler
{
	struct set_driver_settings_request
	{
		bool enable_syscall_hook;
	};

	void handle_set_driver_settings_request(
		set_driver_settings_request* req,
		size_t bufferLength,
		NTSTATUS& status,
		ULONG_PTR& info
	)
	{
		if (bufferLength < sizeof(set_driver_settings_request))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			return;
		}

		if (req->enable_syscall_hook)
		{
			o_NtQuerySystemInformation = memory::ssdt::get_function_by_entry<decltype(NtQuerySystemInformation_hook)>(0x36);
			if (!memory::ssdt::hook_single_entry(0x36, NtQuerySystemInformation_hook, o_NtQuerySystemInformation))
			{
				ang_debug("Failed to hook NtQuerySystemInformation!\n");
				status = STATUS_UNSUCCESSFUL;
			}
		}
		else
		{
			memory::ssdt::cleanup();
		}

		status = STATUS_SUCCESS;
		info = 0;
	}
}