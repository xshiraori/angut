#include <utils.hpp>
#include <ntifs.h>
#include "memory.hpp"

namespace utils::misc {
    std::uint64_t get_kernel_base()
    {
		std::uint64_t kernel_base = 0;
		auto enum_modules = [&](char* driver_name, std::uintptr_t image_base, std::uint64_t image_size) -> bool
		{
			STRING driver_name_str;
			RtlInitString(&driver_name_str, driver_name);

			STRING ntoskrnl_str, ntkrnlmp_str;
			RtlInitString(&ntoskrnl_str, "ntoskrnl.exe");
			RtlInitString(&ntkrnlmp_str, "ntkrnlmp.exe");

			if (!RtlCompareString(&driver_name_str, &ntoskrnl_str, TRUE) || !RtlCompareString(&driver_name_str, &ntkrnlmp_str, TRUE))
			{
				ang_debug("Found kernel base: %p\n", image_base);
				kernel_base = image_base;
				return TRUE;
			}
			return FALSE;
		};

		memory::module::enumerate_modules(enum_modules);
		return kernel_base;
    }

	
}