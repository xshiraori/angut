#include <memory.hpp>
#include <utils.hpp>

namespace memory::module 
{
	void region_belongs_to(std::uint64_t region, module_information& module)
	{
		auto enum_modules = [&](char* driver_name, std::uintptr_t image_base, std::uint64_t image_size) -> bool
		{
			if (region >= image_base && region <= image_base + image_size) {
				module.base = image_base;
				module.size = image_size;
				strcpy(module.module_name, driver_name);
				return TRUE;
			}
			return FALSE;
		};

		module::enumerate_modules(enum_modules);
	}
}

namespace memory::process
{
	NTSTATUS write_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID buffer, SIZE_T size)
	{
		std::uint64_t bytes_read;
		return MmCopyVirtualMemory(src_process, buffer, dst_process, dst_address, size, KernelMode, &bytes_read);
	}

	NTSTATUS read_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID value, SIZE_T size)
	{
		std::uint64_t bytes_read;
		return MmCopyVirtualMemory(src_process, &value, dst_process, dst_address, KernelMode, size, &bytes_read);
	}
}

namespace memory
{
	bool write_to_read_only_memory(PVOID address, const void* data, SIZE_T size) {
		PMDL mdl = IoAllocateMdl(address, size, FALSE, FALSE, NULL);
		if (!mdl) 
		{
			return false;
		}

		__try 
		{
			MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{
			IoFreeMdl(mdl);
			return false;
		}

		PVOID mapping = MmMapLockedPagesSpecifyCache(
			mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

		if (!mapping) 
		{
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return false;
		}

		MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		RtlCopyMemory(mapping, data, size);

		MmUnmapLockedPages(mapping, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return true;
	}
}