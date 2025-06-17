#include <memory.hpp>
#include <utils.hpp>
#include <intrin.h>

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
	NTSTATUS write_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID src_address, SIZE_T size)
	{
		std::uint64_t bytes_written;
		return MmCopyVirtualMemory(src_process, src_address, dst_process, dst_address, size, KernelMode, &bytes_written);
	}

	NTSTATUS read_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID src_address, SIZE_T size)
	{
		std::uint64_t bytes_read;
		return MmCopyVirtualMemory(src_process, src_address, dst_process, dst_address, size, KernelMode, &bytes_read);
	}
}

namespace memory
{
	namespace CONSTANTS::UNDOCUMENTED
	{
		PFN_EXPALLOCATEHANDLETABLEENTRY ExpAllocateHandleTableEntry = nullptr;
	}

	NTSTATUS map_and_write(PVOID destination, PVOID source, SIZE_T size) {
		ang_debug("map_and_write: dest=%p, size=%zu\n", destination, size);

		PMDL mdl = IoAllocateMdl(destination, (ULONG)size, FALSE, FALSE, NULL);
		if (!mdl) {
			ang_debug("Failed to allocate MDL\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		ang_debug("MDL allocated successfully\n");

		__try {
			MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
			ang_debug("Pages locked successfully\n");
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			NTSTATUS code = GetExceptionCode();
			ang_debug("MmProbeAndLockPages failed: 0x%08X\n", code);
			IoFreeMdl(mdl);
			return STATUS_INVALID_ADDRESS;
		}

		PVOID mapped = MmMapLockedPagesSpecifyCache(
			mdl,
			KernelMode,
			MmNonCached,
			NULL,
			FALSE,
			NormalPagePriority
		);

		if (!mapped) {
			ang_debug("MmMapLockedPagesSpecifyCache failed\n");
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return STATUS_INTERNAL_ERROR;
		}
		ang_debug("Pages mapped at %p\n", mapped);

		NTSTATUS status = MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) {
			ang_debug("MmProtectMdlSystemAddress failed: 0x%08X\n", status);
			MmUnmapLockedPages(mapped, mdl);
			MmUnlockPages(mdl);
			IoFreeMdl(mdl);
			return status;
		}
		ang_debug("Protection changed to RW\n");

		RtlCopyMemory(mapped, source, size);
		ang_debug("Memory copied successfully\n");

		MmUnmapLockedPages(mapped, mdl);
		MmUnlockPages(mdl);
		IoFreeMdl(mdl);

		return STATUS_SUCCESS;
	}

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

	static KIRQL g_old_irql;

	void disable_wp() 
	{
		// Raise IRQL to prevent context switching
		g_old_irql = KeRaiseIrqlToDpcLevel();

		// Clear CET bit in CR4
		auto cr4 = __readcr4();
		cr4 &= ~(1ULL << 23);
		__writecr4(cr4);

		// Clear WP bit in CR0
		auto cr0 = __readcr0();
		cr0 &= ~(1ULL << 16);
		__writecr0(cr0);
	}

	void enable_wp() 
	{
		// Restore WP bit
		auto cr0 = __readcr0();
		cr0 |= (1ULL << 16);
		__writecr0(cr0);

		// Restore CET bit
		auto cr4 = __readcr4();
		cr4 |= (1ULL << 23);
		__writecr4(cr4);

		// Lower IRQL back
		KeLowerIrql(g_old_irql);
	}

}