#pragma once
#include <nt_internals.hpp>
#include <ntifs.h>
#include <cstdint>

namespace memory {
    struct hook_info {
        void* original_function;
        void* hook_function;
    };

    struct patch_info {
        void* address;
		unsigned char patch_bytes[64];
		unsigned char original_bytes[64];
		size_t patch_size;
    };

    class patch_manager {
    public:
        static patch_manager& get_instance() {
            static patch_manager instance;
            return instance;
        }
        void add_patch(const patch_info& patch) {
            for (int i = 0; i < 64; ++i) {
                if (m_availablePathces[i].address == nullptr) {
                    m_availablePathces[i] = patch;
                    return;
                }
            }
        }

        void remove_patch(void* address) {
            for (int i = 0; i < 64; ++i) {
                if (m_availablePathces[i].address == address)
                {
                    m_availablePathces[i] = patch_info(); // Reset the patch info
                    return;
                }
            }
        }
    private:
        patch_manager() = default;
        ~patch_manager() = default;
        patch_manager(const patch_manager&) = delete;
        patch_manager& operator=(const patch_manager&) = delete;
        patch_info m_availablePathces[64]; // Array to hold available patches
    };
    
    patch_manager g_patchManager;

    template<typename T>
    bool write_to_read_only_memory(PVOID address, T value) 
    {
        PMDL mdl = IoAllocateMdl(address, sizeof(T), FALSE, FALSE, NULL);
        if (!mdl) {
            return false;
        }

        __try {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            IoFreeMdl(mdl);
            return false;
        }

        PVOID mapping = MmMapLockedPagesSpecifyCache(
            mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

        if (!mapping) {
            MmUnlockPages(mdl);
            IoFreeMdl(mdl);
            return false;
        }

        MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);
        RtlCopyMemory(mapping, &value, sizeof(T));

        MmUnmapLockedPages(mapping, mdl);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);

        return true;
    }

    bool write_to_read_only_memory(PVOID address, const void* data, SIZE_T size);

    namespace process 
    {
        template<typename T>
        NTSTATUS write_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, T value)
        {
            std::uint64_t bytes_read;
            return MmCopyVirtualMemory(src_process, &value, dst_process, dst_address, sizeof(T), KernelMode, &bytes_read);
        }

        template<typename T>
        NTSTATUS read_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, T& value)
        {
            std::uint64_t bytes_read;
            return MmCopyVirtualMemory(src_process, &value, dst_process, dst_address, sizeof(T), KernelMode, &bytes_read);
        }

        NTSTATUS write_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID buffer, SIZE_T size);
        NTSTATUS read_memory(PEPROCESS dst_process, PVOID dst_address, PEPROCESS src_process, PVOID value, SIZE_T size);
    }

    namespace module {
        struct module_information
        {
            char module_name[256];
            std::uint64_t base;
            std::uint64_t size;
        };

        void region_belongs_to(std::uint64_t region, module_information& module);

        template <typename Callback>
        void enumerate_modules(Callback callback)
        {
            ULONG                           needed = 0;
            NTSTATUS                        status;
            PRTL_PROCESS_MODULES      pModInfo = nullptr;
            SIZE_T                          allocSize;

            status = ZwQuerySystemInformation(
                SystemModuleInformation,
                nullptr,
                0,
                &needed
            );
            if (status != STATUS_INFO_LENGTH_MISMATCH) 
            {
                return;
            }

            allocSize = needed + 0x1000;
            pModInfo = (PRTL_PROCESS_MODULES)
                ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, 'drvQ');
            if (!pModInfo) 
            {
                return;
            }

            status = ZwQuerySystemInformation(
                SystemModuleInformation,
                pModInfo,
                (ULONG)allocSize,
                &needed
            );
            if (!NT_SUCCESS(status)) 
            {
                ExFreePoolWithTag(pModInfo, 'drvQ');
                return;
            }

            for (ULONG i = 0; i < pModInfo->NumberOfModules; i++) 
            {
                PRTL_PROCESS_MODULE_INFORMATION entry = &pModInfo->Modules[i];

                std::uintptr_t imageBase = (std::uintptr_t)entry->ImageBase;
                std::uint64_t  imageSize = (std::uint64_t)entry->ImageSize;

                CHAR* driverNameAnsi =
                    (CHAR*)(entry->FullPathName + entry->OffsetToFileName);

                if (callback(driverNameAnsi, imageBase, imageSize)) 
                {
                    break;
                }
            }

            ExFreePoolWithTag(pModInfo, 'drvQ');
        }
    }
}