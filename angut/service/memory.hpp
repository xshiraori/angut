#pragma once
#include <nt_internals.hpp>
#include <ntifs.h>
#include <cstdint>
#include "utils.hpp"
#include "constants.hpp"

using CurrentVer = memory::CONSTANTS::WIN10;

namespace memory {
    NTSTATUS static search_pattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
    {
        ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
        if (ppFound == NULL || pattern == NULL || base == NULL)
            return STATUS_INVALID_PARAMETER;

        for (ULONG_PTR i = 0; i < size - len; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG_PTR j = 0; j < len; j++)
            {
                if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
                {
                    found = FALSE;
                    break;
                }
            }
            if (found != FALSE)
            {
                *ppFound = (PUCHAR)base + i;
                return STATUS_SUCCESS;
            }
        }
        return STATUS_NOT_FOUND;
    }

    NTSTATUS static search_from_kernelbase(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, const char* section_name = "PAGE")
    {
        static auto base = utils::misc::get_kernel_base();
		static auto kernel_nt_header = RtlImageNtHeader(reinterpret_cast<PVOID>(base));

		if (kernel_nt_header == NULL)
			return STATUS_NOT_FOUND;
		
        static auto section = reinterpret_cast<PIMAGE_SECTION_HEADER>(kernel_nt_header + 1);

        for (PIMAGE_SECTION_HEADER section_iterator = section; section_iterator < section + (kernel_nt_header->FileHeader.NumberOfSections); section_iterator++)
        {
            ANSI_STRING s1, s2;
            RtlInitAnsiString(&s1, section_name);
            RtlInitAnsiString(&s2, section_iterator->Name);
            if (!RtlCompareString(&s1, &s2, TRUE))
            {
                return search_pattern(pattern, wildcard, len, reinterpret_cast<PVOID>(base + section_iterator->VirtualAddress), section_iterator->Misc.VirtualSize, ppFound);
            }
        }

        return STATUS_NOT_FOUND;
	}

    NTSTATUS map_and_write(PVOID destination, PVOID source, SIZE_T size);

    void disable_wp();

    void enable_wp();

    static NTSTATUS initialize_constants()
    {
        search_from_kernelbase(
            CurrentVer::ExpAllocateHandleTableEntry_prologue_pattern,
            0xCC,
            sizeof(CurrentVer::ExpAllocateHandleTableEntry_prologue_pattern),
            reinterpret_cast<PVOID*>(&memory::CONSTANTS::UNDOCUMENTED::ExpAllocateHandleTableEntry)
        );

        if (!memory::CONSTANTS::UNDOCUMENTED::ExpAllocateHandleTableEntry)
        {
            ang_debug("Failed to find ExpAllocateHandleTableEntry function!\n");
            return STATUS_NOT_FOUND;
        }

        ang_debug("ExpAllocateHandleTableEntry found at %p\n", memory::CONSTANTS::UNDOCUMENTED::ExpAllocateHandleTableEntry);
        return STATUS_SUCCESS;
    }

    struct hook_info {
        void* original_function;
        void* hook_function;
    };

    class patch_manager {
    public:
        struct patch_info {
            void* address;
            unsigned char patch_bytes[64];
            unsigned char original_bytes[64];
            size_t patch_size;
            char tag[16];
        };

        static patch_manager& get_instance() {
            static patch_manager instance;
            return instance;
        }

        void add_patch(void* address, void* patch_bytes, void* original_bytes, size_t length, const char* tag = nullptr) {
            for (int i = 0; i < 64; ++i) {
                if (m_availablePathces[i].address == nullptr) {
					m_availablePathces[i].address = address;
					RtlCopyMemory(m_availablePathces[i].patch_bytes, patch_bytes, length);
					RtlCopyMemory(m_availablePathces[i].original_bytes, original_bytes, length);
					m_availablePathces[i].patch_size = length;
                    if (tag) {
                        strncpy_s(m_availablePathces[i].tag, tag, sizeof(m_availablePathces[i].tag) - 1);
                        m_availablePathces[i].tag[sizeof(m_availablePathces[i].tag) - 1] = '\0';
                    }
                    return;
                }
            }
        }

        void remove_patch(void* address) {
            for (int i = 0; i < 64; ++i) {
                if (m_availablePathces[i].address == address)
                {
                    m_availablePathces[i] = patch_info();
                    return;
                }
            }
        }

		void remove_patch_by_tag(const char* tag) {
			for (int i = 0; i < 64; ++i) {
				if (m_availablePathces[i].tag && strcmp(m_availablePathces[i].tag, tag) == 0) {
					m_availablePathces[i] = patch_info();
					return;
				}
			}
		}

		patch_info get_patch_by_tag(const char* tag) const {
			for (int i = 0; i < 64; ++i) {
				if (m_availablePathces[i].tag && strcmp(m_availablePathces[i].tag, tag) == 0) {
					return m_availablePathces[i];
				}
			}
			return patch_info();
		}

		patch_info get_patch_by_address(void* address) const {
			for (int i = 0; i < 64; ++i) {
				if (m_availablePathces[i].address == address) {
					return m_availablePathces[i];
				}
			}
			return patch_info();
		}

		const patch_info* get_all_patches() const {
			return m_availablePathces;
		}

    private:
        patch_manager() = default;
        ~patch_manager() = default;
        patch_manager(const patch_manager&) = delete;
        patch_manager& operator=(const patch_manager&) = delete;
        patch_info m_availablePathces[8];
    };    

    class hook_manager
    {
	public:
		static hook_manager& get_instance() {
			static hook_manager instance;
			return instance;
		}
		void add_hook(void* original_function, void* hook_function) {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].original_function == nullptr) {
					m_hooks[i].original_function = original_function;
					m_hooks[i].hook_function = hook_function;
					return;
				}
			}
		}
		void remove_hook(void* original_function) {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].original_function == original_function) {
					m_hooks[i] = hook_info();
					return;
				}
			}
		}
		const hook_info* get_all_hooks() const {
			return m_hooks;
		}

		hook_info get_hook_by_original_function(void* original_function) const {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].original_function == original_function) {
					return m_hooks[i];
				}
			}
			return hook_info();
		}

		hook_info get_hook_by_hook_function(void* hook_function) const {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].hook_function == hook_function) {
					return m_hooks[i];
				}
			}
			return hook_info();
		}

		void remove_hook_by_hook_function(void* hook_function) {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].hook_function == hook_function) {
					m_hooks[i] = hook_info();
					return;
				}
			}
		}

		void* get_original_function(void* hook_function) const {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].hook_function == hook_function) {
					return m_hooks[i].original_function;
				}
			}
			return nullptr;
		}

		void* get_hook_function(void* original_function) const {
			for (int i = 0; i < 64; ++i) {
				if (m_hooks[i].original_function == original_function) {
					return m_hooks[i].hook_function;
				}
			}
			return nullptr;
		}
	private:
		hook_manager() = default;
		~hook_manager() = default;
		hook_manager(const hook_manager&) = delete;
		hook_manager& operator=(const hook_manager&) = delete;
		hook_info m_hooks[64];
    };

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

#pragma once

    extern "C" {
#include <ntifs.h> // Needed for kernel-mode types
    }

    template<typename T>
    class generic_storage
    {
    public:
        generic_storage() : count_(0) {}

        bool add(const T& item)
        {
            if (count_ >= MaxItems)
                return false;

            RtlCopyMemory(&items_[count_], &item, sizeof(T));
            ++count_;
            return true;
        }

        bool remove(const T& item)
        {
            for (size_t i = 0; i < count_; ++i)
            {
                if (equals(items_[i], item))
                {
                    if (i != count_ - 1)
                    {
                        RtlCopyMemory(&items_[i], &items_[count_ - 1], sizeof(T));
                    }
                    --count_;
                    return true;
                }
            }
            return false;
        }

        T* get_all(size_t& out_count)
        {
            out_count = count_;
            return items_;
        }

        size_t size() const
        {
            return count_;
        }

        void clear()
        {
            count_ = 0;
        }

        template<typename V>
        T* find(const V& item)
        {
            for (size_t i = 0; i < count_; ++i)
            {
                if (equals<V>(items_[i], item))
                    return &items_[i];
            }
            return nullptr;
        }


    private:
        static constexpr size_t MaxItems = 32;
        T items_[MaxItems];
        size_t count_;

        template<typename V>
        bool equals(const T& a, const V& b) { return false; };
    };


    struct handle_info
    {
        std::uint32_t pid;
        std::uint32_t access_rights;
        void* value;
    };

    class handle_storage : public generic_storage<handle_info>
    {
    public:
		static handle_storage& get_instance()
		{
			static handle_storage instance;
			return instance;
		}

    private:
        handle_storage() = default;
        ~handle_storage() = default;
        handle_storage(const handle_storage&) = delete;
        handle_storage& operator=(const handle_storage&) = delete;

        template<typename V>
        bool equals(const handle_info& a, const V& b)
        {
            if (a.value == b)
            {
                return true;
            }
            return false;
        }
    };

    template<typename Func>
    void execute_wp_disabled(Func function)
    {
		disable_wp();
		function();
		enable_wp();
    }
}