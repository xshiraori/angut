#pragma once
#include "nt_internals.hpp"
#include "memory.hpp"

namespace memory::ssdt
{
	class ssdt_hook_manager
    {
	public:
		struct ssdt_hook
		{
			std::uint16_t index;
			PVOID hook_function;
			PVOID original_function;
			PVOID trampoline_function;
		};

        static ssdt_hook_manager& get_instance() {
            static ssdt_hook_manager instance;
            return instance;
        }

		PVOID get_hook_function_by_index(std::uint16_t index) const
		{
			for (const auto& hook : m_hooks)
			{
				if (hook.index == index)
				{
					return hook.hook_function;
				}
			}
			return nullptr;
		}

		PVOID get_original_function_by_index(std::uint16_t index) const
		{
			for (const auto& hook : m_hooks)
			{
				if (hook.index == index)
				{
					return hook.original_function;
				}
			}
			return nullptr;
		}

		PVOID get_trampoline_function_by_index(std::uint16_t index) const
		{
			for (const auto& hook : m_hooks)
			{
				if (hook.index == index)
				{
					return hook.trampoline_function;
				}
			}
			return nullptr;
		}

		PVOID get_original_function_by_hook(PVOID hook_function) const
		{
			for (const auto& hook : m_hooks)
			{
				if (hook.hook_function == hook_function)
				{
					return hook.original_function;
				}
			}
			return nullptr;
		}

		PVOID get_trampoline_function_by_hook(PVOID hook_function) const
		{
			for (const auto& hook : m_hooks)
			{
				if (hook.hook_function == hook_function)
				{
					return hook.trampoline_function;
				}
			}
			return nullptr;
		}

		VOID add_hook(std::uint16_t index, PVOID hook_function, PVOID original_function, PVOID trampoline_function)
		{
			if (index >= 0x1000 || !hook_function || !original_function || !trampoline_function)
			{
				return;
			}

			for (auto& hook : m_hooks)
			{
				if (hook.index == 0)
				{
					hook.index = index;
					hook.hook_function = hook_function;
					hook.original_function = original_function;
					hook.trampoline_function = trampoline_function;
					return;
				}
			}

			ang_debug("No available slot for new hook!\n");
		}

		VOID remove_hook(std::uint16_t index)
		{
			for (auto& hook : m_hooks)
			{
				if (hook.index == index)
				{
					hook.index = 0;
					hook.hook_function = nullptr;
					hook.original_function = nullptr;
					hook.trampoline_function = nullptr;
					return;
				}
			}
			ang_debug("Hook with index %u not found!\n", index);
		}

		bool pop_from_back(ssdt_hook& hook)
		{
			for (int i = 4; i >= 0; --i)
			{
				if (m_hooks[i].index != 0)
				{
					hook = m_hooks[i];
					m_hooks[i] = ssdt_hook(); // reset the slot
					return true;
				}
			}
			return false;
		}
	private:
		
		ssdt_hook_manager() = default;
		~ssdt_hook_manager() = default;
		ssdt_hook_manager(const ssdt_hook_manager&) = delete;
		ssdt_hook_manager& operator=(const ssdt_hook_manager&) = delete;

		ssdt_hook m_hooks[5];

    };


    PKSERVICE_TABLE_DESCRIPTOR_ENTRY get_system_service_table_entry(std::uint32_t index);
    std::uint64_t set_system_service_table_entry(std::uint32_t index, std::uint64_t new_function = 0);
    bool is_suitable_cave_simple(ULONG_PTR addr, SIZE_T size);
    PVOID find_code_cave_from_first_syscall(SIZE_T required_size);
    PVOID write_trampoline_into_cave(PVOID target_function);
	void cleanup();
	bool hook_single_entry(std::uint16_t index, PVOID hook, PVOID original);
	PVOID get_service_table_base();

	template<typename T>
	T* get_function_by_entry(std::uint16_t index)
	{
		auto entry = get_system_service_table_entry(index);
		auto service_table_base = reinterpret_cast<ULONG_PTR>(get_service_table_base());
		if (!entry) return nullptr;
		return reinterpret_cast<T*>(service_table_base + entry->bits.Offset);
	}
}

