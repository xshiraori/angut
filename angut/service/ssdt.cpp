#include "ssdt.hpp"

namespace memory::ssdt
{
    bool is_suitable_cave_simple(ULONG_PTR addr, SIZE_T size) {
        PUCHAR bytes = reinterpret_cast<PUCHAR>(addr);

        for (SIZE_T i = 0; i < size; i++) 
        {
            if (bytes[i] != 0x00 && bytes[i] != 0xCC) 
            {
                return false;
            }
        }

        return (addr & 0xF) == 0;
    }

    PVOID get_service_table_base()
    {
        std::uint64_t system_service_repeat = 0;
        if (search_from_kernelbase(
            CONSTANTS::WIN10::KiSystemServiceRepeat,
            0xCC,
            sizeof(CONSTANTS::WIN10::KiSystemServiceRepeat),
            reinterpret_cast<PVOID*>(&system_service_repeat), ".text"
        ))
        {
            return nullptr;
        }

        auto service_table_address = system_service_repeat + *reinterpret_cast<std::uint32_t*>(system_service_repeat + 3) + 7;
        auto service_table = reinterpret_cast<PKSERVICE_TABLE_DESCRIPTOR>(service_table_address);

        return service_table->Base;  // Return the actual service table base
    }

    PVOID find_code_cave_from_first_syscall(SIZE_T required_size) {
        auto service_table_base = reinterpret_cast<std::uint64_t>(get_service_table_base());  // Get actual base
        auto first_entry = get_system_service_table_entry(0);
        auto first_syscall_addr = service_table_base + first_entry->bits.Offset;

        auto max_offset = 0x00FFFFFF;
        auto max_address = service_table_base + max_offset;
        for (auto addr = first_syscall_addr; addr < max_address - required_size; addr++)
        {
            if (!MmIsAddressValid(reinterpret_cast<PVOID>(addr)))
            {
                continue;
            }

            if (is_suitable_cave_simple(addr, required_size)) 
            {
                auto offset = (addr - service_table_base);
                if (offset <= 0x00FFFFFF) {
                    ang_debug("Found code cave at: %p (offset: 0x%X)\n", addr, offset);
                    return reinterpret_cast<PVOID>(addr);
                }
            }
        }

        return nullptr;
    }

    PVOID write_trampoline_into_cave(PVOID target_function)
    {
        memory::disable_wp();

        PUCHAR trampoline = reinterpret_cast<PUCHAR>(find_code_cave_from_first_syscall(12));
        if (!trampoline) return nullptr;

        trampoline[0] = 0x48;   // REX.W prefix
        trampoline[1] = 0xB8;   // mov rax, imm64
        *reinterpret_cast<PULONG_PTR>(&trampoline[2]) = reinterpret_cast<ULONG_PTR>(target_function);
        trampoline[10] = 0xFF;  // jmp rax
        trampoline[11] = 0xE0;

        memory::enable_wp();
        return reinterpret_cast<PVOID>(trampoline);
    }

    PKSERVICE_TABLE_DESCRIPTOR_ENTRY get_system_service_table_entry(std::uint32_t index)
    {
        std::uint64_t system_service_repeat = 0;
        if (search_from_kernelbase(
            CONSTANTS::WIN10::KiSystemServiceRepeat,
            0xCC,
            sizeof(CONSTANTS::WIN10::KiSystemServiceRepeat),
            reinterpret_cast<PVOID*>(&system_service_repeat), ".text"
        ))
        {
            ang_debug("Failed to locate service table address!\n");
            return 0;
        }

        auto service_table_address = system_service_repeat + *reinterpret_cast<std::uint32_t*>(system_service_repeat + 3) + 7;
        auto service_table = reinterpret_cast<PKSERVICE_TABLE_DESCRIPTOR>(service_table_address);

        return &service_table->Base[index];
    }

    std::uint64_t set_system_service_table_entry(std::uint32_t index, std::uint64_t new_function)
    {
        std::uint64_t system_service_repeat = 0;
        if (search_from_kernelbase(
            CONSTANTS::WIN10::KiSystemServiceRepeat,
            0xCC,
            sizeof(CONSTANTS::WIN10::KiSystemServiceRepeat),
            reinterpret_cast<PVOID*>(&system_service_repeat), ".text"
        ))
        {
            ang_debug("Failed to locate service table address!\n");
            return false;
        }

        auto service_table_address = system_service_repeat + *reinterpret_cast<std::uint32_t*>(system_service_repeat + 3) + 7;
        auto service_table = reinterpret_cast<PKSERVICE_TABLE_DESCRIPTOR>(service_table_address);

        if (new_function)
        {
            disable_wp();
            auto old = service_table->Base[index].bits.Offset;
            service_table->Base[index].bits.Offset = static_cast<std::uint32_t>((new_function - reinterpret_cast<std::uint64_t>(service_table->Base)));
            enable_wp();
            return reinterpret_cast<std::uint64_t>(service_table->Base) + old;
        }

        return 0;
    }

	// caller needs to capture the original function pointer before calling this function
    // the reason is that the moment we replace the syscall, entry might get called with caller having no copy of the original function
    bool hook_single_entry(std::uint16_t index, PVOID hook, PVOID original)
    {
		if (index >= 0x1000 || !hook || !original)
		{
			return false;
		}

        auto trampoline = write_trampoline_into_cave(hook);
		if (!trampoline)
		{
			ang_debug("Failed to write trampoline into cave!\n");
			return false;
		}

		set_system_service_table_entry(index, reinterpret_cast<std::uint64_t>(trampoline));
        auto& hm = ssdt_hook_manager::get_instance();
        hm.add_hook(index, hook, original, trampoline);
    }

    void cleanup()
    {
		auto& hm = ssdt_hook_manager::get_instance();
        do {
			ssdt_hook_manager::ssdt_hook hook;
			bool removed = hm.pop_from_back(hook);
			if (!removed) break;

            set_system_service_table_entry(hook.index, reinterpret_cast<std::uint64_t>(hook.original_function));
        } while (true);
    }
}