#include "ssdt.hpp"

namespace memory::ssdt
{
    bool is_suitable_cave_simple(ULONG_PTR addr, SIZE_T size) 
    {
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

    PVOID find_code_cave_from_first_syscall(SIZE_T required_size) 
    {
        auto service_table_base = reinterpret_cast<std::uint64_t>(get_service_table_base());
		
        if (!service_table_base)
		{
			ang_debug("Failed to get service table base!\n");
			return nullptr;
		}

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
        PUCHAR trampoline = reinterpret_cast<PUCHAR>(find_code_cave_from_first_syscall(12));
        if (!trampoline) {
            ang_debug("No suitable code cave found\n");
            return nullptr;
        }

        ang_debug("Code cave found at %p\n", trampoline);

        // Verify the cave is really empty
        ang_debug("Cave contents before write: ");
        for (int i = 0; i < 12; i++) {
            ang_debug("%02X ", trampoline[i]);
        }
        ang_debug("\n");

        // Prepare shellcode
        UCHAR shellcode[12];
        shellcode[0] = 0x48;
        shellcode[1] = 0xB8;
        *reinterpret_cast<PULONG_PTR>(&shellcode[2]) = reinterpret_cast<ULONG_PTR>(target_function);
        shellcode[10] = 0xFF;
        shellcode[11] = 0xE0;

        NTSTATUS status = memory::map_and_write(trampoline, shellcode, sizeof(shellcode));
        if (!NT_SUCCESS(status)) {  // <-- Fix here!
            ang_debug("Failed to write trampoline: 0x%08X\n", status);
            return nullptr;
        }

        // Verify write succeeded
        ang_debug("Cave contents after write: ");
        for (int i = 0; i < 12; i++) {
            ang_debug("%02X ", trampoline[i]);
        }
        ang_debug("\n");

        return trampoline;
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
            return 0;  // Should be 0, not false
        }

        auto service_table_address = system_service_repeat + *reinterpret_cast<std::uint32_t*>(system_service_repeat + 3) + 7;
        auto service_table = reinterpret_cast<PKSERVICE_TABLE_DESCRIPTOR>(service_table_address);

        if (new_function)
        {
            std::uint64_t original_function = service_table->Base[index].bits.Offset;
            KSERVICE_TABLE_DESCRIPTOR_ENTRY original_entry = service_table->Base[index];
            original_entry.bits.Offset = static_cast<std::uint32_t>((new_function - reinterpret_cast<std::uint64_t>(service_table->Base)));

            NTSTATUS status = memory::map_and_write(&service_table->Base[index], &original_entry, sizeof(original_entry));
            if (!NT_SUCCESS(status))
            {
                ang_debug("Failed to write SSDT entry: 0x%08X\n", status);
                return 0;
            }

            ang_debug("Successfully updated SSDT entry %d\n", index);
            return reinterpret_cast<std::uint64_t>(service_table->Base) + original_function;
        }

        return 0;
    }

	// caller needs to capture the original function pointer before calling this function
    // the reason is that the moment we replace the syscall, entry might get called with caller having no copy of the original function
    bool hook_single_entry(std::uint16_t index, PVOID hook, PVOID original)
    {
		if (index >= 0x1000 || !hook || !original)
		{
            ang_debug("Invalid parameters for hooking SSDT entry %x: hook=%p, original=%p\n", index, hook, original);
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

		ang_debug("Hooked SSDT entry %x with hook at %p and original function at %p\n", index, hook, original);
        return true;
    }

    void cleanup()
    {
        auto& hm = ssdt_hook_manager::get_instance();
        do {
            ssdt_hook_manager::ssdt_hook hook;
            bool removed = hm.pop_from_back(hook);
            if (!removed)
            {
                break;
            }

            UCHAR zero_bytes[12] = { 0 };
            NTSTATUS status = memory::map_and_write(hook.trampoline_function, zero_bytes, 12);
            if (!NT_SUCCESS(status)) 
            {
                ang_debug("Failed to zero trampoline at %p: 0x%08X\n",
                    hook.trampoline_function, status);
            }

            set_system_service_table_entry(hook.index, reinterpret_cast<std::uint64_t>(hook.original_function));
        } while (true);
    }
}