#pragma once
#include "nt_internals.hpp"
#include <cstdint>

namespace memory::CONSTANTS
{
    class WIN10
    {
    public:
		WIN10() = delete;
        static const std::uint64_t EPROCESS_TO_HANDLE_TABLE = 0x570; // Offset to the handle table in EPROCESS structure
        static const std::uint64_t OBJECT_TO_HEADER = 0x30;

        static const UCHAR ExpAllocateHandleTableEntry_prologue_pattern[35];

        static const UCHAR KiSystemServiceRepeat[21];
    };
}

namespace memory::CONSTANTS::UNDOCUMENTED
{
    extern PFN_EXPALLOCATEHANDLETABLEENTRY ExpAllocateHandleTableEntry;
}