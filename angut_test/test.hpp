#pragma
#include "driver.hpp"
#include "utils.hpp"
#include <iostream>

static void test_read()
{
    utils::driver::MEMORY_OPERATION op = {};

    auto notepadPid = utils::GetProcessList()["notepad.exe"];
    auto notepadBase = utils::GetProcessModuleBase(notepadPid);

    op.ProcessId = notepadPid;
    op.Address = notepadBase;
    op.Size = 2;

    BYTE localBuf[2] = {};
    op.Buffer = localBuf;

    if (!utils::driver::do_ioctl(IOCTL_READ_PROCESS_MEMORY, op))
    {
        printf("unable to send ioctl\n");
    }

    for (ULONG i = 0; i < 2; i++) {
        printf("Read byte index [%d] : %02X ", i, localBuf[i]);
    }
    printf("\n");
}

static void test_enum_drivers()
{
    utils::driver::MEMORY_OPERATION buffer = {};
    if (!utils::driver::do_ioctl(IOCTL_ENUMERATE_DRIVERS, buffer))
    {
        printf("unable to send ioctl\n");
    }
}

static void test_enum_callbacks()
{
    auto buffer = malloc(0x2000);
    if (!buffer)
    {
        return;
    }

    memset(buffer, 0, 0x2000);
    reinterpret_cast<enumerate_callbacks_request*>(buffer)->callback_type = CallbackType::ProcessObject;

    if (!utils::driver::do_ioctl(IOCTL_ENUMERATE_CALLBACKS, buffer, 0x2000))
    {
        printf("unable to send ioctl\n");
    }

    auto resp = reinterpret_cast<enumerate_callbacks_response*>(buffer);

    printf("Number of callbacks found: %llu\n", resp->count);

    for (uint64_t i = 0; i < resp->count; i++)
    {
        printf("Callback %llu:\n", i);
        printf("  Module: %s\n", resp->entries[i].mi.module_name);
        printf("  Base: 0x%llx\n", resp->entries[i].mi.base);
        printf("  Size: 0x%llx\n", resp->entries[i].mi.size);
        printf("  Address: 0x%llx\n", resp->entries[i].callback_address);
        printf("  Pre-operation: %s\n", resp->entries[i].pre_operation ? "true" : "false");
        printf("\n");
    }

    if (resp->count > 0) {
        auto targetCallback = resp->entries[0].callback_address;

        patch_callback_request patchReq = {};
        patchReq.callback_address = targetCallback;
        patchReq.callback_type = CallbackType::ProcessObject; // ProcessObject

        printf("Attempting to patch callback at 0x%llx\n", targetCallback);

        if (utils::driver::do_ioctl(IOCTL_PATCH_CALLBACK, patchReq)) {
            printf("Callback patched successfully!\n");
        }
        else {
            printf("Failed to patch callback\n");
        }
    }

    free(buffer);
}