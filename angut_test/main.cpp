// UserModeTest.cpp
#include "driver.hpp"
#include "utils.hpp"
#include <iostream>
#include "test.hpp"

enumerate_callbacks_response* enum_callbacks()
{
	auto buffer = malloc(0x2000);
	if (!buffer)
	{
		return nullptr;
	}
	memset(buffer, 0, 0x2000);
	reinterpret_cast<enumerate_callbacks_request*>(buffer)->callback_type = CallbackType::ProcessObject;
	if (!utils::driver::do_ioctl(IOCTL_ENUMERATE_CALLBACKS, buffer, 0x2000))
	{
		printf("unable to send ioctl\n");
	}
	auto resp = reinterpret_cast<enumerate_callbacks_response*>(buffer);
	return resp;
}

int main()
{
    if (!utils::driver::init())
    {
        std::cout << "unable to load driver\n" << std::endl;
        return 0;
    }

	auto resp = enum_callbacks();
	for (uint64_t i = 0; i < resp->count; i++)
	{
		printf("Callback %llu: Address: 0x%llx, Module: %s, PreOperation: %d\n",
			i,
			resp->entries[i].callback_address,
			resp->entries[i].mi.module_name,
			resp->entries[i].pre_operation);
	}

	std::cout << "Enter the index of the callback to patch: ";
	uint64_t index;
	std::cin >> index;

	if (index >= resp->count)
	{
		std::cout << "Invalid index." << std::endl;
	}
	auto targetCallback = resp->entries[index].callback_address;
	patch_callback_request patchReq = {};
	patchReq.callback_type = CallbackType::ProcessObject;
	patchReq.callback_address = targetCallback;
	if (!utils::driver::do_ioctl(IOCTL_PATCH_CALLBACK, patchReq))
	{
		printf("Failed to patch callback at 0x%llx\n", targetCallback);
	}
	else
	{
		printf("Callback at 0x%llx patched successfully!\n", targetCallback);
	}
    
    return 0;
}
