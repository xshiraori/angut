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

void send_patch_req(std::uintptr_t targetCallback)
{
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
}

void send_patch_delete_req(std::uintptr_t targetCallback)
{
	patch_callback_request patchReq = {};
	patchReq.callback_type = CallbackType::ProcessObject;
	patchReq.callback_address = targetCallback;
	if (!utils::driver::do_ioctl(IOCTL_DELETE_CALLBACK_PATCH, patchReq))
	{
		printf("Failed to delete patch for callback at 0x%llx\n", targetCallback);
	}
	else
	{
		printf("Patch for callback at 0x%llx deleted successfully!\n", targetCallback);
	}
}

std::uint64_t send_get_process_base_req(std::uint32_t processId)
{
	auto buffer = malloc(0x2000);
	memset(buffer, 0, 0x2000);
	auto req = reinterpret_cast<get_process_info_request*>(buffer);
	req->process_id = processId;
	if (!utils::driver::do_ioctl(IOCTL_GET_PROCESS_INFO, req, 0x2000))
	{
		printf("Failed to get process base for process %u\n", processId);
		return 0;
	}
	else
	{
		auto resp = reinterpret_cast<get_process_info_response*>(buffer);
		printf("Process %u main module base address: 0x%llx\n", processId, resp->base_address);
		return resp->base_address;
	}
}

void send_open_handle_req(std::uint32_t processId, ACCESS_MASK desiredAccess)
{
	auto buffer = malloc(0x2000);
	memset(buffer, 0, 0x2000);

	auto req = reinterpret_cast<create_user_handle_request*>(buffer);
	req->processId = processId;
	req->desiredAccess = desiredAccess;

	if (!utils::driver::do_ioctl(IOCTL_CREATE_MANUAL_HANDLE, req, 0x2000))
	{
		printf("Failed to open handle for process %u\n", processId);
	}
	else
	{
		auto resp = reinterpret_cast<create_user_handle_response*>(buffer);
		printf("Handle opened successfully: 0x%p\n", resp->handle);

		// test out the handle
		HANDLE hProcess = resp->handle;
		
		auto base = send_get_process_base_req(processId);
		if (!base)
		{
			return;
		}

		SHORT magic_header;
		if (ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(base), &magic_header, sizeof(magic_header), nullptr))
		{
			printf("Successfully read memory from process %u at base 0x%p: magic header = 0x%x\n", processId, base, magic_header);
		}
		else
		{
			printf("Failed to read memory from process %u at base 0x%p\n", processId, base);
		}
	}
}

void send_select_target_process_req(std::uint32_t processId)
{
	if (!utils::driver::do_ioctl(IOCTL_SELECT_TARGET_PROCESS, &processId, 4))
	{
		printf("Failed to select target process %u\n", processId);
	}
	else
	{
		printf("Target process %u selected successfully!\n", processId);
	}
}


class cli {
public:
	static void display_callbacks(enumerate_callbacks_response* resp)
	{
		if (!resp)
		{
			std::cout << "No callbacks found." << std::endl;
			return;
		}
		printf("Number of callbacks found: %llu\n", resp->count);
		for (uint64_t i = 0; i < resp->count; i++)
		{
			printf("Callback %llu: Address: 0x%llx, Module: %s, PreOperation: %d\n",
				i,
				resp->entries[i].callback_address,
				resp->entries[i].mi.module_name,
				resp->entries[i].pre_operation);
		}
	}


	static void run()
	{
		std::cout << "Welcome to the Angut CLI!" << std::endl;
		std::cout << "Available commands:" << std::endl;
		std::cout << "1. Enumerate callbacks" << std::endl;
		std::cout << "2. Patch an existing callback" << std::endl;
		std::cout << "3. Remove the patch from the callback" << std::endl;
		std::cout << "4. Open handle from kernel mode" << std::endl;
		std::cout << "5. Get process main module base" << std::endl;
		std::cout << "6. Select target process for handle operations" << std::endl;
		std::cout << "7. Exit" << std::endl;

		int choice;
		while (true)
		{
			std::cout << "Enter your choice: ";
			std::cin >> choice;
			switch (choice)
			{
			case 1:
			{
				auto resp = enum_callbacks();
				display_callbacks(resp);
				break;
			}
			case 2:
			{
				auto resp = enum_callbacks();

				display_callbacks(resp);

				std::cout << "Enter the index of the callback to patch: ";
				uint64_t index;
				std::cin >> index;
				
				if (index >= resp->count)
				{
					std::cout << "Invalid index." << std::endl;
					break;
				}

				auto targetCallback = resp->entries[index].callback_address;
				send_patch_req(targetCallback);
				break;
			}
			case 3:
			{
				auto resp = enum_callbacks();
				display_callbacks(resp);

				std::cout << "Enter the index of the callback to remove patch: ";
				uint64_t index;
				std::cin >> index;
				
				if (index >= resp->count)
				{
					std::cout << "Invalid index." << std::endl;
					break;
				}
				auto targetCallback = resp->entries[index].callback_address;
				send_patch_delete_req(targetCallback);
				break;
			}
			case 4:
			{
				std::uint32_t processId;
				ACCESS_MASK desiredAccess;
				std::cout << "Enter Process ID: ";
				std::cin >> processId;
				
				desiredAccess = PROCESS_ALL_ACCESS;
				send_open_handle_req(processId, desiredAccess);
				break;
			}
			case 5:
			{
				std::uint32_t processId;
				std::cout << "Enter Process ID to get main module base: ";
				std::cin >> processId;

				send_get_process_base_req(processId);
				break;
			}
			case 6:
			{
				std::uint32_t processId;
				std::cout << "Enter Process ID to select as target: ";
				std::cin >> processId;
				send_select_target_process_req(processId);
				break;
			}
			case 7:
			{
				std::cout << "Exiting Angut CLI. Goodbye!" << std::endl;
				return;
			}
			default:
				std::cout << "Invalid choice, please try again." << std::endl;
			}
		}
	}
};


int main()
{
    if (!utils::driver::init())
    {
        std::cout << "unable to load driver\n" << std::endl;
        return 0;
    }

	cli::run();
    return 0;
}
