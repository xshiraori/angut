#include "angut_api.hpp"
#include <iostream>

namespace angut::driver
{
    bool init()
    {
        driver_handle = CreateFileW(
            L"\\\\.\\angut",
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (driver_handle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        return true;
    }

	void disconnect()
	{
		if (driver_handle && driver_handle != INVALID_HANDLE_VALUE) 
        {
			CloseHandle(driver_handle);
			driver_handle = nullptr;
		}
	}

    DWORD do_ioctl(std::uint32_t ioctl_code, void* data, size_t size)
    {
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(
            driver_handle,
            ioctl_code,
            data,
            (DWORD)size,
            data,  
            (DWORD)size,
            &bytesReturned,
            nullptr
        );

        if (!result) 
        {
            return GetLastError();
        }

        return 0;
    }
}

namespace angut::ioctl
{
	namespace handler
	{
		bool send_memory_read_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_READ_PROCESS_MEMORY, req, bufferLength) == 0;
		}
		bool send_memory_write_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_WRITE_PROCESS_MEMORY, req, bufferLength) == 0;
		}
		bool send_enumerate_callbacks_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_ENUMERATE_CALLBACKS, req, bufferLength) == 0;
		}
		bool send_patch_callback_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_PATCH_CALLBACK, req, bufferLength) == 0;
		}
		bool send_delete_callback_patch_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_DELETE_CALLBACK_PATCH, req, bufferLength) == 0;
		}
		bool send_create_user_send_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_CREATE_MANUAL_HANDLE, req, bufferLength) == 0;
		}
		bool send_get_process_info_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_GET_PROCESS_INFO, req, bufferLength) == 0;
		}
		bool send_select_target_process_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_SELECT_TARGET_PROCESS, req, bufferLength) == 0;
		}
		bool send_set_driver_settings_request(void* req, size_t bufferLength)
		{
			return driver::do_ioctl(IOCTL_SET_DRIVER_SETTINGS, req, bufferLength) == 0;
		}
	}
}

namespace angut::service
{
	bool read_memory(void* buffer, void* address, size_t size, uint32_t processId)
	{
		if (!driver::init() || !buffer || !address)
		{
			return false;
		}
		memory_read_request* req = reinterpret_cast<memory_read_request*>(malloc(0x1000));
		req->Address = address;
		req->Buffer = buffer;
		req->Size = size;
		req->ProcessId = processId;

		return ioctl::handler::send_memory_read_request(req, 0x1000);
	}
	bool write_memory(void* buffer, void* address, size_t size, uint32_t processId)
	{
		if (!driver::init() || !buffer || !address)
		{
			return false;
		}

		memory_write_request* req = reinterpret_cast<memory_write_request*>(malloc(0x1000));
		req->Address = address;
		req->Buffer = buffer;
		req->Size = size;
		req->ProcessId = processId;
		
		return ioctl::handler::send_memory_write_request(req, 0x1000);
	}

	bool enumerate_callbacks(callback_information* cbi, size_t& amount)
	{
		if (!driver::init())
		{
			return false;
		}

		auto req = reinterpret_cast<enumerate_callbacks_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}

		req->callback_type = callback_type::ProcessObject;
		if (!ioctl::handler::send_enumerate_callbacks_request(req, 0x1000))
		{
			return false;
		}

		auto resp = reinterpret_cast<enumerate_callbacks_response*>(req);
		if (resp->count == 0)
		{
			amount = 0;
			return true;
		}

		cbi = resp->entries;
		amount = resp->count;
		return true;
	}

	bool patch_callback(std::uintptr_t callback_address, callback_type type)
	{
		if (!driver::init())
		{
			return false;
		}
		auto req = reinterpret_cast<patch_callback_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}
		req->callback_address = callback_address;
		req->callback_type = type;
		if (!ioctl::handler::send_patch_callback_request(req, 0x1000))
		{
			return false;
		}

		delete req; // Free the request memory after sending
		return true;
	}

	bool delete_callback_patch(std::uintptr_t callback_address, callback_type type)
	{
		if (!driver::init())
		{
			return false;
		}
		auto req = reinterpret_cast<patch_callback_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}
		req->callback_address = callback_address;
		req->callback_type = type;
		if (!ioctl::handler::send_delete_callback_patch_request(req, 0x1000))
		{
			return false;
		}

		delete req; // Free the request memory after sending
		return true;
	}

	bool create_handle(std::uint32_t processId, ACCESS_MASK desiredAccess, HANDLE& outHandle)
	{
		if (!driver::init())
		{
			return false;
		}
		create_user_handle_request* req = reinterpret_cast<create_user_handle_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}
		req->processId = processId;
		req->desiredAccess = desiredAccess;
		if (!ioctl::handler::send_create_user_send_request(req, 0x1000))
		{
			free(req);
			return false;
		}
		auto resp = reinterpret_cast<create_user_handle_response*>(req);
		outHandle = resp->handle;
		free(req); // Free the request memory after sending
		return true;
	}

	bool get_process_base(std::uint32_t processId, std::uint64_t& baseAddress)
	{
		if (!driver::init())
		{
			return false;
		}
		get_process_info_request* req = reinterpret_cast<get_process_info_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}
		req->process_id = processId;
		if (!ioctl::handler::send_get_process_info_request(req, 0x1000))
		{
			free(req);
			return false;
		}
		auto resp = reinterpret_cast<get_process_info_response*>(req);
		baseAddress = resp->base_address;
		free(req); // Free the request memory after sending
		return true;
	}

	bool select_target_process(std::uint32_t processId)
	{
		if (!driver::init())
		{
			return false;
		}
		select_target_process_request* req = reinterpret_cast<select_target_process_request*>(malloc(0x1000));
		if (!req)
		{
			return false;
		}
		req->process_id = processId;
		if (!ioctl::handler::send_select_target_process_request(req, 0x1000))
		{
			free(req);
			return false;
		}
		free(req); // Free the request memory after sending
		return true;
	}

	bool set_driver_settings(set_driver_settings_request& settings)
	{
		if (!driver::init())
		{
			return false;
		}
		if (!ioctl::handler::send_set_driver_settings_request(&settings, sizeof(settings)))
		{
			return false;
		}
		return true;
	}
}