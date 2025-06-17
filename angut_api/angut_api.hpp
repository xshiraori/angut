#pragma once
#include <Windows.h>
#include <cstdint>
#include "angut_types.hpp"

#define IOCTL_READ_PROCESS_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PROCESS_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_DRIVERS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ENUMERATE_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PATCH_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETE_CALLBACK_PATCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CREATE_MANUAL_HANDLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SELECT_TARGET_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DRIVER_SETTINGS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

namespace angut
{
	static HANDLE driver_handle = nullptr;
	namespace driver
	{
		bool init();
		DWORD do_ioctl(std::uint32_t ioctl_code, void* data, size_t size);
		void disconnect();
	}

	namespace ioctl
	{
		namespace handler
		{
			bool send_memory_read_request(void* req, size_t bufferLength);
			bool send_memory_write_request(void* req, size_t bufferLength);
			bool send_enumerate_callbacks_request(void* req, size_t bufferLength);
			bool send_patch_callback_request(void* req, size_t bufferLength);
			bool send_delete_callback_patch_request(void* req, size_t bufferLength);
			bool send_create_user_send_request(void* req, size_t bufferLength);
			bool send_get_process_info_request(void* req, size_t bufferLength);
			bool send_select_target_process_request(void* req, size_t bufferLength);
			bool send_set_driver_settings_request(void* req, size_t bufferLength);
		}
	}

	namespace service
	{
		bool read_memory(void* buffer, void* address, size_t size, uint32_t processId);
		bool write_memory(void* buffer, void* address, size_t size, uint32_t processId);
		bool enumerate_callbacks(callback_information* cbi, size_t& amount);
		bool patch_callback(std::uintptr_t callback_address, callback_type type);
		bool delete_callback_patch(std::uintptr_t callback_address, callback_type type);
		bool create_handle(std::uint32_t processId, ACCESS_MASK desiredAccess, HANDLE& outHandle);
		bool get_process_base(std::uint32_t processId, std::uint64_t& baseAddress);
		bool select_target_process(std::uint32_t processId);
		bool set_driver_settings(const set_driver_settings_request& settings);
	}
}