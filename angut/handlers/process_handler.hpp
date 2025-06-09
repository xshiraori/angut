#include <process.hpp>
#include <utils.hpp>

namespace ioctl::handler {
	struct create_user_handle_request
	{
		std::uint32_t processId;
		ACCESS_MASK desiredAccess;
	};

	struct create_user_handle_response
	{
		HANDLE handle;
	};

	void handle_process_create_user_handle(
		create_user_handle_request* req,
		size_t bufferLength,
		NTSTATUS& status,
		ULONG_PTR& info
	)
	{
		PEPROCESS targetProcess = nullptr;
		status = PsLookupProcessByProcessId(
			reinterpret_cast<HANDLE>(UIntToPtr(req->processId)),
			&targetProcess
		);
		if (!NT_SUCCESS(status)) {
			utils::logger::debug("Failed to lookup process by ID %u. Status: 0x%lx\n", req->processId, status);
			return;
		}

		auto desired_access = req->desiredAccess;
		RtlZeroMemory(req, bufferLength);

		HANDLE handle = nullptr;
		status = process::create_handle_for_user(
			PsGetCurrentProcess(),
			targetProcess,
			desired_access,
			&handle
		);
		
		auto resp = reinterpret_cast<create_user_handle_response*>(req);
		RtlZeroMemory(resp, bufferLength);

		if (NT_SUCCESS(status)) {
			resp->handle = handle;
			info = sizeof(create_user_handle_response);
			utils::logger::debug("Handle created successfully!!!\n");
		}
		else {
			resp->handle = nullptr;
			info = 0;
			utils::logger::debug("Failed to create handle for process %u. Status: 0x%lx\n", req->processId, status);
		}
	}
}