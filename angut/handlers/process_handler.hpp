#include <process.hpp>
#include <utils.hpp>
#include <memory.hpp>
#include <state.hpp>

namespace ioctl::handler 
{
	struct create_user_handle_request
	{
		std::uint32_t processId;
		ACCESS_MASK desiredAccess;
	};

	struct create_user_handle_response
	{
		HANDLE handle;
	};

	struct get_process_info_request
	{
		std::uint32_t process_id;
	};

	struct get_process_info_response
	{
		std::uint64_t base_address;
	};

	struct select_target_process_request
	{
		std::uint32_t process_id;
	};

	void handle_create_user_handle_request(
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
		if (!NT_SUCCESS(status)) 
		{
			ang_debug("Failed to lookup process by ID %u. Status: 0x%lx\n", req->processId, status);
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

		if (NT_SUCCESS(status)) 
		{
			auto& hs = memory::handle_storage::get_instance();
			hs.add(
				{ req->processId, desired_access, handle }
			);

			resp->handle = handle;
			info = sizeof(create_user_handle_response);
			ang_debug("Handle created successfully!!!\n");
		}
		else 
		{
			resp->handle = nullptr;
			info = 0;
			ang_debug("Failed to create handle for process %u. Status: 0x%lx\n", req->processId, status);
		}

		ObDereferenceObject(targetProcess);
	}

	void handle_get_process_info_request(
		get_process_info_request* req,
		size_t bufferLength,
		NTSTATUS& status,
		ULONG_PTR& info
	)
	{
		if (bufferLength < sizeof(get_process_info_response)) 
		{
			status = STATUS_BUFFER_TOO_SMALL;
			return;
		}

		auto process_id = req->process_id;

		auto resp = reinterpret_cast<get_process_info_response*>(req);
		RtlZeroMemory(resp, bufferLength);

		if (!NT_SUCCESS(process::get_process_base(process_id, resp->base_address)))
		{
			ang_debug("Failed to get base address for process %u. Status: 0x%lx\n", process_id, status);
			return;
		}

		if (resp->base_address == 0) 
		{
			status = STATUS_NOT_FOUND;
			ang_debug("Failed to get base address for process %u. Status: 0x%lx\n", process_id, status);
			return;
		}

		info = sizeof(get_process_info_response);

		ang_debug("Process %u info retrieved successfully. Base: 0x%llx\n", resp->base_address);
		status = STATUS_SUCCESS;
	}

	void handle_select_target_process_request(
		select_target_process_request* req,
		size_t bufferLength,
		NTSTATUS& status,
		ULONG_PTR& info
	)
	{
		if (req->process_id <= 0)
		{
			status = STATUS_INVALID_PARAMETER;
			ang_debug("Invalid process ID: %u\n", req->process_id);
			return;
		}

		driver_state::get_instance().target_process_id = req->process_id;

		status = STATUS_SUCCESS;
		ang_debug("Target process %u selected successfully.\n", req->process_id);
	}
}