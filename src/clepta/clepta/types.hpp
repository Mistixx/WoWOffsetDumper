#pragma once

#include "forward.hpp"
#include "types_win32.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <type_traits>

namespace clepta
{
	using void_t = void*;
	using ptr_t = uintptr_t;

	struct process_state
	{
		void reset() noexcept
		{
			CloseHandle(handle);
			handle = nullptr;
			pid = 0;
			current = false;
			base_address = 0;
			base_size = 0;
		}

		HANDLE handle = nullptr;
		uint32_t pid = 0;
		bool current = false;
		ptr_t base_address = 0;
		ptr_t base_size = 0;
	};

	struct process_info
	{
		uint32_t usage;
		uint32_t pid;
		uint32_t pid_parent;
		uint32_t mid;
		uint32_t threads;
		int64_t priority;
		uint32_t flags;
		std::string filename;
		std::string filename_lower;
	};

	struct module_info
	{
		ptr_t base;
		ptr_t entry;
		std::string name;
		std::filesystem::path fullpath;
		uint32_t size;
		uintptr_t ldr;
	};

	typedef NTSTATUS(__stdcall* NtQueryInformationProcess_t)(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);
}