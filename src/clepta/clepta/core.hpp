#pragma once

#include "dynamic_function.hpp"
#include "memory.hpp"
#include "object.hpp"

namespace clepta
{
	inline void load_default_imports()
	{
		dynamic_import{}.load("NtQueryInformationProcess", "ntdll.dll");
	}

	template <typename T = uint64_t>
	inline object<peb_t<T>> get_peb(process_state* state)
	{
		dynamic_function<NtQueryInformationProcess_t> fn;

		if constexpr (std::is_same_v<T, uint32_t>)
		{
			ptr_t ptr = 0;
			if (NT_SUCCESS(fn("NtQueryInformationProcess", state->handle, ProcessWow64Information, &ptr, static_cast<ULONG>(sizeof(ptr)), nullptr)))
				return object<peb_t<T>>{ state, ptr };
		}
		else
		{
			PROCESS_BASIC_INFORMATION pbi;
			ULONG bytes = 0;

			if (NT_SUCCESS(fn("NtQueryInformationProcess", state->handle, ProcessBasicInformation, &pbi, static_cast<ULONG>(sizeof(pbi)), &bytes)))
				return object<peb_t<T>>{ state, reinterpret_cast<ptr_t>(pbi.PebBaseAddress) };
		}

		throw std::exception("failed to get PEB");
	}

	template <typename T = uint64_t>
	inline object<peb_ldr_data_t<T>> get_ldr(process_state* state)
	{
		object<peb_t<T>> peb = get_peb<T>(state);
		return { state, peb->Ldr };
	}
}