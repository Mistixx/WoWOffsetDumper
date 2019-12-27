#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <winternl.h>
#include <winioctl.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(pop)

namespace clepta
{
	struct process_state;

	class process;
	class modules;

	class basic_pattern;
	class pattern_traits;
	class pattern_search;
	class pattern_search_result;
	using pattern = basic_pattern;

	template <typename obj_t>
	class object;

	template <typename obj_t>
	class object_ptr;
}