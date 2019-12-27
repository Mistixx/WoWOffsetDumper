#pragma once

#include "core.hpp"
#include "types.hpp"

#include <filesystem>
#include <vector>

namespace clepta
{
	template <typename T = uint64_t>
	struct module_list : std::vector<module_info>
	{
		module_list() noexcept = default;
		module_list(process_state* state)
		{
			auto ldr = get_ldr<T>(state);
			for (T head = ldr->InLoadOrderModuleList.Flink;
				head != (ldr.address() + offsetof(peb_ldr_data_t<T>, InLoadOrderModuleList));
				memory::read(state, head, sizeof(head), &head))
			{
				if (!head)
					break;

				module_info data;
				wchar_t localPath[(MAX_PATH * 2)]{};
				object<ldr_data_table_entry_base_t<T>> entry(state, head);
				memory::read(state, entry->FullDllName.Buffer, entry->FullDllName.Length, &localPath);

				data.base = entry->DllBase;
				data.entry = entry->EntryPoint;
				data.size = entry->SizeOfImage;
				data.fullpath = localPath;
				data.name = std::filesystem::path(data.fullpath).filename().generic_string();
				data.ldr = static_cast<ptr_t>(head);

				emplace_back(data);
			}
		}
	};
}