#pragma once

#include "types.hpp"

#include <vector>

namespace clepta
{
	struct process_list : std::vector<process_info>
	{
		process_list(const std::string& name = "")
		{
			HANDLE snap;

			// Transform name to lower so we can compare without any problems.
			// TODO: Move this and the next transform to a utils thingy instead.
			std::string namelower = name;
			std::transform(namelower.begin(), namelower.end(), namelower.begin(), tolower);

			snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snap == INVALID_HANDLE_VALUE)
				throw std::exception("invalid handle value trying to fetch process list");

			PROCESSENTRY32 entry = { 0 };
			entry.dwSize = sizeof(PROCESSENTRY32);

			for (bool success = Process32First(snap, &entry); success; success = Process32Next(snap, &entry))
			{
				// Transform tolower, move to utils instead like mentioned above.
				std::string exe = entry.szExeFile;
				std::transform(exe.begin(), exe.end(), exe.begin(), tolower);

				// If called with empty name we find all processes otherwise normal compare.
				if (name.empty() || exe.compare(namelower.c_str()) == 0)
				{
					process_info data;
					data.usage = entry.cntUsage;
					data.pid = entry.th32ProcessID;
					data.pid_parent = entry.th32ParentProcessID;
					data.mid = entry.th32ModuleID;
					data.threads = entry.cntThreads;
					data.priority = entry.pcPriClassBase;
					data.flags = entry.dwFlags;
					data.filename = entry.szExeFile;
					data.filename_lower = exe;
					emplace_back(data);
				}
			}

			// Be a nice person and cleanup.
			CloseHandle(snap);
		}
	};
}