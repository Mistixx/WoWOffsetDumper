#pragma once

#include "types.hpp"

#include <unordered_map>
#include <string>

namespace clepta
{
	class dynamic_import
	{
	public:
		void load(const std::string& name, const char* mod)
		{
			HMODULE h = GetModuleHandle(mod);
			if (h == NULL)
				throw std::exception("could not get module handle");

			FARPROC fn = GetProcAddress(h, name.c_str());
			if (fn == 0)
				throw std::exception("could not find address for function");

			if (fn)
				loaded[name] = fn;
		}

		template <typename T>
		T get(const std::string& name)
		{
			if (loaded.find(name) != loaded.end())
				return reinterpret_cast<T>(loaded[name]);

			return nullptr;
		}

		static std::unordered_map<std::string, FARPROC> loaded;

	};

	std::unordered_map<std::string, FARPROC> dynamic_import::loaded;
}