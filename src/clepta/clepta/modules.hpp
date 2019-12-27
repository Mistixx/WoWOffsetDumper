#pragma once

#include "core.hpp"
#include "memory.hpp"
#include "module_list.hpp"
#include "types.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace clepta
{
	class modules
	{
	public:
		modules() noexcept = delete;
		modules(process_state* state) noexcept : state(state) {}
		~modules() noexcept = default;

		modules(const modules&) = delete;
		modules& operator=(const modules&) = delete;

		std::optional<module_info> get(ptr_t base)
		{
			auto cmpFn = [base](const module_info& mod)
			{
				return (base >= mod.base && base < mod.base + mod.size);
			};

			auto it = std::find_if(m_cache.begin(), m_cache.end(), cmpFn);
			if (it != m_cache.end())
				return *it;

			update_cache();

			it = std::find_if(m_cache.begin(), m_cache.end(), cmpFn);
			if (it != m_cache.end())
				return *it;

			return std::nullopt;
		}

		std::optional<module_info> get(const std::string& name)
		{
			auto cmpFn = [name](const module_info& mod)
			{
				return (name.compare(mod.name.c_str()) == 0);
			};

			auto it = std::find_if(m_cache.begin(), m_cache.end(), cmpFn);
			if (it != m_cache.end())
				return *it;

			update_cache();

			it = std::find_if(m_cache.begin(), m_cache.end(), cmpFn);
			if (it != m_cache.end())
				return *it;

			return std::nullopt;
		}

		std::optional<module_info> get_main()
		{
			object<peb_t<uint64_t>> peb = get_peb(state);
			return get(peb->ImageBaseAddress);
		}

		std::vector<module_info> get_all()
		{
			update_cache();
			return m_cache;
		}

		bool validate(uintptr_t base)
		{
			object<IMAGE_DOS_HEADER> idh(state, base);

			if (idh->e_magic != IMAGE_DOS_SIGNATURE)
				return false;

			object<IMAGE_NT_HEADERS> inth(state, base + idh->e_lfanew);

			return inth->Signature == IMAGE_NT_SIGNATURE;
		}

	private:
		module_list<> enum_modules()
		{
			return module_list(state);
		}

		void update_cache()
		{
			m_cache = enum_modules();
		}

	private:
		process_state* state;

		module_list<> m_cache;

	};
}