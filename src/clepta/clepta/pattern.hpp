#pragma once

#include "capstone/capstone.h"
#include "memory.hpp"
#include "pattern_traits.hpp"
#include "types.hpp"

#include <string_view>
#include <vector>

namespace clepta
{
	class pattern_search_result : public std::vector<std::ptrdiff_t>
	{
	public:
		pattern_search_result() noexcept = default;
		~pattern_search_result() noexcept = default;

		operator bool() const noexcept
		{
			return valid();
		}

		bool valid() const noexcept
		{
			return !empty();
		}
	};

	class basic_pattern : pattern_traits
	{
		using value_type = const char*;
		using traits_type = pattern_traits;

	public:
		enum type
		{
			normal = 0,
			deference,
		};

		basic_pattern() noexcept = default;
		basic_pattern(const char* str, type t = type::normal, int offset = 0) noexcept :
			ptr(str), t(t), of(offset) {}
		basic_pattern(std::string_view str, type t = type::normal, int offset = 0) noexcept :
			basic_pattern(str.data(), t, offset) {}
		~basic_pattern() noexcept = default;

		pattern_search_result search(const uint8_t* bytes, std::size_t sz)
		{
			pattern_search_result results;

			for (std::size_t off = 0; off < sz; ++off)
				if (compare(bytes + off, ptr))
					results.push_back(off + of);

			return results;
		}

		pattern_search_result search(const std::vector<uint8_t>& bytes)
		{
			return search(bytes.data(), bytes.size());
		}

		pattern_search_result search(const uint8_t* bytes, std::size_t sz, const char* mnemonic)
		{
			std::size_t size = find_first_mnemonic(bytes, sz, mnemonic);

			return search(bytes, size);
		}

		pattern_search_result search(const std::vector<uint8_t>& bytes, const char* mnemonic)
		{
			return search(bytes.data(), bytes.size(), mnemonic);
		}

		pattern_search_result search(process_state* state, const module_info& mod)
		{
			std::vector<uint8_t> bytes;
			bytes.resize(mod.size);
			memory::read(state, mod.base, mod.size, &bytes[0]);

			auto matches = search(bytes);

			for (auto& match : matches)
				if (t == type::deference)
					match += memory::read<int32_t>(state, mod.base + match) + 0x4;

			return matches;
		}

	private:
		std::ptrdiff_t find_first_mnemonic(const uint8_t* bytes, std::size_t sz, const char* mnemonic)
		{
			uintptr_t result = 0;
			csh handle;
			size_t count = sz;
			uint64_t address = 0;
			const uint8_t* cbytes = bytes;

			if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
				return 0;

			cs_insn* insn = cs_malloc(handle);

			while (cs_disasm_iter(handle, &cbytes, &count, &address, insn))
			{
				if (strcmp(insn->mnemonic, mnemonic) == 0)
				{
					result = insn->address;
					break;
				}
			}

			cs_free(insn, 1);
			cs_close(&handle);

			return result;
		}

	private:
		value_type ptr;
		type t;
		int of;

	};
}