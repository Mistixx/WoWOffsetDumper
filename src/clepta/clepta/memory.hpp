#pragma once

#include "types.hpp"

namespace clepta
{
	namespace memory
	{
		uint32_t read(process_state* state, uint64_t address, uint64_t size, void* result)
		{
			SIZE_T read = 0;

			if (address == 0)
				return ERROR_INVALID_ADDRESS;

			if (!ReadProcessMemory(state->handle, (LPCVOID)address, result, size, &read) || read != static_cast<SIZE_T>(size))
				return GetLastError();

			return ERROR_SUCCESS;
		}

		template <typename T, bool based = false>
		struct reader
		{
			template <typename... Args>
			T read(process_state* state, ptr_t addr, Args&&... args)
			{
				T tmp;
				ZeroMemory(&tmp, sizeof(T));

				if constexpr (based)
					addr += state->base_address;

				if (memory::read(state, addr, sizeof(T), &tmp) != ERROR_SUCCESS)
					return tmp;

				return tmp;
			}
		};

		template <>
		struct reader<std::string, false>
		{
			std::string read(process_state* state, ptr_t addr, int16_t max_length = 32)
			{
				char c = '\0';
				std::string ret = "";

				do
				{
					memory::read(state, addr + (sizeof(char) * ret.size()), sizeof(char), &c);
					ret += c;
				} while (c != '\0' && ret.size() < max_length);

				return ret;
			}
		};

		template <>
		struct reader<std::string, true>
		{
			std::string read(process_state* state, ptr_t addr, int16_t max_length = 32)
			{
				return reader<std::string, false>{}.read(state, state->base_address + addr, max_length);
			}
		};

		template <typename T, bool based = false, typename... Args>
		T read(process_state* state, ptr_t addr, Args&&... args)
		{
			using Tu = std::remove_cvref_t<T>;
			return reader<Tu, based>{}.read(state, addr, std::forward<Args>(args)...);
		}
	}
}