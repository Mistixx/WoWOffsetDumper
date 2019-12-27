#pragma once

#include <cinttypes>

namespace clepta
{
	class pattern_traits
	{
	public:
		inline uint8_t value(const char* c)
		{
			return (get_bits(c[0]) << 4 | get_bits(c[1]));
		}

		inline bool compare(const uint8_t* bytes, const char* base_pattern)
		{
			for (; *base_pattern; *base_pattern != ' ' ? ++bytes : bytes, ++base_pattern)
			{
				if (*base_pattern == ' ' || *base_pattern == '?')
					continue;

				if (*bytes != value(base_pattern))
					return false;

				++base_pattern;
			}

			return true;
		}

	private:
		inline bool in_range(char c, char a, char b)
		{
			return (c >= a && c <= b);
		}

		inline char get_bits(char c)
		{
			return (in_range(c, '0', '9') ? (c - '0') : ((c & (~0x20)) - 'A' + 0xA));
		}
	};
}