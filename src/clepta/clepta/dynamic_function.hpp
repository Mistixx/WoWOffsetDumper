#pragma once

#include "dynamic_import.hpp"

#include <functional>

namespace clepta
{
	template <typename Fx>
	class dynamic_function
	{
		typedef Fx fx_t;

	public:
		template <typename... Args>
		auto operator()(const char* name, Args&&... args)
		{
			fx_t fn = dynamic_import{}.get<fx_t>(name);
			return fn ? fn(std::forward<Args>(args)...) : throw std::bad_function_call();
		}
	};
}