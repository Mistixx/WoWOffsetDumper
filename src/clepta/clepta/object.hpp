#pragma once

#include "memory.hpp"
#include "process.hpp"

#include <memory>

namespace clepta
{
	template <typename obj_t>
	class object
	{
	public:
		object() = default;
		object(process_state* state, ptr_t addr = 0) :
			_state(state), _address(addr)
		{
			mirror();
		}

		object(const object&) = default;
		object& operator=(const object&) = default;

		object(object&&) = default;
		object& operator=(object&&) = default;

		obj_t operator*() { return _data; }
		obj_t* operator->() { return &_data; }

		virtual bool mirror(uintptr_t addr = 0)
		{
			if (addr == 0)
				addr = _address;

			return (memory::read(_state, addr, sizeof(_data), &_data) == ERROR_SUCCESS);
		}

		void clear()
		{
			memset(&_data, 0, sizeof(_data));
		}

		process_state* state() { return _state; }
		ptr_t address() { return _address; }
		void address(ptr_t address) { _address = address; }
		obj_t* data() { return &_data; }

	protected:
		process_state* _state;
		ptr_t _address;
		obj_t _data;

	};

	template <typename obj_t>
	class object_ptr : public object<obj_t>
	{
		using base_t = object<obj_t>;

	public:
		object_ptr() = default;
		object_ptr(process_state* state, ptr_t addr = 0) :
			_state(state, addr) {}

		object_ptr(const object_ptr&) = default;
		object_ptr& operator=(const object_ptr&) = default;

		object_ptr(object_ptr&&) = default;
		object_ptr& operator=(object_ptr&&) = default;

		bool mirror(ptr_t addr = 0) override
		{
			if (addr == 0)
				addr = _address;

			ptr_t ptr = memory::read<ptr_t>(_state, addr);

			if (ptr == 0)
				return false;

			return base_t::mirror(ptr);
		}
	};
}