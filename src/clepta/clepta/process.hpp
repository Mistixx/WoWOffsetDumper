#pragma once

#include "core.hpp"
#include "memory.hpp"
#include "modules.hpp"
#include "pattern.hpp"
#include "process_list.hpp"
#include "types.hpp"

namespace clepta
{
	namespace detail
	{
		struct state_deleter
		{
			void operator()(process_state* state)
			{
				state->reset();
			}
		};
	}

	class process : public std::unique_ptr<process_state, detail::state_deleter>
	{
		using unique_base = std::unique_ptr<process_state, detail::state_deleter>;

	public:
		process() noexcept :
			unique_base(new process_state), pstate(unique_base::get()) {}
		~process() noexcept = default;

		process(const process&) = delete;
		process& operator=(const process&) = delete;

		process(process&&) = default;
		process& operator=(process&&) = default;

		void open(HANDLE handle)
		{
			pstate->handle = handle;
			pstate->pid = GetProcessId(handle);

			if (pstate->pid == GetCurrentProcessId())
				pstate->current = true;

			modules mods(pstate);
			auto main_module = mods.get_main();
			if (!main_module.has_value())
				throw std::exception("failed to get main module of process");
			pstate->base_address = main_module.value().base;
			pstate->base_size = main_module.value().size;
		}

		void open(uint32_t pid, uint32_t access = PROCESS_ALL_ACCESS)
		{
			HANDLE handle = (pid == GetCurrentProcessId()) ? GetCurrentProcess() : OpenProcess(access, false, pid);

			open(handle);
		}

		void open(const std::string& name, uint32_t access = PROCESS_ALL_ACCESS)
		{
			auto procs = process_list(name);

			if (procs.empty())
				throw std::exception("Could not find process.");

			open(procs.front().pid, access);
		}

		void close()
		{
			pstate->reset();
		}

		bool valid()
		{
			DWORD code = 0;
			if (!pstate->handle || !GetExitCodeProcess(pstate->handle, &code))
				return false;
			return (code == STILL_ACTIVE);
		}

		process_state* state() const { return pstate; }
		HANDLE handle() const { return pstate->handle; }
		uint32_t pid() const { return pstate->pid; }
		bool current() const { return pstate->current; }
		ptr_t base_address() const { return pstate->base_address; }
		ptr_t base_size() const { return pstate->base_size; }

	private:
		process_state* pstate;

		uintptr_t m_BaseAddress = 0;
		uintptr_t m_BaseSize = 0;

	};

	typedef process* process_ptr;
}