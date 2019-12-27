#pragma once

#include "clepta/clepta.hpp"
#include "patterns.hpp"

#include <iostream>
#include <fstream>
#include <mutex>
#include <thread>

class offset_dumper
{
public:
	offset_dumper() noexcept = delete;
	offset_dumper(dump_info& inf, int max_threads = 1) : info(inf), num_threads(max_threads)
	{
		process.open(info.target);

		clepta::modules mods(process.state());
		auto mod = mods.get_main();
		main_module = mod.has_value() ? mod.value() : throw std::exception("failed to get main module");
	}

	void dump()
	{
		offset_results = search_patterns(info.offsets);
		funcs_results = search_patterns(info.functions);

		write_results();
	}

	void dump_thread(std::map<std::string, clepta::pattern_search_result>& result, const std::string& name, clepta::pattern pattern)
	{
		auto matches = pattern.search(process.state(), main_module);
		std::lock_guard<std::mutex> guard(result_mutex);
		result[name] = matches;
	}

	std::map<std::string, clepta::pattern_search_result> search_patterns(std::map<std::string, clepta::pattern> patterns)
	{
		std::map<std::string, clepta::pattern_search_result> results;

		if (num_threads > 1)
		{
			std::vector<std::thread> threads;
			for (auto& [name, patt] : patterns)
			{
				if (threads.size() >= num_threads)
				{
					threads.back().join();
					threads.pop_back();
				}

				threads.emplace_back(std::thread(&offset_dumper::dump_thread, this, std::ref(results), std::ref(name), std::ref(patt)));
			}

			for (auto& t : threads)
				t.join();
		}
		else
		{
			for (auto [name, patt] : patterns)
				results[name] = patt.search(process.state(), main_module);
		}

		return results;
	}

	void write_results()
	{
		std::ofstream f(main_module.name + "_offsets.txt", std::ios::trunc);
		f << "#pragma once" << std::endl << std::endl;
		if (offset_results.find("GameVersion") != offset_results.end() && offset_results["GameVersion"].valid())
		{
			f << "// " << clepta::memory::read<std::string, true>(process.state(), offset_results["GameVersion"][0]);
			if (offset_results.find("GameBuild") != offset_results.end() && offset_results["GameBuild"].valid())
				f << "." << clepta::memory::read<std::string, true>(process.state(), offset_results["GameBuild"][0]) << std::endl;
			else
				f << std::endl;
		}
		f << "enum class Offsets" << std::endl << "{" << std::endl;

		for (auto [name, result] : offset_results)
		{
			f << "\t" << name << " = 0x" << std::hex << std::setfill('\0') << std::uppercase << (result.valid() ? result[0] : 0) << "," << std::endl;
		}

		f << "};" << std::endl << std::endl;

		for (auto [name, result] : offset_results)
		{
			std::cout << name << " = 0x" << std::hex << std::setfill('\0') << std::uppercase << (result.valid() ? result[0] : 0) << std::endl;
		}

		std::cout << std::endl;

		f << "enum class FunctionOffsets" << std::endl << "{" << std::endl;

		for (auto [name, result] : funcs_results)
		{
			f << "\t" << name << " = 0x" << std::hex << std::setfill('\0') << std::uppercase << (result.valid() ? result[0] : 0) << "," << std::endl;
		}

		f << "};";

		for (auto [name, result] : funcs_results)
		{
			std::cout << name << " = 0x" << std::hex << std::setfill('\0') << std::uppercase << (result.valid() ? result[0] : 0) << std::endl;
		}

		std::cout << std::endl;
	}

private:
	std::mutex result_mutex;
	clepta::process process;
	clepta::module_info main_module;
	dump_info& info;
	int num_threads;

	std::map<std::string, clepta::pattern_search_result> offset_results;
	std::map<std::string, clepta::pattern_search_result> funcs_results;

};