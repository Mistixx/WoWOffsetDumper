#pragma once

#include "capstone/capstone.h"
#include "clepta/clepta.hpp"

#include <cinttypes>
#include <iostream>
#include <map>
#include <string>
#include <vector>

struct descriptor
{
	uint64_t name;
	uint64_t size;
	uint64_t flags;
};

struct descriptor_result
{
	std::vector<uintptr_t> offsets;
	bool dynamic;
};

std::map<std::string, std::string> base_descriptors
{
	{ "CGObjectData",				"" },
	{ "CGUnitData",					"CGObjectDataEnd" },
	{ "CGUnitDynamicData",			"CGObjectDataEnd" },
	{ "CGActivePlayerData",			"CGPlayerDataEnd" },
	{ "CGActivePlayerDynamicData",	"CGObjectDataEnd" },
	{ "CGItemData",					"CGObjectDataEnd" },
	{ "CGItemDynamicData",			"CGObjectDataEnd" },
	{ "CGPlayerData",				"CGUnitDataEnd" },
	{ "CGPlayerDynamicData",		"CGObjectDataEnd" },
	{ "CGGameObjectData",			"CGObjectDataEnd" },
	{ "CGGameObjectDynamicData",	"CGObjectDataEnd" },
	{ "CGDynamicObjectData",		"CGObjectDataEnd" },
	{ "CGContainerData",			"CGItemDataEnd" },
	{ "CGCorpseData",				"CGObjectDataEnd" },
	{ "CGAreaTriggerData",			"CGObjectDataEnd" },
	{ "CGConversationData",			"CGObjectDataEnd" },
	{ "CGConversationDynamicData",	"CGObjectDataEnd" },
	{ "CGAzeriteEmpoweredData",		"CGItemDataEnd" },
	{ "CGAzeriteItemData",			"CGItemDataEnd" },
	{ "CGSceneObjectData",			"CGObjectDataEnd" },
};

class descriptor_dumper
{
public:
	descriptor_dumper(const std::string& target)
	{
		process.open(target);

		clepta::modules mods(process.state());
		auto mod = mods.get_main();
		main_module = mod.has_value() ? mod.value() : throw std::exception("failed to get main module");
	}

	void dump()
	{
		get_init_funcs();
		get_descriptor_offsets();

		write_results();
	}

	void get_init_funcs()
	{
		auto init_func = clepta::pattern("40 53 48 83 EC 20 E8 ? ? 00 00 E8 ? ? 00 00 E8").search(process.state(), main_module);
		if (!init_func)
			throw std::exception("could not find descriptor initialization function");

		std::vector<uint8_t> bytes;
		bytes.resize(256);
		clepta::memory::read(process.state(), process->base_address + init_func[0], bytes.size(), &bytes[0]);
		const uint8_t* cbytes = bytes.data();

		csh handle;
		size_t count = bytes.size();
		uint64_t init_func_addr = init_func[0];

		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			return;

		cs_insn* insn = cs_malloc(handle);

		while (cs_disasm_iter(handle, &cbytes, &count, &init_func_addr, insn))
		{
			if (strcmp(insn->mnemonic, "call") == 0)
			{
				uint32_t addr;
				memcpy(&addr, &insn->bytes[1], sizeof(uint32_t));
				uintptr_t real = process->base_address + insn->address + static_cast<uintptr_t>(addr) + 5;

				if (real > (process->base_address + process->base_size))
					continue;

				init_funcs.emplace_back(real);
			}
		}

		cs_free(insn, 1);
		cs_close(&handle);
	}

	void get_descriptor_offsets()
	{
		for (uintptr_t addr : init_funcs)
		{
			clepta::pattern_search_result offsets;

			std::vector<uint8_t> bytes;
			bytes.resize(4000);
			clepta::memory::read(process.state(), addr, bytes.size(), &bytes[0]);

			auto dynamic = clepta::pattern("33 C9 48 8D 05 ? ? ? ?", clepta::pattern::normal, 0x5).search(bytes.data(), 100);

			if (!dynamic)
				dynamic = clepta::pattern("33 C0 48 8D 0D ? ? ? ?", clepta::pattern::normal, 0x5).search(bytes.data(), 100);

			if (!dynamic)
			{
				// If we reach to this point this function contains dynamic descriptor
				offsets = clepta::pattern("48 89 05 ? ? ? ?", clepta::pattern::normal, 0x3).search(bytes, "ret");
				//offList = m_Process->FindPatternAll("48 89 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");
			}
			else
			{
				offsets = clepta::pattern("48 8D 05 ? ? ? ?", clepta::pattern::normal, 0x3).search(bytes, "ret");
				//offList = m_Process->FindPatternAll("48 8D 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");

				if (!offsets.valid())
					offsets = clepta::pattern("48 8D 0D ? ? ? ?", clepta::pattern::normal, 0x3).search(bytes, "ret");
				//offList = m_Process->FindPatternAll("48 8D 0D ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");
			}

			std::vector<uintptr_t> realList;
			for (uintptr_t a : offsets)
			{
				uint32_t b = clepta::memory::read<uint32_t>(process.state(), addr + a);
				uintptr_t c = (addr + a + b) + (!dynamic ? 4 : -4);
				uintptr_t d = c - process->base_address;

				realList.push_back(d);
			}

			// Now sort list low > high and pick first offset
			std::sort(realList.begin(), realList.end());
			descriptor_result ds;
			ds.offsets = realList;
			ds.dynamic = !dynamic ? true : false;
			descriptor_results.push_back(ds);
		}
	}

	void write_results()
	{
		for (auto it : descriptor_results)
		{
			std::cout << "0x" << std::hex << std::setfill('\0') << std::uppercase << it.offsets.front();
			std::cout << " " << clepta::memory::read<std::string>(process.state(), clepta::memory::read<uint64_t, true>(process.state(), it.offsets.front()), 255) << std::endl;
		}
	}

private:
	clepta::process process;
	clepta::module_info main_module;

	std::vector<clepta::ptr_t> init_funcs;
	std::vector<descriptor_result> descriptor_results;

};