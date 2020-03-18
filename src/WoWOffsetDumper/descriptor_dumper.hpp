#pragma once

#include "capstone/capstone.h"
#include "clepta/clepta.hpp"

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <map>
#include <regex>
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

std::vector<std::string> descriptor_names
{
	"CGObjectData",
	"CGItemData",
	"CGContainerData",
	"CGAzeriteEmpoweredItemData",
	"CGAzeriteItemData",
	"CGUnitData",
	"CGPlayerData",
	"CGActivePlayerData",
	"CGGameObjectData",
	"CGDynamicObjectData",
	"CGCorpseData",
	"CGAreaTriggerData",
	"CGSceneObjectData",
	"CGConversationData",
	"CGItemDynamicData",
	"CGUnitDynamicData",
	"CGPlayerDynamicData",
	"CGActivePlayerDynamicData",
	"CGGameObjectDynamicData",
	"CGConversationDynamicData",
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

std::map<uint64_t, std::string> mirror_flags
{
	{ 0x0, "MIRROR_NONE" },
	{ 0x1, "MIRROR_ALL" },
	{ 0x2, "MIRROR_SELF" },
	{ 0x4, "MIRROR_OWNER" },
	{ 0x8, "MIRROR_UNK1" },
	{ 0x10, "MIRROR_EMPATH" },
	{ 0x20, "MIRROR_PARTY" },
	{ 0x40, "MIRROR_UNIT_ALL" },
	{ 0x80, "MIRROR_VIEWER_DEPENDENT" },
	{ 0x100, "MIRROR_URGENT" },
	{ 0x200, "MIRROR_URGENT_SELF_ONLY" },
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

		std::ofstream f("descriptors.txt", std::ios::trunc);

		f << "#pragma once" << std::endl << std::endl;
		f << "#include \"Define.hpp\"" << std::endl << std::endl;

		f << "const uint32 DescriptorMulti = 0x4;" << std::endl;
		f << "const uint32 DescriptorOffset = 0x10;" << std::endl << std::endl;

		int desc_count = 0;
		for (auto addrList : descriptor_results)
		{
			int64_t i = 0;
			bool isDynamic = addrList.dynamic;

			f << "enum " << descriptor_names[desc_count] << std::endl;
			f << "{" << std::endl;

			for (auto addr : addrList.offsets)
			{
				descriptor d;

				if (isDynamic)
				{
					d.name = clepta::memory::read<uint64_t, true>(process.state(), addr);
					d.size = clepta::memory::read<uint32_t, true>(process.state(), addr + 0x8);
					d.flags = clepta::memory::read<uint32_t, true>(process.state(), addr + 0xC);
				}
				else
					d = clepta::memory::read<descriptor, true>(process.state(), addr);

				std::string n = clepta::memory::read<std::string>(process.state(), d.name, 255);

				if (n.empty())
					return;

				//if (currentPrefix.empty())
				//{
				//	std::smatch m;
				//	std::regex re("[a-zA-Z]+(?=::)");
				//	std::regex_search(n, m, re);
				//	currentPrefix = m.str();

					//f << "enum " << descriptor_names[desc_count] << std::endl;
					//f << "{" << std::endl;
				//}

				//std::string memberName;

				//{
				//	std::smatch match;
				//	// Don't have lookbehind in C++, cba to improve this
				//	std::regex re("([:]{2})([0-9a-zA-Z_.]+)");
				//	std::regex_search(n, match, re);
				//	memberName = match[2].str();
				//}

				//if (memberName.rfind("m_", 0) == 0)
				//	memberName.erase(0, 2);

				//if (memberName.rfind("local.", 0) == 0)
				//	memberName.erase(0, 6);

				//if (!memberName.empty() && std::islower(memberName.front(), std::locale()))
				//	memberName[0] = std::toupper(memberName[0], std::locale());

				if (!base_descriptors[descriptor_names[desc_count]].empty())
					f << "	" << descriptor_names[desc_count] << "_" << n << " = " << base_descriptors[descriptor_names[desc_count]] << " + " << i << ", // size " << d.size << " flags: " << mirror_flags[d.flags] << std::endl;
				else
					f << "	" << descriptor_names[desc_count] << "_" << n << " = " << i << ", // size " << d.size << std::endl;

				if (isDynamic)
					i += 1;
				else
					i += d.size;
			}

			if (!base_descriptors[descriptor_names[desc_count]].empty())
				f << "	" << descriptor_names[desc_count] << "End = " << base_descriptors[descriptor_names[desc_count]] << " + " << i << std::endl;
			else
				f << "	" << descriptor_names[desc_count] << "End = " << i << std::endl;

			f << "};" << std::endl;

			f << std::endl;

			desc_count++;
		}

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
			bytes.resize(0x4000);
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