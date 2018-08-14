#include "Dumper.hpp"

Dumper::Dumper(ProcessPtr process, uintptr address) :
	MemoryObject(process, address), m_Process(process)
{

}

Dumper::~Dumper()
{

}

void Dumper::Dump()
{
	std::list<DescriptorStruct> descOffsets = GetDescriptorOffsets();

	for (auto it : descOffsets)
	{
		std::cout << "0x" << std::hex << std::setfill('\0') << it.Offsets.front();
		std::cout << " " << ReadString(Read<uint64>(it.Offsets.front()), 255, true) << std::endl;
	}

	DumpDescriptors(descOffsets);

	std::cout << std::endl;

	std::map<std::string, uintptr> offsets = GetOffsets();

	for (auto it : offsets)
	{
		std::cout << it.first << " = 0x" << std::hex << std::setfill('\0') << it.second << std::endl;
	}

	std::cout << std::endl;
}

void Dumper::DumpDescriptors(std::list<DescriptorStruct> offsets)
{
	std::ofstream f("descriptors.txt", std::ios::trunc);

	f << "#pragma once" << std::endl << std::endl;
	f << "#include \"Define.hpp\"" << std::endl << std::endl;

	f << "const uint32 DescriptorMulti = 0x4;" << std::endl;
	f << "const uint32 DescriptorOffset = 0x10;" << std::endl << std::endl;

	for (auto addrList : offsets)
	{
		int64 i = 0;
		std::string currentPrefix;
		bool isDynamic = addrList.IsDynamic;

		for (auto addr : addrList.Offsets)
		{
			Descriptor d;

			if (isDynamic)
			{
				d.Name = Read<uint64>(addr);
				d.Size = Read<uint32>(addr + 0x8);
				d.Flags = Read<uint32>(addr + 0xC);
			}
			else
				d = Read<Descriptor>(addr);

			std::string n = ReadString(d.Name, 255, true);

			if (n.empty())
				return;

			if (currentPrefix.empty())
			{
				std::smatch m;
				std::regex re("[a-zA-Z]+(?=::)");
				std::regex_search(n, m, re);
				currentPrefix = m.str();

				f << "enum " << currentPrefix << std::endl;
				f << "{" << std::endl;
			}

			std::string memberName;

			{
				std::smatch match;
				// Don't have lookbehind in C++, cba to improve this
				std::regex re("([:]{2})([0-9a-zA-Z_.]+)");
				std::regex_search(n, match, re);
				memberName = match[2].str();
			}

			if (memberName.rfind("m_", 0) == 0)
				memberName.erase(0, 2);

			if (memberName.rfind("local.", 0) == 0)
				memberName.erase(0, 6);

			if (!memberName.empty() && std::islower(memberName.front(), std::locale()))
				memberName[0] = std::toupper(memberName[0], std::locale());

			if (!baseDescriptors[currentPrefix].empty())
				f << "	" << currentPrefix << "_" << memberName << " = " << baseDescriptors[currentPrefix] << " + " << i << ", // size " << d.Size << " flags: " << MirrorFlags[d.Flags] << std::endl;
			else
				f << "	" << currentPrefix << "_" << memberName << " = " << i << ", // size " << d.Size << std::endl;

			if (isDynamic)
				i += 1;
			else
				i += d.Size;
		}

		if (!currentPrefix.empty())
		{
			if (!baseDescriptors[currentPrefix].empty())
				f << "	" << currentPrefix << "End = " << baseDescriptors[currentPrefix] << " + " << i << std::endl;
			else
				f << "	" << currentPrefix << "End = " << i << std::endl;

			f << "};" << std::endl;
		}

		currentPrefix.clear();

		f << std::endl;
	}
}

std::map<std::string, uintptr> Dumper::GetOffsets()
{
	std::map<std::string, uintptr> ret;

	for (auto op : offsetPatterns)
	{
		uintptr base = m_Process->FindPattern(op.Pattern.c_str(), op.SigType, op.PatternOffset, op.AddressOffset);
		uint32 rel = m_Process->Read<uint32>(base);
		uintptr real = (base + rel + 4) - m_Process->GetBaseAddress();

		ret[op.Variable] = real;
	}

	return ret;
}

std::list<DescriptorStruct> Dumper::GetDescriptorOffsets()
{
	std::list<DescriptorStruct> ret;
	std::list<uintptr> funcList = GetDescriptorInitFuncs();

	for (uintptr funcAddr : funcList)
	{
		std::list<uintptr> offList;

		uintptr testDynamic = m_Process->FindPattern("33 C9 48 8D 05 ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, funcAddr, 100);

		if (!testDynamic)
			testDynamic = m_Process->FindPattern("33 C0 48 8D 0D ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, funcAddr, 100);

		if (!testDynamic)
		{
			// If we reach to this point this function contains dynamic descriptor

			offList = m_Process->FindPatternAll("48 89 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");
		}
		else
		{
			offList = m_Process->FindPatternAll("48 8D 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");

			if (offList.empty())
				offList = m_Process->FindPatternAll("48 8D 0D ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, funcAddr, "ret");
		}

		std::vector<uintptr> realList;
		for (uintptr a : offList)
		{
			uint32 b = m_Process->Read<uint32>(a);
			uintptr c = (a + b) + (!testDynamic ? 4 : -4);
			uintptr d = c - m_Process->GetBaseAddress();

			realList.push_back(d);
		}

		// Now sort list low > high and pick first offset
		std::sort(realList.begin(), realList.end());
		DescriptorStruct ds;
		ds.Offsets = realList;
		ds.IsDynamic = !testDynamic ? true : false;
		ret.push_back(ds);
	}

	return ret;
}

std::list<uintptr> Dumper::GetDescriptorInitFuncs()
{
	std::list<uintptr> ret;

	uintptr descFuncStart = m_Process->FindPattern("40 53 48 83 EC 20 E8 ? ? 00 00 E8 ? ? 00 00 E8", SignatureType::NORMAL, 0x0, 0x0);

	uint8* bytes = new uint8[256];
	m_Process->Read(descFuncStart, 256, bytes);
	const uint8* cbytes = bytes;

	csh handle;
	size_t count = 256;
	uint64 address = descFuncStart;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return ret;

	cs_insn *insn = cs_malloc(handle);

	while (cs_disasm_iter(handle, &cbytes, &count, &address, insn))
	{
		if (strcmp(insn->mnemonic, "call") == 0)
		{
			uint32 relAddr;
			memcpy(&relAddr, &insn->bytes[1], sizeof(uint32));
			uintptr realAddr = insn->address + static_cast<uintptr>(relAddr) + 5;

			if (realAddr > (m_Process->GetBaseAddress() + m_Process->GetBaseSize()))
				continue;

			ret.push_back(realAddr);
		}
	}

	cs_free(insn, 1);
	delete[] bytes;
	cs_close(&handle);

	return ret;
}