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
	std::list<uintptr> descOffsets = GetDescriptorOffsets();

	for (uintptr it : descOffsets)
	{
		std::cout << "0x" << std::hex << std::setfill('\0') << it << std::endl;
	}

	std::cout << std::endl;

	std::map<std::string, uintptr> offsets = GetOffsets();

	for (auto it : offsets)
	{
		std::cout << it.first << " = 0x" << std::hex << std::setfill('\0') << it.second << std::endl;
	}

	std::cout << std::endl;

	// Need to automatically use new offsets
	//DumpDescriptors();
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

std::list<uintptr> Dumper::GetDescriptorOffsets()
{
	// This FindPattern function finds the first occurance of pattern starting
	// from base address and ending with base address + base size
	// base is Wow.exe
	uintptr funcStart = m_Process->FindPattern("40 53 48 83 EC 20 E8 ? ? 00 00 E8 ? ? 00 00 E8", SignatureType::NORMAL, 0x6, 0x0);
	std::vector<uint8> bytes;
	bytes.resize(22 * 5);
	m_Process->Read(funcStart, 22 * 5, bytes.data());

	std::list<uintptr> funcList;
	for (int32 i = 0; i < 22; ++i)
	{
		uint8* a = &bytes[i * 5];
		uint32* b = reinterpret_cast<uint32*>(++a);
		uintptr c = (funcStart + i * 5) + (*b + 5);

		if (c > m_Process->GetBaseAddress() + m_Process->GetBaseSize())
			continue; // nullsub

		funcList.push_back(c);
	}

	std::list<uintptr> offsetsOut;
	for (uintptr f : funcList)
	{
		// This FindPattern function reads the first 100 bytes starting from 'f'
		// 0x5 is the offset it adds to the pattern.
		// so it will skip 33 C9 48 8D 05 when it returns uintptr
		uintptr a = m_Process->FindPattern("33 C9 48 8D 05 ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, f, 100);

		if (!a)
			a = m_Process->FindPattern("33 C0 48 8D 0D ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, f, 100);

		if (!a)
		{
			// FindPatternAll does a search until it finds a byte (0xC3 here)
			// What this function should do is have the option to use end byte or
			// use a disassembler to search a single function.
			// Need to implement capstone into memory library still.
			// Right now it search for the first occurance of the byte 0xC3 but
			// this is a very bad idea because 0xC3 isnt always 'retn'!
			std::list<uintptr> l = m_Process->FindPatternAll("48 89 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, f, 0xC3);

			std::list<uintptr> l2;
			for (uintptr a2 : l)
			{
				uint32 b = m_Process->Read<uint32>(a2);
				uintptr c = (a2 + b) + 4;
				uintptr d = c - m_Process->GetBaseAddress();

				l2.push_back(d);
			}

			// Now sort list low > high and pick first offset<
			l2.sort();

			offsetsOut.push_back(l2.front());

			continue;
		}

		uint32 b = m_Process->Read<uint32>(a);
		uintptr c = (a + b) - 4;
		uintptr d = c - m_Process->GetBaseAddress();
		offsetsOut.push_back(d);
	}

	// offsetsOut will contain all the updated offsets 
	return offsetsOut;
}

void Dumper::DumpDescriptors()
{
	MemoryObject memory(m_Process, m_Process->GetBaseAddress());

	std::ofstream f("descriptors.txt", std::ios::trunc);

	f << "#pragma once" << std::endl << std::endl;
	f << "#include \"Define.hpp\"" << std::endl << std::endl;

	f << "const uint32 DescriptorMulti = 0x4;" << std::endl;
	f << "const uint32 DescriptorOffset = 0x10;" << std::endl << std::endl;

	for (auto address : descriptors)
	{
		int64 i = 0;

		std::string currentPrefix;

		while (true)
		{
			Descriptor d;

			if (address.second)
			{
				d.Name = memory.Read<uint64>(address.first + i * sizeof(0x12));
				d.Size = memory.Read<uint32>(address.first + (i * sizeof(0x12)) + 0x8);
				d.Flags = memory.Read<uint32>(address.first + (i * sizeof(0x12)) + 0xC);
			}
			else
				memory.Read<Descriptor>(address.first + (i * sizeof(Descriptor)));

			std::string n = memory.ReadString(d.Name, 255, true);

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

			if (!currentPrefix.empty() && n.rfind(currentPrefix.c_str(), 0) != 0)
			{
				if (!baseDescriptors[currentPrefix].empty())
					f << "	" << currentPrefix << "End = " << baseDescriptors[currentPrefix] << " + " << i << std::endl;
				else
					f << "	" << currentPrefix << "End = " << i << std::endl;

				f << "}" << std::endl;

				break;
			}

			if (!baseDescriptors[currentPrefix].empty())
				f << "	" << memberName << " = " << baseDescriptors[currentPrefix] << " + " << i << ", // size " << d.Size << " flags: " << MirrorFlags[d.Flags] << std::endl;
			else
				f << "	" << memberName << " = " << i << ", // size " << d.Size << std::endl;

			if (address.second)
				i += 1;
			else
				i += d.Size;

			// HACK
			if (memberName == "AvailableQuestLineXQuestIDs")
				i += 1;
		}

		currentPrefix.clear();

		f << std::endl;
	}
}