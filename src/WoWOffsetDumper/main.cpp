#include "Common.hpp"
#include "Memory/MemoryObject.hpp"
#include "Memory/Process.hpp"

#include <iostream>
#include <fstream>
#include <regex>

// Inspired by https://github.com/tomrus88/WowMoPObjMgrTest/blob/33182552d39de452255537496192634e8bba24ad/WowMoPObjMgrTest/DescriptorsDumper.cs
// credits to tomrus88

const uint32 DescriptorMulti = 0x4;		// 8.0.1.27326
const uint32 DescriptorOffset = 0x10;	// 8.0.1.27326

std::shared_ptr<Process> g_Process;

struct Descriptor
{
	uint64 Name;
	uint64 Size;
	uint64 Flags;
};

struct DynamicDescriptor
{
	uint64 Name;
	uint16 Size;
	uint16 Flags;
};

std::map<uint64, std::string> MirrorFlags
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

// This is a map because non-dynamic descriptor struct is 18 bytes in size while
// dynamic descriptor struct is 10 bytes in size so the boolean is telling us if its dynamic or not
// 8.0.1.27326
std::map<int32, bool> descriptors
{
	{ 0x2735250, false }, // CGObjectData
	{ 0x27368C0, false }, // CGUnitData
	{ 0x2737C10, true }, // CGUnitDynamicData
	{ 0x2741910, false }, // CGActivePlayerData
	{ 0x2758F40, true }, // CGActivePlayerDynamicData
	{ 0x2735310, false }, // CGItemData
	{ 0x27359F0, true }, // CGItemDynamicData
	{ 0x2737C40, false }, // CGPlayerData
	{ 0x2741900, true }, // CGPlayerDynamicData
	{ 0x2759030, false }, // CGGameObjectData
	{ 0x27592A0, true }, // CGGameObjectDynamicData
	{ 0x27592B0, false }, // CGDynamicObjectData
	{ 0x2735A30, false }, // CGContainerData
	{ 0x2759390, false }, // CGCorpseData
	{ 0x2759870, false }, // CGAreaTriggerData
	{ 0x27352F8, false }, // CGConversationData
	{ 0x2759AB8, true }, // CGConversationDynamicData
	{ 0x27367D0, false }, // CGAzeriteEmpoweredData
	{ 0x2736830, false }, // CGAzeriteItemData
	{ 0x2759A10, false }, // CGSceneObjectData
};

std::map<std::string, std::string> baseDescriptors
{
	{ "CGObjectData",				"" },
	{ "CGUnitData",					"CGObjectDataEnd" },
	{ "CGUnitDynamicData",			"CGDynamicObjectDataEnd" },
	{ "CGActivePlayerData",			"CGPlayerDataEnd" },
	{ "CGActivePlayerDynamicData",	"CGDynamicObjectDataEnd" },
	{ "CGItemData",					"CGObjectDataEnd" },
	{ "CGItemDynamicData",			"CGDynamicObjectDataEnd" },
	{ "CGPlayerData",				"CGUnitDataEnd" },
	{ "CGPlayerDynamicData",		"CGUnitDynamicDataEnd" },
	{ "CGGameObjectData",			"CGObjectDataEnd" },
	{ "CGGameObjectDynamicData",	"CGDynamicObjectDataEnd" },
	{ "CGDynamicObjectData",		"CGObjectDataEnd" },
	{ "CGContainerData",			"CGItemDataEnd" },
	{ "CGCorpseData",				"CGObjectDataEnd" },
	{ "CGAreaTriggerData",			"CGObjectDataEnd" },
	{ "CGConversationData",			"CGObjectDataEnd" },
	{ "CGConversationDynamicData",	"CGDynamicObjectDataEnd" },
	{ "CGAzeriteEmpoweredData",		"CGObjectDataEnd" },
	{ "CGAzeriteItemData",			"CGObjectDataEnd" },
	{ "CGSceneObjectData",			"CGObjectDataEnd" },
};

void DumpDescriptors()
{
	MemoryObject memory(g_Process, g_Process->GetBaseAddress());

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
				d.Name = memory.Read<uint64>(address.first + i * sizeof(DynamicDescriptor));
				d.Size = memory.Read<uint32>(address.first + (i * sizeof(DynamicDescriptor)) + 0x8);
				d.Flags = memory.Read<uint32>(address.first + (i * sizeof(DynamicDescriptor)) + 0xC);
			}
			else
			{
				d.Name = memory.Read<uint64>(address.first + i * sizeof(Descriptor));
				d.Size = memory.Read<uint64>(address.first + (i * sizeof(Descriptor)) + 0x8);
				d.Flags = memory.Read<uint64>(address.first + (i * sizeof(Descriptor)) + 0x10);
			}

			std::string n = memory.ReadString(d.Name, 255, true);

			if (n.empty())
				return;

			if (address.second)
				int asd = 0;

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

std::list<uintptr> TestUpdateDescriptorOffsets()
{
	// This FindPattern function finds the first occurance of pattern starting
	// from base address and ending with base address + base size
	// base is Wow.exe
	uintptr funcStart = g_Process->FindPattern("40 53 48 83 EC 20 E8 ? ? 00 00 E8 ? ? 00 00 E8", SignatureType::NORMAL, 0x6, 0x0);
	std::vector<uint8> bytes;
	bytes.resize(22 * 5);
	g_Process->Read(funcStart, 22 * 5, bytes.data());

	std::list<uintptr> funcList;
	for (int32 i = 0; i < 22; ++i)
	{
		uint8* a = &bytes[i * 5];
		uint32* b = reinterpret_cast<uint32*>(++a);
		uintptr c = (funcStart + i * 5) + (*b + 5);

		if (c > g_Process->GetBaseAddress() + g_Process->GetBaseSize())
			continue; // nullsub

		funcList.push_back(c);
	}

	std::list<uintptr> offsetsOut;
	for (uintptr f : funcList)
	{
		// This FindPattern function reads the first 100 bytes starting from 'f'
		// 0x5 is the offset it adds to the pattern.
		// so it will skip 33 C9 48 8D 05 when it returns uintptr
		uintptr a = g_Process->FindPattern("33 C9 48 8D 05 ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, f, 100);

		if (!a)
			a = g_Process->FindPattern("33 C0 48 8D 0D ? ? ? ?", SignatureType::NORMAL, 0x5, 0x0, f, 100);

		if (!a)
		{
			// FindPatternAll does a search until it finds a byte (0xC3 here)
			// What this function should do is have the option to use end byte or
			// use a disassembler to search a single function.
			// Need to implement capstone into memory library still.
			// Right now it search for the first occurance of the byte 0xC3 but
			// this is a very bad idea because 0xC3 isnt always 'retn'!
			std::list<uintptr> l = g_Process->FindPatternAll("48 89 05 ? ? ? ?", SignatureType::NORMAL, 0x3, 0x0, f, 0xC3);

			std::list<uintptr> l2;
			for (uintptr a2 : l)
			{
				uint32 b = g_Process->Read<uint32>(a2);
				uintptr c = (a2 + b) + 4;
				uintptr d = c - g_Process->GetBaseAddress();

				l2.push_back(d);
			}

			// Now sort list low > high and pick first offset<
			l2.sort();

			offsetsOut.push_back(l2.front());

			continue;
		}

		uint32 b = g_Process->Read<uint32>(a);
		uintptr c = (a + b) - 4;
		uintptr d = c - g_Process->GetBaseAddress();
		offsetsOut.push_back(d);
	}

	// offsetsOut will contain all the updated offsets 
	return offsetsOut;
}

struct OffsetPattern
{
	std::string Variable;
	std::string Pattern;
	SignatureType SigType;
	uintptr PatternOffset;
	uintptr AddressOffset;
};

std::list<OffsetPattern> offsetPatterns
{
	{ "ObjectMgrPtr", "4C 8B 05 ? ? ? ? 48 8B F2 48 8B", SignatureType::NORMAL, 0x3, 0x0 },
	{ "NameCacheBase", "? ? ? ? BA 10 00 00 00 48 83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? E8 ? ? ? ? 33 C9 C7 05 ? ? ? ? FF FF FF FF", SignatureType::NORMAL, 0x0, 0x0 },
	{ "CooldownPtr", "48 8D 05 ? ? ? ? 48  83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48", SignatureType::NORMAL, 0x3, 0x0 }
	// Player name = 33 C0 48 8D 0D ? ? ? ? 38 05 ? ? ? ? 48 0F 45 C1 C3
	// Matches two functions, one is unknown the other contain playername offset
};

std::map<std::string, uintptr> TestUpdateOffsets()
{
	std::map<std::string, uintptr> ret;

	for (auto op : offsetPatterns)
	{
		uintptr base = g_Process->FindPattern(op.Pattern.c_str(), op.SigType, op.PatternOffset, op.AddressOffset);
		uint32 rel = g_Process->Read<uint32>(base);
		uintptr real = (base + rel + 4) - g_Process->GetBaseAddress();

		std::cout << op.Variable << " = 0x" << std::hex << std::setfill('\0') << real << std::endl;

		ret[op.Variable] = real;
	}

	return ret;
}

int main()
{
	g_Process = std::make_shared<Process>("Wow.exe");

	if (!g_Process->Open())
		return 0;

	DumpDescriptors();

	auto v = TestUpdateDescriptorOffsets();
	for (auto it : v)
	{
		std::cout << "0x" << std::hex << std::setfill('\0') << it << std::endl;
	}

	std::cout << std::endl;

	TestUpdateOffsets();

	std::cout << std::endl << "Done! Press enter to exit." << std::endl;

	std::cin.get();

	return 0;
}