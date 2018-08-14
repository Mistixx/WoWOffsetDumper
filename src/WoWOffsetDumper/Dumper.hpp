#pragma once

#include "Common.hpp"
#include "Memory/MemoryObject.hpp"
#include "Memory/Process.hpp"
#include "MirrorFlags.hpp"

#include <iostream>
#include <regex>

// Inspired by https://github.com/tomrus88/WowMoPObjMgrTest/blob/33182552d39de452255537496192634e8bba24ad/WowMoPObjMgrTest/DescriptorsDumper.cs
// credits to tomrus88

struct Descriptor
{
	uint64 Name;
	uint64 Size;
	uint64 Flags;
};

// This is a map because non-dynamic descriptor struct is 18 bytes in size while
// dynamic descriptor struct is 10 bytes in size so the boolean is telling us if its dynamic or not
// 8.0.1.27326
static std::map<int32, bool> descriptors
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

static std::map<std::string, std::string> baseDescriptors
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

struct OffsetPattern
{
	std::string Variable;
	std::string Pattern;
	SignatureType SigType;
	uintptr PatternOffset;
	uintptr AddressOffset;
};

static std::list<OffsetPattern> offsetPatterns
{
	{ "ObjectMgrPtr", "4C 8B 05 ? ? ? ? 48 8B F2 48 8B", SignatureType::NORMAL, 0x3, 0x0 },
	{ "NameCacheBase", "? ? ? ? BA 10 00 00 00 48 83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? E8 ? ? ? ? 33 C9 C7 05 ? ? ? ? FF FF FF FF", SignatureType::NORMAL, 0x0, 0x0 },
	{ "CooldownPtr", "48 8D 05 ? ? ? ? 48  83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48", SignatureType::NORMAL, 0x3, 0x0 }
	// Player name = 33 C0 48 8D 0D ? ? ? ? 38 05 ? ? ? ? 48 0F 45 C1 C3
	// Matches two functions, one is unknown the other contain playername offset
};

class Dumper : public MemoryObject
{
public:
	Dumper() = delete;
	Dumper(ProcessPtr process, uintptr address);
	~Dumper();

	void Dump();

private:
	std::map<std::string, uintptr> GetOffsets();
	std::list<uintptr> GetDescriptorOffsets();

	void DumpDescriptors();
	
private:
	ProcessPtr m_Process;

};