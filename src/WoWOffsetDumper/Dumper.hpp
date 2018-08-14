#pragma once

#include "Common.hpp"
#include "Memory/MemoryObject.hpp"
#include "Memory/Process.hpp"
#include "MirrorFlags.hpp"

#include "capstone/capstone.h"

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

static std::map<std::string, std::string> baseDescriptors
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

struct DescriptorStruct
{
	std::vector<uintptr> Offsets;
	bool IsDynamic;
};

class Dumper : public MemoryObject
{
public:
	Dumper() = delete;
	Dumper(ProcessPtr process, uintptr address);
	~Dumper();

	void Dump();
	void DumpDescriptors(std::list<DescriptorStruct> offsets);

private:
	std::map<std::string, uintptr> GetOffsets();
	std::list<DescriptorStruct> GetDescriptorOffsets();
	std::list<uintptr> GetDescriptorInitFuncs();
	
private:
	ProcessPtr m_Process;

};