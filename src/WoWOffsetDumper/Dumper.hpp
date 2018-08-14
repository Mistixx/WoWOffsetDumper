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

static std::list<OffsetPattern> funcPatterns
{
	{ "MoveTo", "48 83 EC 48 48 8B 81 88 01 00 00 48 83 B8 C0 00 00 00 00 7E 58", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Interact", "40 57 48 83 EC 20 48 8B F9 E8 ? ? ? ? 48 85 C0 75 0B", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_ExecuteBuffer", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 70 83 05 ? ? ? ?", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_GetLocalizedText", "0F B6 41 20 4C 8B DA 48 8D 15 ? ? ? ? 45 8B D0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_GetText", "40 55 57 41 54 41 56 41 57 48 83 EC 20 48 8D 6C 24 20 4C 8B F9 48 89 5D 38 8B 0D ? ? ? ?", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_C_HandleTerrainClick", "40 53 48 83 EC 30 B2 01 48 8B D9 E8 ? ? 00 00 85 C0", SignatureType::NORMAL, 0x0, 0x0 }
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
	std::map<std::string, uintptr> GetFunctionOffsets();
	std::list<DescriptorStruct> GetDescriptorOffsets();
	std::list<uintptr> GetDescriptorInitFuncs();
	
private:
	ProcessPtr m_Process;

};