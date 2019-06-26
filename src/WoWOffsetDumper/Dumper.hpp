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
	intptr PatternOffset;
	uintptr AddressOffset;
};

static std::list<OffsetPattern> offsetPatterns
{
	{ "ObjectMgrPtr", "4C 8B 05 ? ? ? ? 48 8B F2 48 8B", SignatureType::NORMAL, 0x3, 0x0 },
	{ "NameCacheBase", "? ? ? ? BA 10 00 00 00 48 83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? E8 ? ? ? ? 33 C9 C7 05 ? ? ? ? FF FF FF FF", SignatureType::NORMAL, 0x0, 0x0 },
	{ "CooldownPtr", "48 8D 05 ? ? ? ? 48  83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48", SignatureType::NORMAL, 0x3, 0x0 },
	{ "LastHardwareAction", "89 05 ? ? ? ? 8B 03 48 85 C9 74 67 89 44 24 40", SignatureType::NORMAL, 0x2, 0x0 },
	{ "LocalPlayerGUID", "48 8D 05 ? ? ? ? 41 B8 03 00 00 00 0F 1F 00", SignatureType::NORMAL, 0x3, 0x0 },
	{ "CameraBase", "48 8B 05 ? ? ? ? 48 8B 88 ? ? 00 00 48 8B 43 ?", SignatureType::NORMAL, 0x3, 0x0 },
	{ "ZoneID", "44 3B 2D ? ? ? ? 44 8B 44 24 40 8B 54 24 48", SignatureType::NORMAL, 0x3, 0x0 },
	{ "IsTexting", "44 39 25 ? ? ? ? 0F 8E DF 00 00 00 33 D2 44 89 64 24 20", SignatureType::NORMAL, 0x3, 0x0 },
	{ "ActionBarFirstSlot", "48 8D 15 ? ? ? ? 48 63 C8 48 B8 00 00 00 00", SignatureType::NORMAL, 0x3, 0x0 },
	{ "MouseOverGUID", "BA 01 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 74 12", SignatureType::NORMAL, 0x8, 0x0 },
	{ "ClickToMoveTrigger", "48 63 05 ? ? ? ? 48 8D 0C 40 48 8D 05", SignatureType::NORMAL, 0x3, 0x0 },
	{ "GameVersion", "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", SignatureType::NORMAL, 0x9, 0x0 },
	{ "GameBuild", "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", SignatureType::NORMAL, 0x18, 0x0 },
	{ "GameReleaseDate", "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 8D 15 ? ? ? ?", SignatureType::NORMAL, 0x27, 0x0 },
	{ "InGameFlag", "48 83 EC 28 0F B6 15 ? ? ? ? C1 EA 02 83 E2 01", SignatureType::NORMAL, 0x7, 0x0 },
	{ "IsLoadingOrConnecting", "48 81 EC A8 00 00 00 8B 05 ? ? ? ? FF C8", SignatureType::NORMAL, 0x9, 0x0 },
	{ "RuneReady", "49 8B 47 20 85 18 0F 84 ? 00 00 00 0F B6 05 ? ? ? ? 85 C3 0F 87 ? 00 00 00", SignatureType::NORMAL, 0xF, 0x0 },
	{ "ActiveTerrainSpell", "48 83 3D ? ? ? ? 00 75 ? 48 83 3D ? ? ? ? 00 0F 84 ? ? ? ? 48 8D 0D ? ? ? ? 48 89 7C 24 50", SignatureType::NORMAL, 0x1B, 0x0 }
	// Player name = 33 C0 48 8D 0D ? ? ? ? 38 05 ? ? ? ? 48 0F 45 C1 C3
	// Matches two functions, one is unknown the other contain playername offset
};

static std::list<OffsetPattern> funcPatterns
{
	{ "CheckSpellAttribute", "40 53 48 83 EC 20 41 8B D8 48 85 C9 74 14 48 63 D2 E8 ? ? ? ? 85 C3 74 08 B0 01 48 83 C4 20", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_ExecuteBuffer", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 70 83 05 ? ? ? ?", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_GetLocalizedText", "0F B6 41 10 4C 8B DA 48 8D 15 ? ? ? ? 45 8B D0 44 8B 0C 82 41 C1 E9 07 41 F6 C1 01 74 ? 0F B6 81 C2 1A 00 00 EB", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameScript_GetText", "40 55 57 41 54 41 56 41 57 48 83 EC 20 48 8D 6C 24 20 4C 8B F9 48 89 5D 38 8B 0D ? ? ? ?", SignatureType::NORMAL, 0x0, 0x0 },
	{ "FrameTime_GetCurTimeMs", "8B F0 45 85 FF 75 ? E8 ? ? ? ? 44 8B F8 8B D6 8B CD 45 33 F6 E8 ? ? ? ? 48 85 C0 74 0C", SignatureType::ADD, 0x8, 0x4 },
	{ "PartyInfo_GetActiveParty", "E8 ? ? ? ? 0F B6 4D 10 4C 8B F0 41 8B 14 8F C1 EA 07 F6 C2 01 74 ? 48 85 C0 74 ? 48 8D 96 80 00 00 00", SignatureType::ADD, 0x1, 0x4 },
	{ "Party_FindMember", "40 53 48 83 EC 10 44 8B 91 78 01 00 00 33 C0 49 8B D8 4C 8B D9 45 85 D2 74 39 66 0F 1F 44 00 00", SignatureType::NORMAL, 0x0, 0x0 },
	{ "PetInfo_FindSpellById", "44 8B C9 48 8D 15 ? ? ? ? 45 33 C0 0F 1F 00 8B 02 8B C8 81 E1 00 00 00 3F 81 F9 00 00 00 01", SignatureType::NORMAL, 0x0, 0x0 },
	{ "PetInfo_SendPetAction", "4C 89 4C 24 20 48 89 4C 24 08 55 53 41 56 41 57 48 8D 6C 24 C8 48 81 EC 38 01 00 00 4C 8B F9 45 8B F0 B9 02 00 00 00 48 8B DA E8 ? ? ? ? 84 C0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Specialization_IsTalentSelectedById", "3B 15 ? ? ? ? 44 8B C9 73 34 8B C2 48 8D 0D ? ? ? ? 48 C1 E0 06 48 03 C8 74 22 45 85 C0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "SpellBook_CastSpell", "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 41 56 48 83 EC 50 41 0F B6 F1 48 63 D9 49 8B E8 44", SignatureType::NORMAL, 0x0, 0x0 },
	{ "SpellBook_FindSlotBySpellId", "44 8B C1 85 C9 0F 84 ? 00 00 00 84 D2 74 ? ? 8B 0D ? ? ? ? 33 D2 45 85 C9 74 ? 4C 8B 15", SignatureType::NORMAL, 0x0, 0x0 },
	{ "SpellBook_FindSpellOverrideById", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30 45 0F B6 F0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "SpellBook_GetOverridenSpell", "48 89 5C 24 08 57 48 83 EC 20 48 63 F9 8B DA 85 D2 75 ? E8 ? ? ? ? 8B D8 85 C0 75 ? E8", SignatureType::NORMAL, 0x0, 0x0 },
	{ "SpellDB_GetRow", "40 53 48 83 EC 20 8B D9 85 C9 74 13 E8 ? ? ? ? 8B D0 8B CB 48 83 C4 20 5B E9 ? ? ? ? 33 C0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_ClickSpell", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 40 49 8B F1 49 8B E8 4C 8B F2 8B D9 E8", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_GetMinMaxRange", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 49 8B D9 49 8B F8 8B F2 48 8B E9 E8 ? ? ? ? 89 44 24  28 4C 8B CB", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_GetSomeSpellInfo", "E9 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC 48 83 EC 48 E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_GetSpellCharges", "48 83 EC 40 44 0F B6 E2 4D 8B F1 33 D2 4D 8B F8 8B E9 E8 ? ? ? ? 33 DB 48 85 C0", SignatureType::NORMAL, -0x14, 0x0 },
	{ "Spell_GetSpellCooldown", "48 83 EC 58 44 8B D1 C6 44 24 48 00 F7 DA 48 8D 05 ? ? ? ? 41 8B D2 48 1B C9 81 E1 B8 00 00", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_GetSpellType", "E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? 0F BE E8 8B 05 ? ? ? ? 8B CD 0B 05", SignatureType::ADD, 0xE, 0x4 },
	{ "Spell_HandleTerrainClick", "40 53 48 83 EC 30 B2 01 48 8B D9 E8 ? ? 00 00 85 C0", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_IsInRange", "4C 89 4C 24 20 57 41 56 41 57 48 81 EC 80 00 00 00 49 8B 40 08 4D 8B D0 48 C1 E8 3A 44 8B FA 4C 8B F1", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_IsPlayerSpell", "41 F6 C0 01 74 ? 8B CA E8 ? ? ? ? 84 C0 75 ? 8B CB E8 ? ? ? ? 84 C0 74 ? B0 01 48 8B 5C 24 40", SignatureType::ADD, 0x9, 0x4 },
	{ "Spell_IsSpellKnown", "48 89 5C 24 08 57 48 83 EC 30 0F B6 41 10 48 8B F9 48 8D 0D ? ? ? ? 8B DA 44 8B 04 81 41 C1 E8 07", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Spell_IsStealable", "48 89 5C 24 08 48 89 6C 24 10 56 57 41 54 41 56 41 57 48 83 EC 20 45 8B F0 48 8B FA 48 8B D9 E8", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_CanAttack", "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 0F B6 41 10 48 8B ? 48 8D 0D ? ? ? ? 48 ? ?", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_GetAuraByIndex", "44 8B 81 ? ? 00 00 48 81 C1 ? ? 00 00 41 83 F8 FF 75 ? 8B 01 EB ? 41 8B C0 3B D0 73 ? 8B C2 48 69 D0 ? 00 00 00 41 83 F8 FF 75 ? 48 8B 49 08", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_GetFacing", "48 8B 89 F0 00 00 00 F3 0F 10 49 30 E9", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_GetPosition", "40 53 48 83 EC 20 48 8B 89 F0 00 00 00 48 8B DA 4C 8D 41 20 E8 ? ? ? ? 48 8B C3 48 83 C4 20 5B C3", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_GetPower", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 41 0F B6 E8 0F B6 DA 4C 8D 05", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_GetPowerMax", "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 41 0F B6 F0 0F B6 FA 4C 8D 05 ? ? ? ? BA 20 00 00 00", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_Interact", "40 57 48 83 EC 20 48 8B F9 E8 ? ? ? ? 48 85 C0 75 0B", SignatureType::NORMAL, 0x0, 0x0 },
	{ "Unit_IsFriendly", "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ? ? ? ? 83 F8 04 7D ? 48 8B D7 48 8B CB", SignatureType::NORMAL, 0x0, 0x0 },
	//{ "WorldFrame_Intersect", "48 83 EC 38 F3 0F 10 0A 4C 8B D1 F3 0F 10 52 04 F3 0F 5C 51 04 F3 0F 5C 09 F3 0F 10 42 08 F3 0F", SignatureType::NORMAL, 0x0, 0x0 },
	{ "WorldFrame_Intersect", "F3 41 0F 10 08 F3 41 0F 10 50 04 F3 0F 5C 52 04 F3 0F 5C 0A F3 41 0F 10 40 08 F3 0F 5C 42 08 F3 0F 59 D2 F3 0F 59 C9 F3 0F 59 C0 F3 0F 58 D1 F3 0F 58 D0 0F 54 15 06 E0", SignatureType::NORMAL, 0x0, 0x0 },
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