#pragma once

#include "clepta/clepta.hpp"

#include <map>
#include <string>

struct dump_info
{
	const char* target;
	std::map<std::string, clepta::pattern> offsets;
	std::map<std::string, clepta::pattern> functions;
};

dump_info classic_patterns
{
	"WowClassic.exe",
	{
		{ "ActiveTerrainSpell", { "48 83 3D ? ? ? ? 00 75 ? 48 83 3D ? ? ? ? 00 0F 84 ? ? ? ? 48 8D 0D ? ? ? ? 48 89 7C 24 50", clepta::pattern::deference, 0x1B } },
		{ "ObjectMgrPtr", { "4C 8B 05 ? ? ? ? 48 8B F2 48 8B", clepta::pattern::deference, 0x3 } },
		//{ "CooldownPtr", "48 8D 05 ? ? ? ? 48  83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48", clepta::pattern::deference, 0x3 },
		{ "LastHardwareAction", { "BA 00 20 00 00 8B 35 ? ? ? ? 48 8B CF 44 8B C6", clepta::pattern::deference, 0x7 } },
		//{ "LocalPlayerGUID", "48 8D 05 ? ? ? ? 41 B8 03 00 00 00 0F 1F 00", clepta::pattern::deference, 0x3 },
		{ "CameraBase", { "48 8B 05 ? ? ? ? 48 8B 88 ? ? 00 00 48 8B 43 ?", clepta::pattern::deference, 0x3 } },
		//{ "ZoneID", "44 3B 2D ? ? ? ? 44 8B 44 24 40 8B 54 24 48", clepta::pattern::deference, 0x3 },
		//{ "IsTexting", "44 39 25 ? ? ? ? 0F 8E DF 00 00 00 33 D2 44 89 64 24 20", clepta::pattern::deference, 0x3 },
		{ "ActionBarFirstSlot", { "48 8D 15 ? ? ? ? 48 63 C8 48 B8 00 00 00 00", clepta::pattern::deference, 0x3 } },
		//{ "MouseOverGUID", "BA 01 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 74 12", clepta::pattern::deference, 0x8 },
		//{ "ClickToMoveTrigger", "48 63 05 ? ? ? ? 48 8D 0C 40 48 8D 05", clepta::pattern::deference, 0x3 },
		{ "GameVersion", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", clepta::pattern::deference, 0x9 } },
		{ "GameBuild", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", clepta::pattern::deference, 0x18 } },
		{ "GameReleaseDate", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 8D 15 ? ? ? ?", clepta::pattern::deference, 0x27 } },
		{ "InGameFlag", { "0F B6 05 ? ? ? ? C0 E8 06 24 01 C3", clepta::pattern::deference, 0x3 } },
		{ "InGameFlag", { "48 83 EC 28 0F B6 15 ? ? ? ? C1 EA 02 83 E2 01", clepta::pattern::deference, 0x7 } },
		{ "IsLoadingOrConnecting", { "48 81 EC A8 00 00 00 8B 05 ? ? ? ? FF C8", clepta::pattern::deference, 0x9 } },
		{ "RuneReady", { "49 8B 47 20 85 18 0F 84 ? 00 00 00 0F B6 05 ? ? ? ? 85 C3 0F 87 ? 00 00 00", clepta::pattern::deference, 0xF } },

		// NoxiaZ
		{ "CorpsePosition", { "49 8B F8 48 8D 0D ? ? ? ? 48 8B DA E8 ? ? ? ?", clepta::pattern::deference, 0x6 } },
		{ "NameCacheBase",{ "48 8D 3D ? ? ? ? 48 8B DF 48 8D 0D ? ? ? ? 48 83 CB 01 48 89 1D ? ? ? ? E8 ? ? ? ? 33 C9 48 89 1D ? ? ? ?", clepta::pattern::deference, 0x3  } },
		{ "SpellBook",  { "4C 8B 0D ? ? ? ? 0F 1F 44 00 ? 8B C2 49 8B 0C C1 8B 41 04 3B D8 75 05 83 39 01 74 5A 83 39 03", clepta::pattern::deference, 0x3 } },
		{ "RedMessage",  { "48 8D 15 ? ? ? ? 41 B8 ? ? ? ? 48 8D 8D ? ? ? ? 90 0F B6 01", clepta::pattern::deference, 0x3 } },
	},
	{
		{ "CheckSpellAttribute", "40 53 48 83 EC 20 41 8B D8 48 85 C9 74 14 48 63 D2 E8 ? ? ? ? 85 C3 74 08 B0 01 48 83 C4 20" },
		{ "FrameScript_ExecuteBuffer", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 70 83 05 ? ? ? ?" },
		{ "FrameScript_GetLocalizedText", "0F B6 41 10 4C 8B DA 48 8D 15 ? ? ? ? 45 8B D0 44 8B 0C 82 41 C1 E9 07 41 F6 C1 01 74 ? 0F B6 81 C2 1A 00 00 EB" },
		{ "FrameScript_GetText", "40 55 57 41 54 41 56 41 57 48 83 EC 20 48 8D 6C 24 20 4C 8B F9 48 89 5D 38 8B 0D ? ? ? ?" },
		{ "FrameTime_GetCurTimeMs", { "E8 ? ? ? ? 8B F8 E8 ? ? ? ? 8B 4B 04 83 F9 01 74 ? 83 4B ? 02 4C 8D 44 ? 30", clepta::pattern::deference, 0x1 } },
		// Item offsets only used in development and will get outdated (as they are not used in production, duh..)
		{ "Item_GetSpellIdById", { "E8 ? ? ? ? 3B 47 48 74 ? 41 8B CE E8 ? ? ? ? 3B 47 48 0F 85 ? ? 00 00", clepta::pattern::deference, 0xE } },
		{ "Item_GetSpellIdByObj", { "41 55 41 56 41 57 48 81 EC 80 00 00 00 44 8B FA 45 33 C0 8B 91 D8 00 00 00 45 33 E4", clepta::pattern::normal, -0xF } },
		{ "Item_UseItem", { "41 55 41 56 41 57 48 81 EC 80 00 00 00 44 8B FA 45 33 C0 8B 91 D8 00 00 00 45 33 E4", clepta::pattern::normal, -0xF } },
		{ "PartyInfo_GetActiveParty", { "E8 ? ? ? ? 48 8D 4C ? 30 48 8B D8 E8 ? ? ? ? 48 8B 4C ? 20", clepta::pattern::deference, 0x1 } },
		{ "Party_FindMember", { "40 53 48 83 EC 10 44 8B 91 78 01 00 00 33 C0 49 8B D8 4C 8B D9 45 85 D2 74 39 66 0F 1F 44 00 00", clepta::pattern::normal } },
		{ "PetInfo_FindSpellById", { "44 8B C9 48 8D 15 ? ? ? ? 45 33 C0 0F 1F 00 8B 02 8B C8 81 E1 00 00 00 3F 81 F9 00 00 00 01", clepta::pattern::normal } },
		{ "PetInfo_SendPetAction", { "4C 89 4C 24 20 48 89 4C 24 08 55 53 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? 01 00 00 4C 8B F9 45 8B F0 B9 02 00 00 00 48 8B DA E8 ? ? ? ? 84 C0", clepta::pattern::normal } },
		{ "Specialization_IsTalentSelectedById", { "3B 15 ? ? ? ? 44 8B C9 73 34 8B C2 48 8D 0D ? ? ? ? 48 C1 E0 06 48 03 C8 74 22 45 85 C0", clepta::pattern::normal } },
		{ "SpellBook_CastSpell", { "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 41 56 48 83 EC 50 41 0F B6 F1 48 63 D9 49 8B E8 44", clepta::pattern::normal } },
		{ "SpellBook_FindSlotBySpellId", { "44 8B C1 85 C9 0F 84 86 00 00 00 ? D2 74 51 44 8B 0D ? ? ? ? 33 D2 45 85 C9 74 74 4C 8B 15", clepta::pattern::normal } },
		{ "SpellBook_FindSpellOverrideById", { "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83 EC 30 45 0F B6 F0", clepta::pattern::normal } },
		{ "SpellBook_GetOverridenSpell", { "48 89 5C 24 08 57 48 83 EC 20 48 63 F9 8B DA 85 D2 75 ? E8 ? ? ? ? 8B D8 85 C0 75 ? E8", clepta::pattern::normal } },
		{ "SpellDB_GetRow", { "40 53 48 83 EC 20 8B D9 85 C9 74 13 E8 ? ? ? ? 8B D0 8B CB 48 83 C4 20 5B E9 ? ? ? ? 33 C0", clepta::pattern::normal } },
		{ "Spell_ClickSpell", { "E8 ? ? ? ? B9 02 00 00 00 E8 ? ? ? ? EB ? C7 05 ? ? ? ? FF FF FF FF", clepta::pattern::deference, 0x1 } },
		{ "Spell_GetMinMaxRange", { "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 49 8B D9 49 8B F8 8B F2 48 8B E9 E8 ? ? ? ? 89 44 24  28 4C 8B CB", clepta::pattern::normal } },
		{ "Spell_GetSomeSpellInfo", { "E9 ? ? ? ? CC CC CC CC CC CC CC CC CC CC CC 48 83 EC 48 E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8", clepta::pattern::normal } },
		{ "Spell_GetSpellCharges", { "48 83 EC 40 44 0F B6 E2 4D 8B F1 33 D2 4D 8B F8 8B E9 E8 ? ? ? ? 33 DB 48 85 C0", clepta::pattern::normal, -0x14 } },
		{ "Spell_GetSpellCooldown", { "48 83 EC 58 44 8B D1 C6 44 24 48 00 41 F7 D8 48 8D 05 ? ? ? ? 44 8B C2 41 8B D2 48 1B C9 81 E1 B8 00 00 00", clepta::pattern::normal } },
		{ "Spell_GetSpellType", { "E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? 0F BE E8 8B 05 ? ? ? ? 8B CD 0B 05", clepta::pattern::deference, 0xE } },
		{ "Spell_HandleTerrainClick", { "40 53 48 83 EC 30 B2 01 48 8B D9 E8 ? ? 00 00 85 C0", clepta::pattern::normal } },
		{ "Spell_IsInRange", { "4C 89 4C 24 20 57 41 56 41 57 48 81 EC 80 00 00 00 49 8B 40 08 4D 8B D0 48 C1 E8 3A 44 8B FA 4C 8B F1", clepta::pattern::normal } },
		{ "Spell_IsPlayerSpell", { "81 FB 51 0A 00 00 75 ? 8B CB E8 ? ? 00 00 84 C0", clepta::pattern::deference, 0xB } },
		{ "Spell_IsSpellKnown", { "E8 ? ? 01 00 84 C0 0F 85 ? 00 00 00 48 8B ? E8 ? ? FF FF 3D B7 FD 01 00 7F", clepta::pattern::deference, 0x1 } },
		{ "Spell_IsStealable", { "48 89 5C 24 08 48 89 6C 24 10 56 57 41 54 41 56 41 57 48 83 EC 20 45 8B F0 48 8B FA 48 8B D9 E8", clepta::pattern::normal } },
		{ "Unit_CanAttack", { "E8 ? ? ? FF 84 C0 74 9E F7 C3 00 00 30 00", clepta::pattern::deference, 0x1 } },
		{ "Unit_GetAuraByIndex", { "49 8B ? E8 ? ? ? FF 8B 48 20 83 F9 FF 75 04 8B 10 EB 02 8B D1", clepta::pattern::deference, 0x4 } },
		{ "Unit_GetFacing", { "48 8B 89 ? ? 00 00 F3 0F 10 49 30 E9", clepta::pattern::normal } },
		{ "Unit_GetPosition", { "40 53 48 83 EC 20 48 8B 89 ? ? 00 00 48 8B DA 4C 8D 41 ? E8 ? ? ? ? 48 8B C3 48 83 C4 20 5B C3", clepta::pattern::normal } },
		{ "Unit_GetPower", { "80 FB FE 75 ? 48 8B ? ? ? 00 00 B8 FF FF FF 7F 48 3B C8 0F 4E C1", clepta::pattern::normal, -0x66 } },
		{ "Unit_GetPowerMax", { "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 41 0F B6 F0 0F B6 FA 4C 8D 05 ? ? ? ? BA 20 00 00 00", clepta::pattern::normal } },
		{ "Unit_Interact", { "40 57 48 83 EC 20 48 8B F9 E8 ? ? ? ? 48 85 C0 75 0B", clepta::pattern::normal } },
		{ "Unit_IsFriendly", { "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ? ? ? ? 83 F8 04 7D ? 48 8B D7 48 8B CB", clepta::pattern::normal } },
		{ "WorldFrame_Intersect", { "48 83 EC 38 F3 0F 10 0A 4C 8B D1 F3 0F 10 52 04 F3 0F 5C 51 04 F3 0F 5C 09 F3 0F 10 42 08 F3 0F", clepta::pattern::normal } }
	}
};

dump_info retail_patterns
{
	"Wow.exe",
	{
		{ "ActiveTerrainSpell", { "48 83 3D ? ? ? ? 00 75 ? 48 83 3D ? ? ? ? 00 0F 84 ? ? ? ? 48 8D 0D ? ? ? ? 48 89 7C 24 50", clepta::pattern::deference, 0x1B } },
		{ "ObjectMgrPtr", { "41 0F 10 00 48 8B 0D ? ? ? ? 0F 29 44 24 20 48 85 ? ? ? 48", clepta::pattern::deference, 0x7 } },
		//{ "NameCacheBase", "? ? ? ? BA 10 00 00 00 48 83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? E8 ? ? ? ? 33 C9 C7 05 ? ? ? ? FF FF FF FF", clepta::pattern::deference },
		//{ "CooldownPtr", "48 8D 05 ? ? ? ? 48  83 C8 01 48 8D 0D ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48 8D 05 ? ? ? ? 48 83 C8 01 48 89 05 ? ? ? ? 48", clepta::pattern::deference, 0x3 },
		{ "LastHardwareAction", { "BA 00 20 00 00 8B 35 ? ? ? ? 48 8B CF 44 8B C6", clepta::pattern::deference, 0x7 } },
		//{ "LocalPlayerGUID", "48 8D 05 ? ? ? ? 41 B8 03 00 00 00 0F 1F 00", clepta::pattern::deference, 0x3 },
		{ "CameraBase", { "48 8B 05 ? ? ? ? 48 8B 88 ? ? 00 00 48 8B 43 ?", clepta::pattern::deference, 0x3 } },
		//{ "ZoneID", "44 3B 2D ? ? ? ? 44 8B 44 24 40 8B 54 24 48", clepta::pattern::deference, 0x3 },
		//{ "IsTexting", "44 39 25 ? ? ? ? 0F 8E DF 00 00 00 33 D2 44 89 64 24 20", clepta::pattern::deference, 0x3 },
		{ "ActionBarFirstSlot", { "48 8D 15 ? ? ? ? 48 63 C8 48 B8 00 00 00 00", clepta::pattern::deference, 0x3 } },
		//{ "MouseOverGUID", "BA 01 00 00 00 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 85 C0 74 12", clepta::pattern::deference, 0x8 },
		//{ "ClickToMoveTrigger", "48 63 05 ? ? ? ? 48 8D 0C 40 48 8D 05", clepta::pattern::deference, 0x3 },
		{ "GameVersion", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", clepta::pattern::deference, 0x9 } },
		{ "GameBuild", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8", clepta::pattern::deference, 0x18 } },
		{ "GameReleaseDate", { "40 53 48 83 EC 20 48 8D 15 ? ? ? ? 48 8B D9 E8 ? ? ? ? 48 8D 15 ? ? ? ? 48 8B CB E8 ? ? ? ? 48 8D 15 ? ? ? ?", clepta::pattern::deference, 0x27 } },
		{ "InGameFlag", { "0F B6 05 ? ? ? ? C0 E8 06 24 01 C3", clepta::pattern::deference, 0x3 } },
		{ "IsLoadingOrConnecting", { "48 81 EC A8 00 00 00 8B 05 ? ? ? ? FF C8", clepta::pattern::deference, 0x9 } },
		{ "RuneReady", { "49 8B 47 20 85 18 0F 84 ? 00 00 00 0F B6 05 ? ? ? ? 85 C3 0F 87 ? 00 00 00", clepta::pattern::deference, 0xF } },
		// Player name = 33 C0 48 8D 0D ? ? ? ? 38 05 ? ? ? ? 48 0F 45 C1 C3
		// Matches two functions, one is unknown the other contain playername offset
	},
	{
		{ "CheckSpellAttribute", "48 85 C9 74 0C 48 63 C2 44 85 04 81 74 03 B0 01 C3 32 C0 C3" },
		{ "FrameScript_ExecuteBuffer", "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 56 48 83 EC 70 83 05 ? ? ? ?" },
		{ "FrameScript_GetLocalizedText", "0F B6 41 10 4C 8B DA 48 8D 15 ? ? ? ? 45 8B D0 44 8B 0C 82 41 C1 E9 07 41 F6 C1 01 74 ? 0F B6 81 C2 1A 00 00 EB" },
		{ "FrameScript_GetText", "40 55 57 41 54 41 56 41 57 48 83 EC 20 48 8D 6C 24 20 4C 8B F9 48 89 5D 38 8B 0D ? ? ? ?" },
		{ "FrameTime_GetCurTimeMs", { "E8 ? ? ? ? 8B F8 E8 ? ? ? ? 8B 4B 04 83 F9 01 74 ? 83 4B ? 02 4C 8D 44 ? 30", clepta::pattern::deference, 0x1 } },
		// Item offsets only used in development and will get outdated (as they are not used in production, duh..)
		{ "Item_GetSpellIdById", { "E8 ? ? ? ? 3B 47 48 74 ? 41 8B CE E8 ? ? ? ? 3B 47 48 0F 85 ? ? 00 00", clepta::pattern::deference, 0xE } },
		{ "Item_GetSpellIdByObj", { "41 55 41 56 41 57 48 81 EC 80 00 00 00 44 8B FA 45 33 C0 8B 91 D8 00 00 00 45 33 E4", clepta::pattern::normal, -0xF } },
		{ "Item_UseItem", { "41 55 41 56 41 57 48 81 EC 80 00 00 00 44 8B FA 45 33 C0 8B 91 D8 00 00 00 45 33 E4", clepta::pattern::normal, -0xF } },
		{ "PartyInfo_GetActiveParty", { "E8 ? ? ? ? 48 8D 4C ? 30 48 8B D8 E8 ? ? ? ? 48 8B 4C ? 20", clepta::pattern::deference, 0x1 } },
		{ "Party_FindMember", { "40 53 48 83 EC 10 44 8B 91 78 01 00 00 33 C0 49 8B D8 4C 8B D9 45 85 D2 74 39 66 0F 1F 44 00 00", clepta::pattern::normal } },
		{ "PetInfo_FindSpellById", { "44 8B C9 48 8D 15 ? ? ? ? 45 33 C0 0F 1F 00 8B 02 8B C8 81 E1 00 00 00 3F 81 F9 00 00 00 01", clepta::pattern::normal } },
		{ "PetInfo_SendPetAction", { "4C 89 4C 24 20 48 89 4C 24 08 55 53 41 56 41 57 48 8D 6C 24 ? 48 81 EC ? 01 00 00 4C 8B F9 45 8B F0 B9 02 00 00 00 48 8B DA E8 ? ? ? ? 84 C0", clepta::pattern::normal } },
		{ "Specialization_IsTalentSelectedById", { "3B 15 ? ? ? ? 44 8B C9 73 34 8B C2 48 8D 0D ? ? ? ? 48 C1 E0 06 48 03 C8 74 22 45 85 C0", clepta::pattern::normal } },
		{ "SpellBook_CastSpell", { "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 41 56 48 83 EC 50 41 0F B6 F1 48 63 D9 49 8B E8 44", clepta::pattern::normal } },
		{ "SpellBook_FindSlotBySpellId", { "44 8B C1 85 C9 0F 84 86 00 00 00 ? D2 74 51 44 8B 0D ? ? ? ? 33 D2 45 85 C9 74 74 4C 8B 15", clepta::pattern::normal } },
		{ "SpellBook_FindSpellOverrideById", { "8B 0C E8 E8 ? ? ? ? 8B D0 48 8D 0D ? ? ? ? 8B F0 E8 ? ? ? ? 84 C0 74 24 45 85 F6 74 11", clepta::pattern::deference, 0x4 } },
		{ "SpellBook_GetOverridenSpell", { "48 89 5C 24 08 57 48 83 EC 20 48 63 F9 8B DA 85 D2 75 ? E8 ? ? ? ? 8B D8 85 C0 75 ? E8", clepta::pattern::normal } },
		{ "SpellDB_GetRow", { "40 53 48 83 EC 20 8B D9 85 C9 74 13 E8 ? ? ? ? 8B D0 8B CB 48 83 C4 20 5B E9 ? ? ? ? 33 C0", clepta::pattern::normal } },
		{ "Spell_ClickSpell", { "E8 ? ? ? ? B9 02 00 00 00 E8 ? ? ? ? EB ? C7 05 ? ? ? ? FF FF FF FF", clepta::pattern::deference, 0x1 } },
		{ "Spell_GetMinMaxRange", { "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 49 8B D9 49 8B F8 8B F2 48 8B E9 E8 ? ? ? ? 89 44 24  28 4C 8B CB", clepta::pattern::normal } },
		{ "Spell_GetSomeSpellInfo", { "E8 ? ? ? ? 48 8B 5E 20 48 83 C6 18 48 8B E8 48 3B DE 0F 84 B8 01 00 00 48 8D ? ? ? ? FE 0F 1F 00", clepta::pattern::deference, 0x1} },
		{ "Spell_GetSpellCharges", { "F3 0F 11 44 24 68 48 89 44 24 20 E8 ? ? ? ? 83 7C 24 60 00 7E 76 66 0F 6E C8 48 8B CF F3 0F E6 C9", clepta::pattern::deference, 0xC} },
		{ "Spell_GetSpellCooldown", { "48 83 EC 58 44 8B D1 C6 44 24 48 00 F7 DA 48 8D 05 ? ? ? ? 41 8B D2 48 1B C9 81 E1 B8 00 00", clepta::pattern::normal } },
		{ "Spell_GetSpellType", { "E8 ? ? ? ? 48 85 C0 74 ? 48 8B C8 E8 ? ? ? ? 0F BE E8 8B 05 ? ? ? ? 8B CD 0B 05", clepta::pattern::deference, 0xE } },
		{ "Spell_HandleTerrainClick", { "40 53 48 83 EC 30 B2 01 48 8B D9 E8 ? ? 00 00 85 C0", clepta::pattern::normal } },
		{ "Spell_IsInRange", { "4C 89 4C 24 20 57 41 56 41 57 48 81 EC 80 00 00 00 49 8B 40 08 4D 8B D0 48 C1 E8 3A 44 8B FA 4C 8B F1", clepta::pattern::normal } },
		{ "Spell_IsPlayerSpell", { "81 FB 51 0A 00 00 75 ? 8B CB E8 ? ? 00 00 84 C0", clepta::pattern::deference, 0xB } },
		{ "Spell_IsSpellKnown", { "E8 ? ? 01 00 84 C0 0F 85 ? 00 00 00 48 8B ? E8 ? ? FF FF 3D B7 FD 01 00 7F", clepta::pattern::deference, 0x1 } },
		{ "Spell_IsStealable", { "48 89 5C 24 08 48 89 6C 24 10 56 57 41 54 41 56 41 57 48 83 EC 20 45 8B F0 48 8B FA 48 8B D9 E8", clepta::pattern::normal } },
		{ "Unit_CanAttack", { "E8 ? ? ? FF 84 C0 74 9E F7 C3 00 00 30 00", clepta::pattern::deference, 0x1 } },
		{ "Unit_GetAuraByIndex", { "49 8B ? E8 ? ? ? FF 8B 48 20 83 F9 FF 75 04 8B 10 EB 02 8B D1", clepta::pattern::deference, 0x4 } },
		{ "Unit_GetFacing", { "48 8B 89 ? ? 00 00 F3 0F 10 49 30 E9", clepta::pattern::normal } },
		{ "Unit_GetPosition", { "40 53 48 83 EC 20 48 8B 89 ? ? 00 00 48 8B DA 4C 8D 41 ? E8 ? ? ? ? 48 8B C3 48 83 C4 20 5B C3", clepta::pattern::normal } },
		{ "Unit_GetPower", { "80 FB FE 75 ? 48 8B ? ? ? 00 00 B8 FF FF FF 7F 48 3B C8 0F 4E C1", clepta::pattern::normal, -0x73 } },
		{ "Unit_GetPowerMax", { "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 41 0F B6 F0 0F B6 FA 4C 8D 05 ? ? ? ? BA 20 00 00 00", clepta::pattern::normal } },
		{ "Unit_Interact", { "40 57 48 83 EC 20 48 8B F9 E8 ? ? ? ? 48 85 C0 75 0B", clepta::pattern::normal } },
		{ "Unit_IsFriendly", { "48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ? ? ? ? 83 F8 04 7D ? 48 8B D7 48 8B CB", clepta::pattern::normal } },
		//{ "WorldFrame_Intersect", "48 83 EC 38 F3 0F 10 0A 4C 8B D1 F3 0F 10 52 04 F3 0F 5C 51 04 F3 0F 5C 09 F3 0F 10 42 08 F3 0F", clepta::pattern::normal },
		{ "WorldFrame_GetCurrent", { "E8 ? ? ? ? 48 8B C8 E8 ? ? ? ? 48 8B D8 48 85 C0 74 18 0F", clepta::pattern::deference, 0x1 } },
		{ "WorldFrame_Intersect", { "49 8B CC E8 ? ? ? ? 84 C0 75 ? F2 0F 10 44 24 50", clepta::pattern::deference, 0x4 } },
	}
};
