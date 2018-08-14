#pragma once

#include "Define.hpp"

#include <map>

static std::map<uint64, std::string> MirrorFlags
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