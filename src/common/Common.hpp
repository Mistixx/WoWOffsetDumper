#pragma once

#include "Define.hpp"

#include <algorithm>
#include <array>
#include <codecvt>
#include <exception>
#include <iomanip>
#include <list>
#include <map>
#include <memory>
#include <numeric>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <cerrno>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>

#if PLATFORM == PLATFORM_WINDOWS
	#define WIN32_LEAN_AND_MEAN	
	#include <Windows.h>
#endif