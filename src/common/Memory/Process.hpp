#pragma once

#include "Common.hpp"

#include <fstream>
#include <TlHelp32.h>

#define INRANGE(x,a,b)	(x >= a && x <= b) 
#define getBits( x )	(INRANGE(x,'0','9') ? (x - '0') : ((x&(~0x20)) - 'A' + 0xa))
#define getByte( x )	(getBits(x[0]) << 4 | getBits(x[1]))

enum SignatureType
{
	NORMAL = 0x0,
	READ = 0x1,
	SUBTRACT = 0x2
};

class Process
{
public:
	Process();
	Process(uint32 processId, uint32 desiredAccess = PROCESS_ALL_ACCESS);
	Process(const std::string& processName);
	Process(void* handle);
	~Process();

	bool Open(uint32 desiredAccess = PROCESS_ALL_ACCESS);
	bool Close();

	bool SetPrivilege(const std::string& privilege, bool enablePrivilege);

	uint32 Allocate(uint32 size, void*& addr);
	uint32 Free(void* addr);

	uint32 Read(uint64 address, uint64 size, PVOID result);
	uint32 Write(uint64 address, uint64 size, PVOID data);

	template <typename T>
	T Read(uint64 address)
	{
		T res;
		ZeroMemory(&res, sizeof(T));

		if (Read(address, sizeof(T), &res) != ERROR_SUCCESS)
			return res;

		return res;
	}

	template <typename T>
	uint32 Write(uint64 address, T data)
	{
		return Write(address, sizeof(T), &data);
	}

	uint32 WriteString(uint64 address, std::string data)
	{
		for (uint32 i = 0; i < data.size(); ++i)
			Write(address + (i * sizeof(char)), data[i]);

		return 0;
	}

	// Inspired by https://github.com/Y3t1y3t/CSGO-Dumper/blob/master/Dumper/src/Remote/Remote.cpp
	bool CompareBytes(const uchar* bytes, const char* pattern);
	uintptr FindPattern(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset);
	uintptr FindPattern(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset, uint64 start, uint64 size);
	std::list<uintptr> FindPatternAll(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset, uint64 start, uint8 endByte);

	uint64 GetModuleAddress(const std::string& moduleName);

	void* GetHandle();
	uint32 GetPid();
	uint64 GetBaseAddress() { return m_BaseAddress; }
	uint64 GetBaseSize() { return m_BaseSize; }

	bool IsValidProcess();

private:
	void* m_Process;
	std::string m_ProcessName;
	uint64 m_BaseAddress;
	uint64 m_BaseSize;

};

typedef std::shared_ptr<Process> ProcessPtr;

std::vector<PROCESSENTRY32> EnumProcesses(const std::string& name);