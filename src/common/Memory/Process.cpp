#include "Process.hpp"

Process::Process() :
	m_ProcessName("")
{
	m_Process = GetCurrentProcess();
	// HACK
	// Need to implement so if name == "" then get current procName
	m_BaseAddress = GetModuleAddress("Wow.exe");
}

Process::Process(uint32 processId, uint32 desiredAccess) :
	m_ProcessName("")
{
	m_Process = OpenProcess(desiredAccess, false, processId);
}

Process::Process(const std::string& processName) :
	m_ProcessName(processName)
{
	m_ProcessName = processName;
	m_Process = nullptr;
}

Process::Process(void* handle) :
	m_ProcessName("")
{
	m_Process = handle;
}

Process::~Process()
{

}

bool Process::Open(uint32 desiredAccess)
{
	if (!m_ProcessName.length())
		return false;

	auto procs = EnumProcesses(m_ProcessName);

	if (!procs.empty())
	{
		m_Process = OpenProcess(desiredAccess, false, procs[0].th32ProcessID);
		m_BaseAddress = GetModuleAddress(m_ProcessName);
	}

	return IsValidProcess();
}

bool Process::Close()
{
	return CloseHandle(m_Process);
}

// Debug = SE_DEBUG_NAME, true
bool Process::SetPrivilege(const std::string& privilege, bool enablePrivilege)
{
	TOKEN_PRIVILEGES tkp = { 0, 0, 0, 0 };
	LUID luid = { 0, 0 };
	void* hToken = nullptr;
	bool status = false;

	if (OpenProcessToken(m_Process, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValueA(0, privilege.c_str(), &luid))
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Luid = luid;
			tkp.Privileges[0].Attributes = enablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;

			if (AdjustTokenPrivileges(hToken, false, &tkp, 0, 0, 0))
				status = true;
		}
	}

	if (hToken)
		CloseHandle(hToken);

	return status;
}

uint32 Process::Allocate(uint32 size, void*& addr)
{
	SetLastError(ERROR_SUCCESS);

	addr = VirtualAllocEx(m_Process, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	return GetLastError();
}

uint32 Process::Free(void* addr)
{
	SetLastError(ERROR_SUCCESS);

	VirtualFreeEx(m_Process, addr, 0, MEM_RELEASE);

	return GetLastError();
}

uint32 Process::Read(uint64 address, uint64 size, PVOID pResult)
{
	uint64 read = 0;

	if (address == 0)
		return ERROR_INVALID_ADDRESS;

	if (!ReadProcessMemory(m_Process, (LPCVOID)address, pResult, size, &read) || read != size)
		return GetLastError();

	return ERROR_SUCCESS;
}

uint32 Process::Write(uint64 address, uint64 size, PVOID pData)
{
	uint64 written = 0;

	if (address == 0)
		return ERROR_INVALID_ADDRESS;

	if (!WriteProcessMemory(m_Process, (LPVOID)address, pData, size, &written) || written != size)
		return GetLastError();

	return ERROR_SUCCESS;
}

bool Process::CompareBytes(const uchar* bytes, const char* pattern)
{
	for (; *pattern; *pattern != ' ' ? ++bytes : bytes, ++pattern)
	{
		if (*pattern == ' ' || *pattern == '?')
			continue;

		if (*bytes != getByte(pattern))
			return false;

		++pattern;
	}

	return true;
}

uintptr Process::FindPattern(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset)
{
	return FindPattern(pattern, type, patternOffset, addressOffset, GetBaseAddress(), GetBaseSize());
}

uintptr Process::FindPattern(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset, uint64 start, const char* mnemonic = "")
{
	int64 size = GetFirstMnemonic(start, mnemonic) - start;

	return FindPattern(pattern, type, patternOffset, addressOffset, start, size);
}

uintptr Process::FindPattern(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset, uint64 start, uint64 size)
{
	std::vector<uint8> bytes;
	uint64 base = start;
	uint64 length = size;

	bytes.resize(length);

	Read(base, length, bytes.data());
	uint8* pb = reinterpret_cast<uint8*>(bytes.data());

	for (auto off = 0UL; off < length; ++off)
	{
		if (CompareBytes(pb + off, pattern))
		{
			uint64 add = base + off + patternOffset;

			if (type & SignatureType::READ)
				add = Read<uintptr>(add);

			if (type & SignatureType::SUBTRACT)
				add -= base;

			return add + addressOffset;
		}
	}

	return 0;
}

std::list<uintptr> Process::FindPatternAll(const char* pattern, SignatureType type, uintptr patternOffset, uintptr addressOffset, uint64 start, const char* mnemonic)
{
	std::list<uintptr> ret;
	uintptr addr = 0;
	int64 size = GetFirstMnemonic(start, mnemonic) - start;

	while ((addr = FindPattern(pattern, type, patternOffset, addressOffset, start, size)) > 0 && size > 0)
	{
		ret.push_back(addr);

		size -= addr - start + 1;
		start = addr + 1;
	}

	return ret;
}

uintptr Process::GetFirstMnemonic(uintptr start, const char* mnemonic)
{
	uintptr ret = 0;
	csh handle;
	size_t count = 0x1000;
	uint64 address = start;

	uint8* bytes = new uint8[count];
	Read(start, count, bytes);
	const uint8* cbytes = bytes;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return 0;

	cs_insn *insn = cs_malloc(handle);

	while (cs_disasm_iter(handle, &cbytes, &count, &address, insn))
	{
		if (strcmp(insn->mnemonic, mnemonic) == 0)
		{
			ret = insn->address;
			break;
		}
	}

	cs_free(insn, 1);
	delete[] bytes;
	cs_close(&handle);

	return ret;
}

uint64 Process::GetModuleAddress(const std::string& moduleName)
{
	HANDLE hSnapshot;
	MODULEENTRY32 mod;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetPid());

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	mod.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &mod))
	{
		CloseHandle(hSnapshot);
		return 0;
	}

	do
	{
		if (_stricmp(moduleName.c_str(), mod.szModule) == 0)
		{
			CloseHandle(hSnapshot);
			m_BaseSize = mod.modBaseSize;
			return reinterpret_cast<uint64>(mod.modBaseAddr);
		}
	} while (Module32Next(hSnapshot, &mod));

	CloseHandle(hSnapshot);

	return 0;
}

void* Process::GetHandle()
{
	return m_Process;
}

uint32 Process::GetPid()
{
	return GetProcessId(m_Process);
}

bool Process::IsValidProcess()
{
	if (m_Process == INVALID_HANDLE_VALUE)
		return false;

	return (WaitForSingleObject(m_Process, 0) == WAIT_TIMEOUT);
}

std::vector<PROCESSENTRY32> EnumProcesses(const std::string& name)
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	std::vector<PROCESSENTRY32> ret;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return ret;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32))
	{
		CloseHandle(hSnapshot);
		return ret;
	}

	do
	{
		if (_stricmp(name.c_str(), pe32.szExeFile) == 0)
			ret.push_back(pe32);
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);

	return ret;
}