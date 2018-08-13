#pragma once

#include "Common.hpp"
#include "Process.hpp"

class MemoryObject
{
public:
	MemoryObject() {}
	MemoryObject(const MemoryObject& obj) :
		m_Process(obj.m_Process), m_Address(obj.m_Address) {}
	MemoryObject(std::shared_ptr<Process> process, uint64 address) :
		m_Process(process), m_Address(address) {}

	template <typename T>
	T Read(uint64 offset)
	{
		return m_Process->Read<T>(GetAbsoluteAddress(offset));
	}

	template <typename T>
	T ReadRelative(uint64 offset)
	{
		return m_Process->Read<T>(offset);
	}

	std::string ReadString(uint64 offset, uint16 maxLength = 32, bool relative = false)
	{
		char c = '\0';
		std::string ret = "";

		do
		{
			if (relative)
				c = ReadRelative<char>(offset + (sizeof(char) * ret.size()));
			else
				c = Read<char>(offset + (sizeof(char) * ret.size()));
			ret += c;
		} while (c != '\0' && ret.size() != maxLength);

		return ret;
	}

	template <typename T>
	T Dereference(uint64 offset)
	{
		return m_Process->Read<T>(m_Process->Read<uint64>(GetAbsoluteAddress(offset)));
	}

	std::shared_ptr<Process> GetProcess() const { return m_Process; }
	void SetProcess(std::shared_ptr<Process> process) { m_Process = process; }
	uint64 GetAddress() const { return m_Address; }
	void SetAddress(uint64 address) { m_Address = address; }
	uint64 GetAbsoluteAddress(uint64 offset) { return m_Address + offset; }

private:
	std::shared_ptr<Process> m_Process;
	uint64 m_Address;

};