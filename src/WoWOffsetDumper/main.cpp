#include "Common.hpp"
#include "Dumper.hpp"

#include "capstone/capstone.h"

#include <iostream>

int32 PrintAndQuit(const std::string& str)
{
	std::cout << str << std::endl << std::endl;
	std::cout << "Press enter to terminate the program.";
	std::cin.get();
	return 0;
}

void TestCapstone()
{
#define CODE "\x55\x48\x8b\x05\xb8\x13\x00\x00"

	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return;
	count = cs_disasm(handle, (uint8*)CODE, sizeof(CODE) - 1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			std::cout << "0x" << std::hex << std::setfill('\0') << insn[j].address << ":\t" << insn[j].mnemonic << "\t\t" << insn[j].op_str << "\n";
		}

		cs_free(insn, count);
	}
	else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);
}

int main()
{
	ProcessPtr process;

	auto processes = EnumProcesses("Wow.exe");
	auto classic_processes = EnumProcesses("WowClassic.exe");
	for (auto p : classic_processes)
		processes.push_back(p);

	if (processes.size() > 1)
	{
		int selected = 0;
		std::cout << "Found multiple processes, please enter the number of the process you want to scan." << std::endl;
		for (int i = 0; i < processes.size(); ++i)
		{
			std::cout << "[" << i << "]: " << processes[i].th32ProcessID << std::endl;
		}
		std::cin >> selected;
		process = std::make_shared<Process>(processes[selected].th32ProcessID);
	}
	else if (processes.size() == 1)
		process = std::make_shared<Process>(processes.back().th32ProcessID);
	else
		return PrintAndQuit("No processes found.");

	if (!process->Open())
		return PrintAndQuit("Failed to open Wow.exe.");

	Dumper dump(process, process->GetBaseAddress());

	dump.Dump();

	return PrintAndQuit("Done!");
}