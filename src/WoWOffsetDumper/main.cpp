#include "descriptor_dumper.hpp"
#include "offset_dumper.hpp"

int main()
{
	clepta::load_default_imports();

	descriptor_dumper desc_dumper("WowClassic.exe");
	desc_dumper.dump();
	offset_dumper(classic_patterns, 10).dump();
	offset_dumper(retail_patterns, 10).dump();

	return 0;

	//ProcessPtr process;

	//auto processes = EnumProcesses("Wow.exe");
	//if (processes.size() > 1)
	//{
	//	int selected = 0;
	//	std::cout << "Found multiple processes, please enter the number of the process you want to scan." << std::endl;
	//	for (int i = 0; i < processes.size(); ++i)
	//	{
	//		std::cout << "[" << i << "]: " << processes[i].th32ProcessID << std::endl;
	//	}
	//	std::cin >> selected;
	//	process = std::make_shared<Process>(processes[selected].th32ProcessID);
	//}
	//else if (processes.size() == 1)
	//	process = std::make_shared<Process>(processes.back().th32ProcessID);
	//else
	//	return PrintAndQuit("No processes found.");

	//if (!process->Open())
	//	return PrintAndQuit("Failed to open Wow.exe.");

	//Dumper dump(process, process->GetBaseAddress());

	//dump.Dump();

	//return PrintAndQuit("Done!");
}