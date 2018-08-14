#include "Common.hpp"
#include "Dumper.hpp"

#include <iostream>

int32 PrintAndQuit(const std::string& str)
{
	std::cout << str << std::endl << std::endl;
	std::cout << "Press enter to terminate the program.";
	std::cin.get();
	return 0;
}

int main()
{
	ProcessPtr process = std::make_shared<Process>("Wow.exe");

	if (!process->Open())
		return PrintAndQuit("Failed to open Wow.exe.");

	Dumper dump(process, process->GetBaseAddress());

	dump.Dump();

	return PrintAndQuit("Done!");
}