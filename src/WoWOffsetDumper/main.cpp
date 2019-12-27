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
}