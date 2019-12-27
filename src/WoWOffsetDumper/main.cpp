#include "descriptor_dumper.hpp"
#include "offset_dumper.hpp"

#define TRY_COUT(x) try{x}catch(const std::exception& e){std::cout<<"Error: " << e.what() << std::endl;}

int main()
{
	// Right now debug build are SLOW AS FUCK! You should run release unless
	// you're doing something funky. maybe fix this sometime
	// the bottleneck is in the pattern search if you want to fix it.
	clepta::load_default_imports();

	// Example usage, best would be to make it so you can choost process
	// you want to dump etc. I aint got time or care to fix something
	// like that right now so this will have to do.
	// Plus I REALLY REALLY HATE defines so, you're welcome!
	TRY_COUT(descriptor_dumper desc_dumper("WowClassic.exe");desc_dumper.dump();)

	// Patterns can be found in patterns.hpp, modify the number '10' to limit
	// how many threads are used. More threads = more memory
	// 1 = single threaded (do not create any extra threads)
	// < 1 is undefined behaviour, maybe I will make it shit on your face
	// if you do this but CBA atm. Hopefully doing <1 doesn't blow up your computer.
	TRY_COUT(offset_dumper(classic_patterns, 10).dump();)
	TRY_COUT(offset_dumper(retail_patterns, 10).dump();)

	return 0;
}