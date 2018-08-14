# WoWOffsetDumper

Automatically dumps offsets and descriptors for World of Warcraft BfA.

[Original Ownedcore thread](https://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/681491-c-descriptors-dumper-find-descriptor-offsets.html)

## Known Bugs

* CGContainerData gets the wrong offset, it starts at NumSlots instead of Slots. This will be fixed with updated FindPattern and FindPatternAll.

## Todo

* Convert functions into a single class and split up the code.
* Make code more readable.
* Add capstone.
* Update FindPattern and FindPatternAll to use disassembler (capstone) for improved/easier usage.

## Tested Patches

8.0.1.27356
8.0.1.27326

## Getting Started

Open in Visual Studio 2017 and build.

### Prerequisites

* [Visual Studio 2017](https://visualstudio.microsoft.com/downloads/)
* World of Warcraft (duh)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Project inspired by [tomrus88](https://github.com/tomrus88/WowMoPObjMgrTest/blob/master/WowMoPObjMgrTest/DescriptorsDumper.cs)
* FindPattern function inspired by [CSGO-Dumper](https://github.com/Y3t1y3t/CSGO-Dumper/blob/master/Dumper/src/Remote/Remote.cpp)