[![Build status](https://ci.appveyor.com/api/projects/status/4dmj8hsn04v92txm/branch/master?svg=true)](https://ci.appveyor.com/project/ejt1/wowoffsetdumper/branch/master)

# WoWOffsetDumper

Automatically dumps offsets and descriptors for World of Warcraft BfA.

[Original Ownedcore thread](https://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/681491-c-descriptors-dumper-find-descriptor-offsets.html)

## Disclaimer

This program to reads the memory of World of Warcraft, therefore it is possible, although unlikely that Blizzard could detect and ban for the usage of this software. NEVER USE THIS SOFTWARE WHILE LOGGED INTO YOUR MAIN ACCOUNT.<br />
You have been warned.

## Known Bugs

* ~~CGContainerData gets the wrong offset, it starts at NumSlots instead of Slots. This will be fixed with updated FindPattern and FindPatternAll.~~

## Todo

* ~~Convert functions into a single class and split up the code.~~
* ~~Make code more readable.~~?
* ~~Add capstone.~~
* ~~Update FindPattern and FindPatternAll to use disassembler (capstone) for improved/easier usage.~~
* Do a technical write-up on how the automatic updating of offsets and descriptors work.
* Rewrite the guide on how to manually get offsets and put it here on GitLab.

## Tested Patches

8.0.1.27356 <br />
8.0.1.27326

## Getting Started

Open in Visual Studio 2017 and build.

### Prerequisites

* [Visual Studio 2017](https://visualstudio.microsoft.com/downloads/)
* [CMake (x64)](https://cmake.org/download/)
* World of Warcraft (duh)

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Project inspired by [tomrus88](https://github.com/tomrus88/WowMoPObjMgrTest/blob/master/WowMoPObjMgrTest/DescriptorsDumper.cs)
* FindPattern function inspired by [CSGO-Dumper](https://github.com/Y3t1y3t/CSGO-Dumper/blob/master/Dumper/src/Remote/Remote.cpp)