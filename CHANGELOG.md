## Change Log

# 2019-12-27

* Reworked with new memory library.
* Now easy to dump offsets from both retail and classic wow, aswell as other games if one would want to.
* Can now use multiple threads to speed-up the scan. More threads require more memory.

# 2018-08-14

* [Moved functions to new class 'Dumper'.](https://gitlab.com/ejt/WoWOffsetDumper/commit/640c8d9b0f06018e16880196f76218d3c23495b8)
* Commented out method Dumper::DumpDescriptors until it automatically uses updated offsets.
* Added capstone to the project.
* Modified Process class to make use of capstone.
* Modified Dumper class to make use of new Process methods.
* Dumper::DumpDescriptor now uses the automatically updated descriptor offsets and dumps all descriptors accordingly.

# 2018-08-13

* Inital commit