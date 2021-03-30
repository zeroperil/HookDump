# HookDump
EDR function hook dumping

Please refer to the Zeroperil blog post for more information [https://zeroperil.co.uk/hookdump/](https://zeroperil.co.uk/hookdump/)

- In order to build this you will need Visual Studio 2019 (community edition is fine) and CMake.  The batch file Configure.bat will create two build directories with Visual Studio solutions.
- The project may build with MinGW with the correct CMake command line, this is untested YMMV.
- There is a dependency on zydis disassembler, so be sure to update the sub-modules in git before configuring the project.
- There is a 32bit and 64bit project, you may find that EDR's hook different functions in 32/64 bit so building and running both executables may provide more complete results
