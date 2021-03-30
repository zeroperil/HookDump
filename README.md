# HookDump
EDR function hook dumping

Please refer to the Zeroperil blog post for more information [https://zeroperil.co.uk/hookdump/](https://zeroperil.co.uk/hookdump/)

- In order to build this you will need Visual Studio 2019 (community edition is fine) and CMake.  The batch file Configure.bat will create two build directories with Visual Studio solutions.
- The project may build with MinGW with the correct CMake command line, this is untested YMMV.
- There is a dependency on zydis disassembler, so be sure to update the sub-modules in git before configuring the project.
- There is a 32bit and 64bit project, you may find that EDR's hook different functions in 32/64 bit so building and running both executables may provide more complete results


NOTES:

- Some EDRs replace the WOW stub in the PEB in order to hook system calls for 32 bit binaries.  In this case you may see zero hooks since no jump instructions are present in NTDLL.  Most likley you will see hooks in the x64 version as the syscall instruction is used for system calls instead of a WOW stub
- We have noted that Windows Defender does not use any user mode hooks
- This tool is designed to be run as a standard user, elevation is not required

HOOK TYPES:

- GPA  
  - GetProcAddress hook, this is output in verbose mode, when the result of GetProcAddress does not match the manually resolved function address.
- JMP  
  - A jump instruction has been patched into the function to redirect execution flow
- EAT 
  - The address in the export address table does not match the address in the export address table in the copy on disc

VERIFICATION:

The only way to truly verify the correct working of the program is to check in a debugger if hooks are present.  If you are getting a zero hooks result and are expecting to see something different, then first verify this in a debugger and please get in touch.
