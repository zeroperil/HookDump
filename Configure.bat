set current=%CD%

mkdir %current%\Build-Win-x64
pushd %current%\Build-Win-x64
cmake -Wno-dev -G "Visual Studio 16 2019" -A x64 %current%
popd

mkdir %current%\Build-Win-x86
pushd %current%\Build-Win-x86
cmake -Wno-dev -G "Visual Studio 16 2019" -A Win32 %current%
popd

