@echo off

REM You need to make sure your environment is properly configured for this!
REM You may need to find "vcvarsall.bat" and run it like ".\vcvarsall.bat amd64" in
REM the same command line that you run this script from if you're getting errors.
REM In my case vcvarsall.bat is under \Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\

IF NOT EXIST .\build\ mkdir build

set COMPILER_FLAGS=/std:c++17 /O2 /nologo /Gm- /GR- /GS- /Gs9999999 /EHa- /Oi /WX /W4
set COMPILER_FLAGS=/D "PM_SHA256_NO_CSTDINT" /D "PM_SHA256_NO_CASSERT" %COMPILER_FLAGS%
set LINKER_FLAGS=/NODEFAULTLIB /SUBSYSTEM:Console /machine:x64 /stack:0x100000,0x100000 /incremental:no /opt:ref kernel32.lib

pushd build\

cl %COMPILER_FLAGS% ../../src/sha256.cpp ../win32_example.cpp /link %LINKER_FLAGS% /out:example.exe

popd
