# SHA-256
## Compiling without the CRT

This is a simple example that merely tests the correctness of the implementation, but it demonstrates that the code will compile fine without errors when compiling without the Visual C/C++ Runtime on Windows.

If your environment is properly configured, simply test with
```
.\build.bat
.\build\example.exe
echo %errorlevel%
```

Output should be 0. If your environment is not properly configured ('cl' is not recognized...) check the comments in build.bat for how to correct this.