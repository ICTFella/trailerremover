@echo off
echo Building PRP Trailer Remover with WinDivert...

REM Check if Visual Studio compiler is available
where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using Visual Studio compiler...
    cl /O2 /W4 /WX /MT trailerremover.c windivert.lib ws2_32.lib /Fe:trailerremover.exe
    if %ERRORLEVEL% == 0 (
        echo Build successful! trailerremover.exe created.
        echo Copy windivert.dll to the same directory to run.
    ) else (
        echo Build failed with Visual Studio compiler.
        goto :try_mingw
    )
    goto :end
)

:try_mingw
REM Try MinGW compiler
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using MinGW compiler...
    gcc -O2 -Wall -Wextra -Werror -o trailerremover.exe trailerremover.c -lwindivert -lws2_32 -static-libgcc
    if %ERRORLEVEL% == 0 (
        echo Build successful! trailerremover.exe created.
        echo Copy windivert.dll to the same directory to run.
    ) else (
        echo Build failed with MinGW compiler.
        goto :no_compiler
    )
    goto :end
)

:no_compiler
echo Error: No suitable compiler found.
echo Please install either:
echo 1. Visual Studio Build Tools (cl.exe)
echo 2. MinGW-w64 (gcc.exe)
goto :end

:end
pause 