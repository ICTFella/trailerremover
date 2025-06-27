@echo off
echo Building PRP Trailer Remover V2...

REM ===============================================
REM Build Target: Version 2 (trailerremover_V2.exe)
REM ===============================================
echo.
echo --- Building Version 2 (trailerremover_V2.exe) ---

REM Check if Visual Studio compiler is available
where cl >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using Visual Studio compiler...
    cl /O2 /W4 /WX /MT trailerremover_v2.c windivert.lib ws2_32.lib /Fe:trailerremover_V2.exe
    if %ERRORLEVEL% == 0 (
        echo Build successful! trailerremover_V2.exe created.
    ) else (
        echo Build failed for V2 with Visual Studio compiler.
    )
    goto :end
)

REM Try MinGW compiler
where gcc >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using MinGW compiler...
    gcc -O2 -Wall -Wextra -Werror -o trailerremover_V2.exe trailerremover_v2.c -lwindivert -lws2_32 -static-libgcc
    if %ERRORLEVEL% == 0 (
        echo Build successful! trailerremover_V2.exe created.
    ) else (
        echo Build failed for V2 with MinGW compiler.
    )
    goto :end
)

echo Error: No suitable compiler found. Please install Visual Studio Build Tools or MinGW.
goto :end

:end
pause 