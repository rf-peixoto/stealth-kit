@echo off
setlocal enabledelayedexpansion
REM ===========================================================================
REM build.bat - Windows / MSVC build for the envcheck examples (mirrors build.sh)
REM
REM   build.bat                 Build the examples            -> build\*.exe
REM   build.bat obfuscate       Run the string obfuscator on every C source
REM                             first, then compile them      -> build\*.obf.exe
REM   build.bat obfuscate 1234  ... with a fixed obfuscation seed (reproducible)
REM   build.bat clean           Remove the build\ directory
REM
REM Run this from a "x64 Native Tools Command Prompt for VS" so that cl.exe is on
REM PATH, with Python 3 also on PATH (python.exe). MSVC is recommended on Windows
REM (the SEH debugger traps and the x86 VMware backdoor probe are MSVC-only).
REM
REM Note: unlike the GNU/strip step on Linux, a cl.exe build keeps its debug info
REM in a separate .pdb, so function names are NOT embedded in the .exe - there is
REM no separate "strip" step to run here.
REM ===========================================================================

set "ROOT=%~dp0"
set "INC=/I "%ROOT%include""
set "LIBSRC="%ROOT%src\envcheck.c""
set "BUILD=%ROOT%build"
set "OBFDIR=%BUILD%\obf"
set "CFLAGS=/nologo /O2 /W3"
set "LIBS=advapi32.lib user32.lib iphlpapi.lib shell32.lib"
set "PY=python"
REM obfuscated sources are machine-generated: quiet the expected warnings
REM (C4774 non-literal format string, C4505/C4101/C4189 unused, C4702 unreachable)
set "OBFW=/wd4774 /wd4505 /wd4101 /wd4189 /wd4702"

if /I "%~1"=="clean" (
    if exist "%BUILD%" rmdir /s /q "%BUILD%"
    echo cleaned %BUILD%
    goto :eof
)

if not exist "%BUILD%" mkdir "%BUILD%"

if /I "%~1"=="obfuscate" goto :obfuscate
if /I "%~1"=="--obfuscate" goto :obfuscate

REM ----------------------------------------------------------------- plain build
REM Compile from inside build\ so .obj files land there (avoids /Fo quoting).
pushd "%BUILD%"
for %%N in (example report guard) do (
    echo CC %%N
    cl %CFLAGS% %INC% "%ROOT%examples\%%N.c" %LIBSRC% /Fe:"%%N.exe" %LIBS%
    if errorlevel 1 ( popd & goto :error )
)
echo CC demo
cl %CFLAGS% "%ROOT%demo\demo.c" /Fe:"demo.exe"
if errorlevel 1 ( popd & goto :error )
popd
echo.
echo Built -^> %BUILD%\
echo   build\report.exe  [--json] [--no-ptrace] [--no-backdoor] [--sleep-skew]
echo   set "GUARD_DRY_RUN=1" ^&^& build\guard.exe    (test the enforcement example safely)
echo   build\example.exe   (JSON report)
echo.
echo Run "build.bat obfuscate" to produce string-obfuscated builds.
goto :eof

REM ------------------------------------------------------------ obfuscated build
:obfuscate
set "SEEDARG="
if not "%~2"=="" set "SEEDARG=--seed %~2"
if not exist "%OBFDIR%" mkdir "%OBFDIR%"

echo == obfuscating sources (tools\cobfuscate.py) ==
%PY% "%ROOT%tools\cobfuscate.py" %LIBSRC% -o "%OBFDIR%\envcheck.c" %SEEDARG% --stats
if errorlevel 1 goto :error
for %%N in (example report guard) do (
    %PY% "%ROOT%tools\cobfuscate.py" "%ROOT%examples\%%N.c" -o "%OBFDIR%\%%N.c" %SEEDARG% --stats
    if errorlevel 1 goto :error
)
%PY% "%ROOT%tools\cobfuscate.py" "%ROOT%demo\demo.c" -o "%OBFDIR%\demo.c" %SEEDARG% --stats
if errorlevel 1 goto :error

echo.
echo == compiling obfuscated sources ==
REM Compile from inside build\obf\ so .obj files land there (avoids /Fo quoting).
pushd "%OBFDIR%"
for %%N in (example report guard) do (
    echo CC %%N.obf
    cl %CFLAGS% %OBFW% %INC% "%OBFDIR%\%%N.c" "%OBFDIR%\envcheck.c" /Fe:"%BUILD%\%%N.obf.exe" %LIBS%
    if errorlevel 1 ( popd & goto :error )
)
echo CC demo.obf
cl %CFLAGS% %OBFW% "%OBFDIR%\demo.c" /Fe:"%BUILD%\demo.obf.exe"
if errorlevel 1 ( popd & goto :error )
popd

echo.
echo Built obfuscated -^> %BUILD%\*.obf.exe   (obfuscated sources in %OBFDIR%\)
echo Compare before/after, e.g.:
echo   strings build\demo.exe     ^| findstr OBFUSCATE     (plain: visible)
echo   strings build\demo.obf.exe ^| findstr OBFUSCATE     (obfuscated: gone)
goto :eof

:error
echo.
echo BUILD FAILED (errorlevel %errorlevel%)
exit /b 1
