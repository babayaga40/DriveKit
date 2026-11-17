@echo off

echo === Building drivekit.exe ===
cl.exe drivekit.c ^
    drivekit_editor_embedded.c ^
    drivekit_functions.c ^
    zlib\adler32.c zlib\crc32.c zlib\zutil.c ^
    zlib\inftrees.c zlib\inffast.c zlib\inflate.c zlib\uncompr.c ^
    zlib_decomp_stubs.c ^
    /I zlib /D ZLIB_DLL= ^
    /Fe:drivekit.exe
if errorlevel 1 goto fail

echo.
echo === Building drivekit_asm_editor.exe ===
cl.exe drivekit_asm_editor.c ^
    /Fe:drivekit_asm_editor.exe
if errorlevel 1 goto fail

echo.
echo === All targets built successfully ===
goto end

:fail
echo.
echo === Build failed ===
exit /b 1

:end
