@echo off
cl.exe drivekit.c ^
    zlib\adler32.c zlib\crc32.c zlib\zutil.c ^
    zlib\inftrees.c zlib\inffast.c zlib\inflate.c zlib\uncompr.c ^
    zlib_decomp_stubs.c ^
    /I zlib /D ZLIB_DLL= ^
    /Fe:drivekit.exe
