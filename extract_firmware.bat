@echo off
:: Pioneer Firmware Extractor
:: Extracts all firmware files from Pioneer .exe installers
:: by cPix / Razor 1911 (c) 2026
::
:: Usage: Place this .bat in the root of PIONEER-ODD-OFFICIAL-FIRMWARE-PACK
::        Run as administrator
::        Extracted files will be in .\extracted\

echo Pioneer Firmware Extractor
echo ==========================
echo.

set SEVENZIP="C:\Program Files\7-Zip\7z.exe"
set OUTDIR=extracted

if not exist %OUTDIR% mkdir %OUTDIR%

echo Extracting all .exe files...
echo.

set COUNT=0
for /r %%f in (*.exe) do (
    echo Extracting: %%~nxf
    %SEVENZIP% e "%%f" -o"%OUTDIR%\%%~nf" -y >nul 2>&1
    set /a COUNT+=1
)

echo.
echo Done! Extracted %COUNT% installers to .\%OUTDIR%\
echo Now run: python analyze_firmware.py
pause
