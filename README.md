# DriveKit v1.0
### Optical Drive Research Toolkit
**by BabaYaga / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering was performed through multiple methods:

**Pre-cutoff protocol:** Captured USB traffic between the third-party `BDRFlash` tool and a drive (Wireshark/USBPcap), then analyzed the resulting binary with IDA Pro and x64dbg.

**Post-cutoff protocol:** Reverse engineered the official Pioneer updater executables (`BDR-XD06J-UHD`, `BDR-XD07UHD`) with IDA Pro — reading x86 assembly only, no decompilation to C or other high-level languages was performed. This revealed the complete post-cutoff flash protocol including the session token mechanism, correct buffer IDs and offsets, drive-specific trigger keys, and the Engineering Mode unlock sequence.

**Drive firmware:** H8S/2000 assembly analysis of `READ BUFFER 0xB0` dumps (MrPenguin), revealing the rolling XOR stream cipher and the Engineering Mode gating conditions.

This project documents the vendor's WRITE BUFFER unlock sequence, the session token mechanism, the firmware pairing requirement, drive-family compatibility groups, trigger key table, and the internal model string table required for newer drive families.

---

## ⚠️ Risk

This tool talks to your optical drive at the raw SCSI/ATAPI command level and includes commands that **flash drive firmware** and **enter a vendor service/kernel mode**. Used incorrectly — wrong drive selected, incompatible firmware, or a command sent to an unsupported drive family — this can **brick the drive**.

- Always confirm the drive letter before running any flash or unlock command
- Don't use `--force` unless you understand what compatibility check you're bypassing
- Firmware flashing commands offer to dump existing firmware — always accept
- Run as Administrator on Windows
- After the execution trigger **do not unplug** until the tool reports completion
- A disc in the drive will cause unlock to fail — always eject first

---

## Hardware Research

Pioneer BD drives use the **Renesas H8S/2000** processor — a big-endian 16/32-bit RISC CPU. Confirmed by decoding the 0xB0 READ BUFFER dump and disassembling as H8S/2000 assembly (MrPenguin, pypcode + custom H8S SLA).

**The firmware files are encrypted using a rolling stream cipher.** Analysis from BDR-S12U (MrPenguin, pypcode/Ghidra) revealed:
- Multi-byte sliding XOR key with Linear Congruential Generator: `currentKey = (currentKey * 16807) % 0x7FFFFFFF`
- Crypto/DMA engine at `0xFF3FF000` handles flash programming and key/certificate verification
- The version check is embedded in the ENCRYPTED binary payload — patching the ASCII header alone is insufficient

**BDRFlash checksum algorithm (from IDA Pro analysis):**
```c
// Checksum covers firmware data from offset 0x10000 onwards
// Date patch at 0x130 is OUTSIDE the checksum range — safe to patch!
uint32_t checksum = 0;
for (uint32_t offset = 0x10000; offset < filesize; offset += 4) {
    checksum -= *(uint32_t*)(firmware + offset);
}
// Stored at firmware[0x8000]
```

**16MB NAND dumps captured:**
- BDR-XD08 (SAT 9330 ID36) — pre-cutoff 1.02
- BDR-XD06U (SAT 8B30 ID69) — post-cutoff 1.12

---

## Flash Protocol — Confirmed from Wireshark Capture

### Pre-cutoff sequence:
```
1. WRITE BUFFER mode=4 bufID=0xFF len=0x100  ← unlock
2. WRITE BUFFER mode=7 bufID=0xFE            ← kernel (chunks)
3. WRITE BUFFER mode=7 bufID=0xF0            ← normal firmware (chunks)
4. WRITE BUFFER mode=5 bufID=0xFF len=0x100  ← execution trigger
```

### Post-cutoff sequence (COMPLETE! From XD07 1.06 updater analysis):
```
1. WRITE BUFFER mode=1 bufID=0x00 len=0x20                  ← unlock
2. WRITE BUFFER mode=7 bufID=0xE5 len=0x02 payload=0x01     ← enable Engineering Mode!
3. WRITE BUFFER mode=7 bufID=0xFE offset=0x0000 len=0x200   ← random session token
4. WRITE BUFFER mode=7 bufID=0xFE offset=0x1200 len=<size>  ← kernel
5. WRITE BUFFER mode=7 bufID=0xF0 offset=0x0000 len=<size>  ← normal firmware (chunked)
6. WRITE BUFFER mode=5 bufID=0xFF offset=0x0000 len=0x100   ← execution trigger
```

**Execution trigger payload structure (0x100 bytes):**
```
[0x00-0x0F] = first 16 bytes of random session token
[0x10-0x13] = drive-specific key from updater dword_5D4B38 table!
[0x14-0xFF] = rest of random session token
```

**Drive trigger keys (from updater dword_5D4B38[index*4]):**

| Drive | Platform | Kernel | Trigger Key | Notes |
|-------|----------|--------|-------------|-------|
| BDR-XD06U | SAT 8B30 | ID69 | `0x641E47BD` | XD06U 1.12 updater ✅ CONFIRMED |
| BDR-XD07 | SAT 8D30 | ID35 | `0xF0116415` | XD07 1.06 updater |

Each Pioneer updater contains a 16-entry key table at VA `0x5D4B38` (file offset `0x1D4B38`). Only index 0 is used — remaining 15 slots are padding. Extract with `extract_keys.py`!

**Key[0] confirmed correct for XD06U** — returns `ASC=4C` (version check) vs `ASC=24` for all other keys!

**`0xF1` state indicator after normal firmware send:**
- `70 00 00 00` = firmware accepted into SRAM ✅
- `70 00 05 00` = drive detected version mismatch in encrypted binary ❌

**CRITICAL DISCOVERY — Spoofed firmware bypasses upload check!**
- Real 1.11 firmware → `0xF1 = 70 00 05 00` (rejected during upload!)
- Spoofed 1.11 with ASCII header claiming 1.12 → `0xF1 = 70 00 00 00` (ACCEPTED!) ✅
- BUT trigger still returns `ASC=4C` — version check happens TWICE!
- Upload phase: bypassed by ASCII header spoof ✅
- Trigger phase: checks encrypted binary in SRAM — still blocked ❌

**Remaining barrier:** Version check embedded in ENCRYPTED firmware binary — 1.12 kernel validates incoming version from encrypted data. ASCII header patching alone is insufficient.

**Full DriveKit sequence:**
```batch
drivekit.exe unlock E
drivekit.exe e5test E
drivekit.exe flashfw E --file S8B30690.111 --file2 S8B30691.111 --postcutoff
```

---

## Critical Discovery: Post-Cutoff Unlock (NEW!)

**`WRITE BUFFER mode=0x01 bufID=0x00 len=0x20`** — previously undocumented Pioneer vendor command!

```
Payload: [16-byte internal model string] + [4-byte key in LE]

Example (BDR-XD06U post-cutoff):
  Model string: "XD05BK2/XV5     "
  Key:          F2 8A A9 08  (0x08A98AF2 in LE)
```

**Important:** Drive returns CHECK CONDITION with sense key=0x00 on SUCCESS!

**Sticky state:** Once unlocked with `mode=0x01`, the drive retains service mode access (`0xF4` accessible) even across power cycles on some drives!

---

## Kernel Limbo States (NEW!)

Two distinct kernel limbo states discovered on post-cutoff XD06U:

**State 1 — Service mode (`mode=0x01` unlock):**
- LED ON ✅
- Firmware: 1.12 (normal mode visible)
- `0xF4` accessible ✅
- Firmware writes rejected ❌

**State 2 — Triggered kernel limbo (XS06 trigger):**
- LED ON, Firmware: 0000
- `0xF4` NOT accessible
- Normal firmware partition erased
- Drive recovers to 1.12 on power cycle

**State 3 — TRUE kernel limbo (ASC=4C rejection):**
- LED OFF 💀
- Firmware: 0000
- Nothing accessible
- Drive recovers to 1.12 on power cycle (kernel partition intact!)

**Key difference from XD08 kernel limbo:** XD06U post-cutoff kernel partition remains intact — drive always recovers to 1.12! XD08 had genuinely empty NAND and stayed in limbo until flashed.

---

## Version Check Discovery (NEW!)

The downgrade protection version check is embedded in the **encrypted binary firmware payload** — NOT in the ASCII header!

**Confirmed by testing:**
- ASCII header spoof (`1.11` → `1.12`, date `17/06/22` → `23/03/03`) → still rejected!
- Version check reads from encrypted binary → cannot be bypassed by header patching alone
- BDRFlash checksum is over data from `0x10000+` → date patch at `0x130` is safe
- The encrypted payload contains the version that the drive's kernel validates

---

## Firmware Spoofing (Research)

Patched firmware files for research purposes:
- `S8B30690_spoof112.bin` — kernel 1.11 with header claiming 1.12 / 23/03/03
- `S8B30691_spoof112.bin` — normal 1.11 with header claiming 1.12 / 23/03/03

Result: `ASC=4C` still fires — version check reads encrypted binary not ASCII header!

---

## Post-Cutoff Timeline

- October 2022 — last safe versions (XD08 1.01 Oct 11 2022)
- December 27, 2022 — Pioneer pushes post-cutoff to all new drives
- XD06U 1.12 (Generated: 2023-03-03) — post-cutoff, `ID69`

**Last safe pre-cutoff versions:**
- BDR-XD08 — **1.01** (2022-10-11), requires `ID36` firmware pair
- BDR-XD07U / AD07 — **1.04** (2022-05-31) ✅ UHD capable
- BDR-XD06U — **1.11** ✅ UHD capable
- BDR-XD05 — **3.01 / 2.10 / 1.21**

**Post-cutoff drives still support LibreDrive and UHD reading** — protection only blocks downgrading/crossflashing!

---

## Internal Model Strings

| Drive | Platform | Kernel | Internal model string |
|-------|----------|--------|----------------------|
| BDR-XD05 (SAT 8231) | pre-cutoff | ID32 | `PIONEER BDR-XD05` |
| BDR-XD06U (SAT 8B30) | pre-cutoff | ID69 | `PIONEER BDR-XS06` |
| BDR-XD06U (SAT 8B30) | post-cutoff | ID69 | `XD05BK2/XV5     ` |
| BDR-AD07 (SAT 8D30) | — | — | `PIONEER BDR-BDS7` |
| BDR-XD08 (SAT 9330) | — | ID36 | `PIONEER BDR-BDS8` |
| BDR-XD08U (SAT 9331) | — | — | `PIONEER BDR-BDS8` |
| BDR-UD04 | — | — | `PIONEER BDR-US04` |
| BDR-211M (SAT 8801) | — | — | `PIONEER BDR-BDS5` |

---

## Unlock Keys

| Key | Drive family | Notes |
|-----|-------------|-------|
| `0x6123789A` | Primary (most drives) | Universal fallback |
| `0x5CF2E094` | Secondary | Different handler |
| `0xBE4B8754` | XD05 post-cutoff (SAT 8232) | From BDR-XD05BKXL2 updater.exe |
| `0x08A98AF2` | XD06U post-cutoff (SAT 8B30) | From BDR-XD06J-UHD updater.exe |
| `0xA44F2F55` | XD08U (SAT 9331) | Confirmed by MrPenguin |
| `0x426623FD` | BDR-UD04 | Confirmed by MrPenguin |

**Note (MrPenguin):** Key comparison is against an internal value — last 4 bytes may be flexible on some drives. CDB length must be >= 19 bytes for `bufID=0xFF` commands!

---

## Pioneer Updater.exe Analysis

Analysis of `BDR-XD05BKXL2` and `BDR-XD06J-UHD` updater executables:

- Firmware embedded as static byte array in `.rdata` section
- Master firmware buffer pointer: `dword_59AA5C`
- Drive ID check: `jnz`→`jmp` at `0x2E0C` to bypass
- Rolling XOR decryption: `currentKey = (currentKey * 16807) % 0x7FFFFFFF`
- Uses WNASPI32 (not IOCTL)
- `FOGEFOGE`/`DUMMY` = template placeholders
- `sub_412BDD` = checksum calculator (subtraction sum from 0x10000)
- `sub_413347` = firmware structure parser
- "Force flash mode is not yet allowed" string found — feature planned but not implemented

---

## Build

**Windows (MSVC Developer Command Prompt):**
```
cl drivekit.c /Fe:drivekit.exe /utf-8
```

**Linux (GCC):**
```
gcc drivekit.c -o drivekit -w
sudo ./drivekit info /dev/sg1
```

---

## Usage

```
drivekit <command> <drive_letter> [options]
```

### Options

| Option | Description |
|---|---|
| `--file name` | Kernel firmware file |
| `--file2 name` | Normal firmware file |
| `--file3 name` | Second normal firmware pass (post-cutoff) |
| `--force` | Skip compatibility checks |
| `--postcutoff` | Skip unlock + force post-cutoff mode (`g_unlock_mode=0x01`) |
| `--nounlock` | Skip unlock step |
| `--key 0x5CF2E094` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |

### Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| `unlock` | Service mode unlock (auto-detects pre/post-cutoff) |
| `flashfw` | Flash kernel + firmware |
| `e5test` | Test `0xE5` Engineering Mode flag — run after unlock, before flashfw |
| `kernellimbo` | Enter kernel limbo mode (post-cutoff drives) |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB (auto-detects read/write direction) |
| `resetnormal` | Attempt to exit kernel/service mode |

---

## Two-Step Kernel Limbo (Post-Cutoff XD06U)

```
# Step 1: Enter first kernel limbo (LED on, Firmware: 0000)
drivekit flashfw E --file S8B30690_spoof112.bin --file2 S8B30691_spoof112.bin

# Wait for: Trigger XS06 mode=5 bufID=0xFF: GOOD
# Confirm: drivekit info E → Firmware: 0000

# Step 2: Enter TRUE kernel limbo (LED off, Firmware: 0000)
drivekit flashfw E --file S8B30690.111 --file2 S8B30691.111 --nounlock

# Result: ASC=4C → LED goes dark → TRUE kernel limbo
# Note: Drive recovers to 1.12 on power cycle (kernel partition intact!)
```

---

## DriveBrowser

Graphical database browser with Supabase cloud sync. 365+ drive entries, 251+ firmware files.

**Windows:**
```
cl drivebrowser_win32.c /Fe:drivebrowser.exe /utf-8 ^
    user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib ole32.lib winhttp.lib
```

**Linux (GTK3):**
```
sudo apt install libgtk-3-dev libcurl4-openssl-dev build-essential
gcc drivebrowser_linux.c -o drivebrowser \
    $(pkg-config --cflags --libs gtk+-3.0) -lcurl -lm
```

---

## Serial Number Decode

Pioneer serial format: `NKDL005825JP`

```
N  K  D  L  0  0  5  8  2  5  J  P
|  |  |-----|  |-----|  |--|  |--|
|  |  factory  sequence  year  market
|  month (A=Jan ... L=Dec)
year letter
```

---

## Buffer IDs

| ID | Description |
|----|-------------|
| `0x92` | Drive config + factory calibration |
| `0xA0` | Session token / model string + key |
| `0xB0` | Capability data — H8S/2000 code visible (pre-cutoff only!) |
| `0xF1` | Drive identity: serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash contents (requires service mode) |
| `0xFE` | Kernel area (RAM) — pre-cutoff bufID |
| `0xF0` | Normal firmware area (RAM) — pre-cutoff bufID |
| `0x00` | Universal firmware buffer (post-cutoff) |
| `0xE5` | Engineering Mode flag setter — enables `0xFF` gating (XD06U confirmed, all modes GOOD!) |

---

## 🎉 Post-Cutoff Flash Protocol CONFIRMED WORKING!

**1.12 → 1.12 same-version flash succeeded!** (September 13, 2026)

The complete protocol is 100% confirmed working on BDR-XD06U post-cutoff:
- Session token → `bufID=0xFE offset=0x0000` ✅
- Kernel → `bufID=0xFE offset=0x1200` ✅
- Normal firmware → `bufID=0xF0 offset=0x0000` chunked ✅
- Trigger with key `0x641E47BD` → **GOOD!** ✅
- Drive reflashed NAND and rebooted successfully! ✅

**Version check behaviour confirmed:**
- Same version (1.12→1.12) → GOOD ✅
- Older version (1.11→1.12 spoofed) → `ASC=4C` ❌
- Different model XD07U 1.04 → `ASC=4C` ❌ (version check is numerical, ignores model!)
- XD05 1.21 (newer version number) → `ASC=4C` ❌
- Version check reads ENCRYPTED binary — not ASCII header!

**Buffer discoveries (normal mode, before Engineering Mode):**
- `READ BUFFER 0xFE` → encrypted firmware in SRAM (2.6MB!) ✅
- `READ BUFFER 0xFC` → diagnostic/error log buffer (6MB) ✅
- `0xFD` (direct vendor opcode) → self-test, takes seconds, returns GOOD ✅
- **Engineering Mode (`0xE5`) LOCKS `0xFE` and `0xFC`!** Must dump before `e5test`!

---

## Pending Research

- **Post-cutoff downgrade** — version check in encrypted binary is the ONLY remaining barrier:
  - Complete protocol confirmed working ✅
  - Version check purely numerical — any firmware < 1.12 rejected regardless of model
  - Need: rolling XOR encryption key for ID69 to patch version bytes in encrypted binary
  - OR: command between firmware send and trigger that bypasses version check
  - OR: Billy's method (collaboration pending)
- **`0xFE` dump analysis** — compare encrypted 1.12 firmware dump to 1.11 file — find version bytes!
- **MrPenguin** — H8S/2000 disassembly, `0xB0` analysis, XD08U testing
- **Coppervid** — working contacts for potential method sharing
- **Extract trigger keys** from all updater exes in firmware archive

---

## Credits

Thank you for the inspiration and help from MrPenguin, cxplay, Sayaka, Coppervid, blackened2687, MakeMKV Forum and cdrinfo.pl

**BDRFlash special thanks** (from BDRFlash v1.00 about box):
Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen, ala42, czary2mary, jadburner, cvs, alexx12345, seku, Leman39, wujooj, jurireal, alphaville0527, SnowFox, Kirby, haysey70, Majestic12, elflorek, floppydumper, redwine, cryptojoe3737, TeddyRaspin, BillyCar11, asmcom, payalnik23, aliter404

**Tools:** Wireshark + USBPcap, IDA Pro + hrtng plugin, x64dbg, pypcode, Visual Studio 2022, WSL, GCC

Research and educational purposes only.

*DriveKit v1.0 — BabaYaga / Razor 1911 (c) 2026*

```
          /\
         /__\
        /\  /\
       /__\/__\
   Razor 1911 - Since 1985
```
