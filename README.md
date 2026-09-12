# DriveKit v1.0
### Optical Drive Research Toolkit
**by BabaYaga / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering of the flash protocol was done by capturing USB traffic between the third-party `BDRFlash` tool and a drive (Wireshark/USBPcap), then analyzing the resulting binary with IDA Pro and x64dbg — **reading x86 assembly only, no decompilation to C or other high-level languages was performed at any point**. This project documents the vendor's WRITE BUFFER unlock sequence, the session token mechanism, the firmware pairing requirement, drive-family compatibility groups, and the internal model string table required for newer drive families.

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

### Post-cutoff sequence (NEW!):
```
1. WRITE BUFFER mode=1 bufID=0x00 len=0x20   ← unlock (undocumented!)
2. WRITE BUFFER mode=7 bufID=0x00            ← kernel (single transfer)
3. WRITE BUFFER mode=7 bufID=0x00            ← normal firmware (single transfer)
4. WRITE BUFFER mode=5 bufID=0xFF len=0x100  ← execution trigger (XS06 payload)
```

**Post-cutoff trigger payload:** `PIONEER BDR-XS06` + key (confirmed working!)

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
| `--nounlock` | Skip unlock step |
| `--key 0x5CF2E094` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |

### Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| `unlock` | Service mode unlock (auto-detects pre/post-cutoff) |
| `flashfw` | Flash kernel + firmware |
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
| `0xE5` | Kernel reinitialize flag (XD08U only, not XD06U) |

---

## Pending Research

- **Post-cutoff downgrade** — version check in encrypted binary payload needs:
  - Rolling XOR encryption key for ID69 platform
  - OR pre-cutoff ID69 kernel (no version check)
  - OR hardware JTAG access
- **MrPenguin** — H8S/2000 disassembly of XD08U, `0xE5` command analysis
- **`0xB0` RAM dump** — locked on post-cutoff drives
- **Billy's method** — collaboration pending

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
