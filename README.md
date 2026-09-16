# DriveKit v1.0
### Optical Drive Research Toolkit
**by BabaYaga / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering was performed through multiple methods:

**Pre-cutoff / crossflash protocol:** greg1wto provided the tools we needed to capture a live BDRFlash crossflash session with Wireshark/USBPcap. The capture was performed and analyzed by BabaYaga — parsed at the USB EPB level to extract the raw NAND write commands, revealing the complete two-pass firmware write protocol, trigger payload structure, and unlock key format.

**Post-cutoff protocol:** Reverse engineered the official Pioneer updater executables (`BDR-XD06J-UHD`, `BDR-XD07UHD`) with IDA Pro — reading x86 assembly only, no decompilation. This revealed the session token mechanism, buffer IDs and offsets, drive-specific trigger keys, and the Engineering Mode unlock sequence.

**Drive firmware:** H8S/2600 assembly analysis of `READ BUFFER 0xB0` dumps (MrPenguin), revealing the rolling XOR stream cipher and the Engineering Mode gating conditions.

---

## ⚠️ Risk

This tool talks to your optical drive at the raw SCSI/ATAPI command level and includes commands that **flash drive firmware** and **enter a vendor service/kernel mode**. Used incorrectly — wrong drive selected, incompatible firmware, or a command sent to an unsupported drive family — this can **brick the drive**.

- Always confirm the drive letter before running any flash or unlock command
- Don't use `--force` unless you understand what compatibility check you're bypassing
- Run as Administrator on Windows
- After the execution trigger **do not unplug** until the tool reports completion
- A disc in the drive will cause unlock to fail — always eject first

---

## Hardware Research

Pioneer BD drives use the **Renesas H8S/2600** processor — a CISC 16/32-bit processor confirmed by decoding the 0xB0 READ BUFFER dump and disassembling as H8S/2600 assembly (MrPenguin).

**The firmware files are encrypted using a rolling stream cipher.** Analysis from BDR-S12U (MrPenguin, pypcode/Ghidra) revealed:
- Multi-byte sliding XOR key with Linear Congruential Generator: `currentKey = (currentKey * 16807) % 0x7FFFFFFF`
- Crypto/DMA engine at `0xFF3FF000` handles flash programming and key/certificate verification
- The version check is embedded in the ENCRYPTED binary payload — patching the ASCII header alone is insufficient
- Firmware memory-maps the unlock payload buffer to `0xA00000`

**Unlock key format — BIG ENDIAN (confirmed by MrPenguin H8S/2600 disassembly):**
```
H8S/2600 assembly: CMP.L #0x9a782361:32, ER0
→ Universal key 0x9A782361 must be sent as bytes: 9A 78 23 61
→ UD04 key     0x426623FD must be sent as bytes: 42 66 23 FD
→ XD08U key    0xA44F2F55 must be sent as bytes: A4 4F 2F 55
```
DriveKit stores keys as little-endian DWORD values (`0x6123789A`) which produce the correct wire bytes (`9A 78 23 61`) when sent LE.

**Universal key policy:** DriveKit always uses `0x6123789A` (wire bytes: `9A 78 23 61`) for the crossflash unlock trigger. This key is confirmed working on all tested drives (SAT 9330, SAT 9331). Drive-specific trigger keys (e.g. `0x552F4FA4` for XD08U 1.04) are for the post-cutoff execution trigger only — not the unlock.

**Pre vs post-cutoff detection:** DriveKit probes `READ BUFFER 0xB0`:
- Returns data → **pre-cutoff** drive (before 2022-12-27) — H8S/2600 code visible
- Returns error 05/24 → **post-cutoff** drive — `0xB0` locked

**BDRFlash checksum algorithm (from IDA Pro analysis):**
```c
uint32_t checksum = 0;
for (uint32_t offset = 0x10000; offset < filesize; offset += 4) {
    checksum -= *(uint32_t*)(firmware + offset);
}
// Stored at firmware[0x8000]
// Date patch at 0x130 is OUTSIDE checksum range — safe to patch!
```

---

## Flash Protocol

### Pre-cutoff sequence (confirmed working — `cmd_flashfw_precut`):
```
1. WRITE BUFFER mode=0x04 bufID=0xFF len=0x100   ← unlock trigger
   payload[0x00-0x0F] = internal model string (from g_mdl_map by drive ID)
   payload[0x10-0x13] = unlock key (universal: 9A 78 23 61)

2. WRITE BUFFER mode=0x07 bufID=0xFE             ← kernel
   full file from offset 0, 0x8000-byte chunks

3. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware
   full file from offset 0, 0x8000-byte chunks

4. WRITE BUFFER mode=0x05 bufID=0xFF len=0x100   ← execution trigger
   same payload as step 1
```

### Post-cutoff crossflash sequence (confirmed working — `cmd_crossflash`):
```
1. WRITE BUFFER mode=0x04 bufID=0xFF len=0x100   ← unlock trigger
   payload[0x00-0x0F] = internal model string (auto-detected from 0xA0/0xF1)
   payload[0x10-0x13] = 9A 78 23 61 (universal key, always)

2. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, first pass
   FULL FILE in 0x8000-byte chunks (including ECC/OOB trailer!)

3. WRITE BUFFER mode=0x07 bufID=0xFE off=0x0000 len=0x200  ← random session token

4. WRITE BUFFER mode=0x07 bufID=0xFE off=0x1200            ← kernel
   kernel file[0x1200:] in 0x8000-byte chunks at NAND offset 0x1200

5. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, second pass
   same as step 2 (full file including ECC)

6. WRITE BUFFER mode=0x05 bufID=0xFF len=0x100   ← final commit trigger
   same payload as step 1
```

**Critical: The FULL file must be sent including ECC/OOB trailer!**
Sending only the NAND image (0x1E0000) causes commit trigger to fail with `04/4C/02`.

**Firmware file format:**
```
[0x000000 - 0x1DFFFF]  = NAND image
[0x1E0000 - end]       = ECC/OOB data  ← MUST be sent!
```

**Kernel file format (post-cutoff):**
```
[0x000000 - 0x0011FF]  = Pioneer header (NOT sent to drive)
[0x001200 - end]       = kernel code → sent to NAND at offset 0x1200
```

**Kernel file format (pre-cutoff):**
```
[0x000000 - end]       = full file sent from offset 0 to bufID=0xFE
```

---

## ✅ CONFIRMED WORKING

**Post-cutoff crossflash/downgrade (September 14, 2026):**
- Drive: BDR-XD08U (SAT 9331 ID05)
- Confirmed: 1.04 ↔ 1.02 crossflash both directions, single command
- Protocol: two-pass NAND write with ECC trailer
- Key: `0x6123789A` universal

**Pre-cutoff downgrade (September 16, 2026):**
- Drive: BDR-XD07U (SAT 8D31 ID05)
- Confirmed: 1.04 → 1.03 downgrade
- Protocol: single-pass, full file from offset 0
- Model string: `PIONEER BDR-BDS7` (from `g_mdl_map[0x8D31]`)
- Key: `0x6123789A` universal

**Pre-cutoff downgrade (pending):**
- XD08U 1.04 → pre-cutoff 1.01 — blocked by version check in encrypted binary
- ASCII header patch insufficient — version check reads encrypted payload
- Pending: kernel modification (Billy collaboration)

---

## Internal Model Strings (`g_mdl_map`)

| Drive ID | Platform | Internal model string |
|----------|----------|----------------------|
| 0x8231/8232 | SAT 8231 | `PIONEER BDR-XD05` |
| 0x8721/8722 | SAT 8721 | `PIONEER BDR-XS06 ` |
| 0x8800 | SAT 8800 | `PIONEER BDR-211  ` |
| 0x8801 | SAT 8801 | `PIONEER BDR-BDS5 ` |
| 0x8A10 | SAT 8A10 | `PIONEER BDR-UD04 ` |
| 0x8B30 | SAT 8B30 | `XD05BK2/XV5     ` (post-cutoff XD06U) |
| 0x8D30/8D31 | SAT 8D30/31 | `PIONEER BDR-BDS7 ` |
| 0x8E20/8E21 | SAT 8E20/21 | `PIONEER BDR-BDS7 ` |
| 0x8F01 | SAT 8F01 | `PIONEER BDR-BDS6 ` |
| 0x9330 | SAT 9330 | `PIONEER BDR-BDS8 ` |
| 0x9331 | SAT 9331 | `PIONEER BDR-BDS8 ` |

---

## Unlock Keys

| Key (LE DWORD) | Wire bytes | Drive family | Notes |
|----------------|-----------|-------------|-------|
| `0x6123789A` | `9A 78 23 61` | Universal | Confirmed on all tested drives ✅ — used for all unlock triggers |
| `0x08A98AF2` | `F2 8A A9 08` | XD06U post-cutoff (SAT 8B30) | From BDR-XD06J-UHD updater |
| `0xA44F2F55` | `55 2F 4F A4` | XD08U (SAT 9331) | Confirmed by MrPenguin |
| `0x426623FD` | `FD 23 66 42` | BDR-UD04 | Confirmed by MrPenguin |
| `0xAA475E15` | `15 5E 47 AA` | XD08 (SAT 9330) | From BDRFlash IDA table |

**Drive trigger keys (post-cutoff execution trigger only):**

| Drive | Platform | Kernel | Version | Trigger Key |
|-------|----------|--------|---------|-------------|
| BDR-XD06U | SAT 8B30 | ID69 | 1.12 | `0x641E47BD` |
| BDR-XD07 | SAT 8D30 | ID35 | 1.06 | `0xF0116415` |
| BDR-XD08 | SAT 9330 | ID36 | 1.02 | `0x3A932579` |
| BDR-XD08U | SAT 9331 | ID05 | 1.02 | `0xC4C1F37F` |
| BDR-XD08U | SAT 9331 | ID05 | 1.04 | `0x552F4FA4` |

---

## Post-Cutoff Timeline

- October 2022 — last safe versions (XD08 1.01, Oct 11 2022)
- December 27, 2022 — Pioneer pushes post-cutoff to all new drives

**Last safe pre-cutoff versions:**
- BDR-XD08U — **1.01** (2022-10-11), kernel ID05
- BDR-XD08U — **1.00** (2022-04-03), kernel ID05
- BDR-XD07U — **1.04** (2022-05-31), kernel ID05 ✅ UHD capable
- BDR-XD06U — **1.11** ✅ UHD capable
- BDR-XD05 — **3.01 / 2.10 / 1.21**

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
| `--force` | Skip compatibility checks and interactive prompts |
| `--nounlock` | Skip unlock step |
| `--key 0x6123789A` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |

### Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| **`flash`** | **Auto-detect pre/post-cutoff and flash — recommended** |
| `crossflash` | Post-cutoff crossflash/downgrade (direct, no auto-detect) |
| `flashfw` | Legacy flash command (pre/post-cutoff, complex sweep logic) |
| `unlock` | Service mode unlock |
| `e5test` | Test Engineering Mode flag |
| `kernellimbo` | Enter kernel limbo mode |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB |
| `resetnormal` | Attempt to exit kernel/service mode |
| `xordiff` | XOR two encrypted firmware files to find version bytes |
| `patchfw` | Patch firmware ASCII header to spoof version |

### flash command (recommended)

```
drivekit flash E --file kernel.bin --file2 normal.bin
```

Probes `READ BUFFER 0xB0` to detect drive generation:
- **Pre-cutoff** (`0xB0` readable) → `flashfw_precut` — single-pass protocol
- **Post-cutoff** (`0xB0` errors) → `crossflash` — two-pass NAND write protocol

Model string auto-detected from `READ BUFFER 0xA0` / `g_mdl_map` table.
Unlock key always `0x6123789A` (universal, confirmed working on all tested drives).

### xordiff command

```
drivekit xordiff --file fw_new.bin --file2 fw_old.bin
```

XORs two encrypted firmware files — non-zero positions reveal version/date bytes.
No drive needed.

### patchfw command

```
drivekit patchfw --file fw_ref.bin --file2 fw_target.bin
```

Patches ASCII header bytes in `fw_target` to match `fw_ref` version/date.
Only patches printable ASCII — binary/crypto regions preserved.
Output: `fw_target_patched.bin`. No drive needed.

---

## DriveBrowser

Graphical database browser with Supabase cloud sync.

**Windows:**
```
cl drivebrowser_win32.c /Fe:drivebrowser.exe /utf-8 ^
    user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib ole32.lib winhttp.lib
```

**Linux (GTK3):**
```
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
year letter (N=2022, O=2023, P=2024...)
```

| Field | Position | Example | Meaning |
|-------|----------|---------|---------|
| Year letter | [0] | `N` | Manufacturing year (N=2022, O=2023, P=2024) |
| Month | [1] | `K` | Month (A=Jan, B=Feb ... L=Dec) |
| Factory | [2-3] | `DL` | Factory code |
| Sequence | [4-7] | `0058` | Sequential unit number |
| Year (2-digit) | [8-9] | `25` | Year suffix |
| Market | [10-11] | `JP` | Market region (JP=Japan, EU=Europe, US=USA) |

---

## Buffer IDs

| ID | Description |
|----|-------------|
| `0x92` | Drive config + factory calibration |
| `0xA0` | Model string + unlock key (post-cutoff) / capability data (pre-cutoff) |
| `0xB0` | H8S/2600 code — readable on pre-cutoff only, used for generation detection |
| `0xF1` | Drive identity: serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash contents (requires service mode) |
| `0xFE` | Kernel/token write target (crossflash protocol) |
| `0xF0` | Normal firmware write target (both protocols) |
| `0xFF` | Execution trigger (commit flash to NAND) |
| `0xE5` | Engineering Mode flag setter |

---

## Pending Research

- **Pre-cutoff downgrade** — version check in encrypted binary:
  - ASCII header patch confirmed insufficient
  - Need kernel modification to remove version check (Billy collaboration pending)
  - OR LCG seed extraction to re-encrypt firmware with spoofed version bytes
- **XD06U post-cutoff downgrade** — same encrypted binary barrier
- **MrPenguin** — H8S/2600 kernel disassembly for version check location
- **Trigger keys** — extract from all updater EXEs in firmware archive

---

## Credits

**MrPenguin** — H8S/2600 deep firmware analysis, rolling XOR cipher reverse engineering, BDR-S12U pypcode/Ghidra analysis, unlock key endianness clarification, `0xB0` READ BUFFER disassembly, and ongoing technical guidance invaluable throughout this project.

**greg1wto** — provided the tools we needed to capture a live BDRFlash crossflash session with Wireshark/USBPcap, which made the NAND write protocol analysis possible.

Thank you for the inspiration and help from cxplay, Sayaka, Coopervid, blackened2687, Billy, MakeMKV Forum and cdrinfo.pl

**BDRFlash special thanks:**
Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen, ala42, czary2mary, jadburner, cvs, alexx12345, seku, Leman39, wujooj, jurireal, alphaville0527, SnowFox, Kirby, haysey70, Majestic12, elflorek, floppydumper, redwine, cryptojoe3737, TeddyRaspin, BillyCar11, asmcom, payalnik23, aliter404

**Tools:** Wireshark + USBPcap, IDA Pro + hrtng plugin, x64dbg, pypcode, Visual Studio 2022, WSL, GCC

Research and educational purposes only.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*

```
          /\
         /__\
        /\  /\
       /__\/__\
   Razor 1911 - Since 1985
```
