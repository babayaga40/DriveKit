# DriveKit v1.0
### Optical Drive Research Toolkit
**by BabaYaga / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering was performed through multiple methods:

**Pre-cutoff / crossflash protocol:** greg1wto provided the tools we needed to capture a live BDRFlash crossflash session with Wireshark/USBPcap. The capture was performed and analyzed by BabaYaga — parsed at the USB EPB level to extract the raw NAND write commands, revealing the complete two-pass firmware write protocol, trigger payload structure, and unlock key format.

**Post-cutoff protocol:** Reverse engineered the official Pioneer updater executables (`BDR-XD06J-UHD`, `BDR-XD07UHD`) with IDA Pro — reading x86 assembly only, no decompilation. This revealed the session token mechanism, buffer IDs and offsets, drive-specific trigger keys, and the Engineering Mode unlock sequence.

**Drive firmware:** H8S/2600 assembly analysis of `READ BUFFER 0xB0` dumps (MrPenguin), revealing the rolling XOR stream cipher and the Engineering Mode gating conditions.

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

Pioneer BD drives use the **Renesas H8S/2600** processor — a CISC 16/32-bit processor (LDMAC and STMAC instructions confirmed, which raises H8S/2000 to H8S/2600). Confirmed by decoding the 0xB0 READ BUFFER dump and disassembling as H8S/2600 assembly (MrPenguin).

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
DriveKit stores keys as little-endian DWORD values (`0x6123789A`) which produce the correct wire bytes (`9A 78 23 61`) when sent LE. Minimum payload length = 20 bytes (16 model string + 4 key).

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

## Flash Protocol

### Crossflash sequence (CONFIRMED WORKING — from Wireshark EPB capture analysis):
```
1. WRITE BUFFER mode=0x04 bufID=0xFF len=0x100   ← unlock trigger
   payload[0x00-0x0F] = model string (e.g. "PIONEER BDR-BDS8")
   payload[0x10-0x13] = unlock key (little-endian, universal: 9A 78 23 61)
   payload[0x14-0xFF] = zeros

2. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, first pass
   FULL FILE in 0x8000-byte chunks (including ECC/OOB trailer!)
   e.g. 9331051.102 = 0x1E6700 bytes = 61 chunks

3. WRITE BUFFER mode=0x07 bufID=0xFE off=0x0000 len=0x200  ← random session token

4. WRITE BUFFER mode=0x07 bufID=0xFE off=0x1200 len=<size> ← kernel
   kernel file[0x1200:] sent in 0x8000-byte chunks at NAND offset 0x1200

5. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, second pass
   same as step 2 (full file)

6. WRITE BUFFER mode=0x05 bufID=0xFF len=0x100   ← final commit trigger
   same payload structure as step 1
```

**Critical discovery: The FULL file must be sent including ECC/OOB trailer!**
Sending only the NAND image (0x1E0000) causes the commit trigger to fail with `04/4C/02`.
The full file (e.g. 0x1E6700) must be sent — the extra 0x6700 bytes are ECC data the drive expects.

**The firmware is written TWICE** — first pass bypasses version protection, second pass with kernel is the permanent write.

**Firmware file format:**
```
[0x000000 - 0x1DFFFF]  = 0x1E0000 bytes  → NAND image
[0x1E0000 - end]       = ECC/OOB data    → MUST be sent! (not optional)
```

**Kernel file format:**
```
[0x000000 - 0x0011FF]  = Pioneer header (0x1200 bytes, NOT sent)
[0x001200 - end]       = actual kernel code → sent to NAND at offset 0x1200
```

### Post-cutoff sequence (from XD07 1.06 updater analysis):
```
1. WRITE BUFFER mode=0x01 bufID=0x00 len=0x20                  ← unlock
2. WRITE BUFFER mode=0x07 bufID=0xE5 len=0x02 payload=0x01     ← enable Engineering Mode
3. WRITE BUFFER mode=0x07 bufID=0xFE offset=0x0000 len=0x200   ← random session token
4. WRITE BUFFER mode=0x07 bufID=0xFE offset=0x1200 len=<size>  ← kernel
5. WRITE BUFFER mode=0x07 bufID=0xF0 offset=0x0000 len=<size>  ← normal firmware (chunked)
6. WRITE BUFFER mode=0x05 bufID=0xFF offset=0x0000 len=0x100   ← execution trigger
```

**Drive trigger keys (from updater dword_5D4B38[index*4]):**

| Drive | Platform | Kernel | Version | Trigger Key | Source |
|-------|----------|--------|---------|-------------|--------|
| BDR-XD06U | SAT 8B30 | ID69 | 1.12 | `0x641E47BD` | XD06U 1.12 updater ✅ CONFIRMED |
| BDR-XD07 | SAT 8D30 | ID35 | 1.06 | `0xF0116415` | XD07 1.06 updater |
| BDR-XD08 | SAT 9330 | ID36 | 1.02 | `0x3A932579` | XD08 1.02 updater |
| BDR-XD08U | SAT 9331 | ID05 | 1.02 | `0xC4C1F37F` | XD08U 1.02 updater |
| BDR-XD08U | SAT 9331 | ID05 | 1.04 | `0x552F4FA4` | XD08U 1.04 updater |

**Important:** Trigger key changes per firmware VERSION — not just per drive model!

---

## ✅ CROSSFLASH / DOWNGRADE — CONFIRMED WORKING (September 14, 2026)

**First confirmed Pioneer post-cutoff crossflash/downgrade using our own tool.**

**Background:** greg1wto provided the tools we needed to capture a live BDRFlash crossflash session with Wireshark/USBPcap. BabaYaga performed the capture and analyzed the pcapng at the USB Enhanced Packet Block (EPB) level — stripping the 27-byte usbmon pseudo-header from each packet — extracting the raw NAND write commands. This revealed the two-pass firmware write protocol that BDRFlash uses, which had not been documented anywhere.

**What was discovered from the capture:**
- Firmware is written to NAND **twice** — not once as previously assumed
- The FULL file must be sent including ECC/OOB trailer — truncating to 0x1E0000 causes commit failure
- The unlock trigger payload is dead simple: model string at `[0x00]`, key at `[0x10]`, zeros elsewhere
- The universal key `0x6123789A` (wire bytes: `9A 78 23 61`) works as the unlock for all tested drives
- Model string and key are auto-detected from `READ BUFFER 0xA0` by DriveKit

**Test performed:**
- Drive: BDR-XD08 physically, running BDR-XD08U firmware (SAT 9331 ID05)
- Confirmed working: 1.04 ↔ 1.02 crossflash in both directions, single command
- Key used: `0x6123789A` (universal, auto-detected)
- Result: **SUCCESS** ✅ — fully automatic, no manual recovery needed

**Complete working command:**
```
drivekit crossflash E --file <kernel> --file2 <normal_firmware>
```

**Pre-cutoff downgrade status:**
- Attempted: XD08U 1.04 → pre-cutoff 1.01 (files S9331050.100 + S9331051.101)
- Result: commit trigger returns `04/4C/02` — version check in encrypted binary
- Patching ASCII header only is insufficient — version check reads encrypted payload
- Pending: kernel modification to remove version check (Billy collaboration)

---

## Version Check Discovery

The downgrade protection version check is embedded in the **encrypted binary firmware payload** — NOT in the ASCII header!

**Confirmed by testing:**
- ASCII header patch (`1.01` → `1.02` in plaintext header) → still rejected with `04/4C/02`
- Version check reads from encrypted binary → cannot be bypassed by header patching alone
- `xordiff` of 1.02 vs 1.01 firmware shows ~1.9M differing bytes — entire encrypted payload differs between versions (different LCG seed per version)
- Only 5 bytes differ in ASCII header region (version digit, date, filename)

**`0xF1` state indicator after normal firmware send:**
- `70 00 00 00` = firmware accepted into SRAM ✅
- `70 00 05 00` = drive detected version mismatch in encrypted binary ❌

---

## Critical Discovery: Post-Cutoff Unlock (pre-crossflash research)

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

## Kernel Limbo States

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
- Drive recovers to previous firmware on power cycle (kernel partition intact)

---

## Post-Cutoff Timeline

- October 2022 — last safe versions (XD08 1.01 Oct 11 2022)
- December 27, 2022 — Pioneer pushes post-cutoff to all new drives
- XD06U 1.12 (Generated: 2023-03-03) — post-cutoff, `ID69`

**Last safe pre-cutoff versions:**
- BDR-XD08U — **1.01** (2022-10-11), kernel ID05
- BDR-XD08U — **1.00** (2022-04-03), kernel ID05
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
| BDR-XD08U (SAT 9331) | — | ID05 | `PIONEER BDR-BDS8` |
| BDR-UD04 | — | — | `PIONEER BDR-US04` |
| BDR-211M (SAT 8801) | — | — | `PIONEER BDR-BDS5` |

---

## Unlock Keys

| Key (LE DWORD) | Wire bytes | Drive family | Notes |
|----------------|-----------|-------------|-------|
| `0x6123789A` | `9A 78 23 61` | Universal (all drives) | Confirmed working on all tested drives ✅ |
| `0x5CF2E094` | `94 E0 F2 5C` | Secondary | Different handler |
| `0xBE4B8754` | `54 87 4B BE` | XD05 post-cutoff (SAT 8232) | From BDR-XD05BKXL2 updater.exe |
| `0x08A98AF2` | `F2 8A A9 08` | XD06U post-cutoff (SAT 8B30) | From BDR-XD06J-UHD updater.exe |
| `0xA44F2F55` | `55 2F 4F A4` | XD08U (SAT 9331) | Confirmed by MrPenguin |
| `0x426623FD` | `FD 23 66 42` | BDR-UD04 | Confirmed by MrPenguin |
| `0xAA475E15` | `15 5E 47 AA` | XD08 (SAT 9330) | From BDRFlash IDA table |

**Note:** DriveKit auto-detects the correct model string and key from `READ BUFFER 0xA0`. The universal key `0x6123789A` is used as fallback when 0xA0 returns zero key bytes.

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
| `--force` | Skip compatibility checks and interactive prompts |
| `--nounlock` | Skip unlock step |
| `--key 0x6123789A` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |

### Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| `unlock` | Service mode unlock (auto-detects pre/post-cutoff) |
| `flashfw` | Flash kernel + firmware |
| `crossflash` | Post-cutoff crossflash/downgrade — confirmed protocol |
| `e5test` | Test `0xE5` Engineering Mode flag |
| `kernellimbo` | Enter kernel limbo mode (post-cutoff drives) |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB |
| `resetnormal` | Attempt to exit kernel/service mode |
| `xordiff` | XOR two encrypted firmware files to find version bytes |
| `patchfw` | Patch firmware ASCII header to spoof version |

### crossflash command

```
drivekit crossflash E --file kernel.bin --file2 normal.bin [--key 0x6123789A]
```

Model string and key are auto-detected from the drive via `READ BUFFER 0xA0`.
The universal key `0x6123789A` is used as fallback. Use `--key` to override.

### xordiff command

```
drivekit xordiff --file fw_new.bin --file2 fw_old.bin
```

XORs two encrypted firmware files to find differing byte positions.
Non-zero positions = version/date/checksum bytes that differ between versions.
No drive needed — pure file analysis.

### patchfw command

```
drivekit patchfw --file fw_ref.bin --file2 fw_target.bin
```

Patches ASCII header bytes in `fw_target` to match `fw_ref` (version, date, filename).
Only patches printable ASCII bytes — binary/crypto regions are preserved.
Output saved as `fw_target_patched.bin`. No drive needed.

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
| `0xA0` | Model string + unlock key (read before Engineering Mode) |
| `0xB0` | Capability data — H8S/2600 code visible (pre-cutoff only!) |
| `0xF1` | Drive identity: serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash contents (requires service mode) |
| `0xFE` | Kernel area (NAND write target in crossflash protocol) |
| `0xF0` | Normal firmware area (NAND write target in crossflash protocol) |
| `0x00` | Universal firmware buffer (post-cutoff) |
| `0xE5` | Engineering Mode flag setter |
| `0xFF` | Execution trigger (commit flash to NAND) |

---

## Pending Research

- **Pre-cutoff downgrade** — version check in encrypted binary is the remaining barrier:
  - Version check reads encrypted payload, ASCII header patch insufficient
  - Need: kernel modification to remove version check (Billy collaboration pending)
  - OR: LCG seed extraction to re-encrypt firmware with spoofed version bytes
- **XD06U post-cutoff downgrade** — same encrypted binary version check barrier
- **MrPenguin** — H8S/2600 disassembly, `0xB0` analysis, share `0xFE`/`0xFC` dump method
- **Extract trigger keys** from all updater exes in firmware archive

---

## Credits

**MrPenguin** — H8S/2600 deep firmware analysis, rolling XOR cipher reverse engineering, BDR-S12U pypcode/Ghidra analysis, unlock key endianness clarification, `0xB0` READ BUFFER disassembly, and ongoing technical guidance that has been invaluable throughout this project.

**greg1wto** — provided the tools we needed to capture a live BDRFlash crossflash session with Wireshark/USBPcap, which made the NAND write protocol analysis possible.

Thank you for the inspiration and help from cxplay, Sayaka, Coopervid, blackened2687, Billy, MakeMKV Forum and cdrinfo.pl

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
