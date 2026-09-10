# DriveKit v1.0
### Optical Drive Research Toolkit
**by cPix / Razor 1911 (c) 2026**

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
- Known plaintext attack possible using serial number visible in NAND dumps

**16MB NAND dumps captured:**
- BDR-XD08 (SAT 9330 ID36) — pre-cutoff 1.02
- BDR-XD06U (SAT 8B30 ID69) — post-cutoff 1.12 ← NEW!

**Memory map (SAT 8801 family):**
- `0x00100000` = bootloader
- `0x00400000` = main firmware
- `0x00410000` = model string storage
- `0xff3ff000` = crypto/DMA engine (flash + AES verification)

**TWO unlock keys confirmed from H8S/2000 assembly:**
```
0x6123789A  (primary)
0x5CF2E094  (secondary, different handler)
```

---

## Flash Protocol — Confirmed from Wireshark Capture

Full reverse engineering of the BDRFlash protocol confirmed via USB capture of working flash sessions.

### 1. Session Token
```
READ BUFFER 0xA0 mode=2 offset=0x90 len=0x10  → 16-byte token
```
On pre-cutoff drives returns model string + key. On post-cutoff drives returns dynamic token.

### 2. Unlock
```
WRITE BUFFER mode=4 bufID=0xFF len=0x100   (pre-cutoff)
WRITE BUFFER mode=1 bufID=0x00 len=0x20    (post-cutoff) ← NEW!
```
**A disc in the drive causes unlock to fail with ASC=04 — always eject first!**

### 3. Kernel firmware transfer
```
WRITE BUFFER mode=7 bufID=0xFE  (0x8000 byte chunks)
```

### 4. Normal firmware transfer
```
WRITE BUFFER mode=7 bufID=0xF0  (0x8000 byte chunks)
```

### 5. Execution trigger
```
WRITE BUFFER mode=5 bufID=0xFF len=0x100
```
Returns `ASC=4C` (LOGICAL UNIT FAILED SELF-TEST) if kernel/normal firmware pair is rejected.

### 6. Wait for NAND write
```
GET EVENT STATUS × 160  →  TEST UNIT READY + REQUEST SENSE × 300
```
Drive reboots itself. **No power cycle needed.**

---

## Critical Discovery: Post-Cutoff Unlock (NEW!)

**`WRITE BUFFER mode=0x01 bufID=0x00 len=0x20`** — previously undocumented Pioneer vendor command that gives service mode access on post-cutoff drives!

```
Payload: [16-byte internal model string] + [4-byte key in LE]

Example (BDR-XD06U post-cutoff):
  Model string: "XD05BK2/XV5     "
  Key:          F2 8A A9 08  (0x08A98AF2 in LE)
  Full payload: 58 44 30 35 42 4B 32 2F 58 56 35 20 20 20 20 00 F2 8A A9 08
```

**Important:** The drive returns CHECK CONDITION with sense key=0x00 on success — this is normal! Do not treat sense key=0x00 as failure.

This unlock gives access to:
- ✅ NAND dump (`bufID=0xF4`)
- ✅ Kernel firmware transfer (`bufID=0xFE`)
- ❌ Normal firmware transfer (`bufID=0xF0`) — requires additional research

---

## Post-Cutoff Flash Sequence (NEW!)

Confirmed from Wireshark capture of Pioneer official updater flashing XD06U 1.12:

```
ORDER IS DIFFERENT from pre-cutoff:
1. Normal firmware first  (bufID=0xF0)
2. Kernel               (bufID=0xFE) — only 4 chunks
3. Normal firmware AGAIN (bufID=0xF0)
4. Execution trigger
```

DriveKit supports this via `--file2` (normal pass 1) + `--file` (kernel) + `--file3` (normal pass 2).

---

## Critical Discovery: Firmware Pairing

**Kernel ID and normal firmware must match exactly.** The execution trigger validates the pair before issuing the NAND write command:

| Kernel | Normal | Result |
|--------|--------|--------|
| ID36 + ID36 | ✅ NAND commits |
| ID36 + ID35 | ❌ ASC=4C rejected |
| ID36 + ID05 | ❌ ASC=4C rejected |
| ID69 + ID69 | ✅ NAND commits |

**XD08 Recovery:** A drive stuck in kernel mode with empty NAND can be recovered by flashing a matched firmware pair — no version check possible with empty NAND.

---

## Internal Model Strings (NEW entries!)

| Drive | Platform | Kernel | Internal model string |
|-------|----------|--------|----------------------|
| BDR-XD05 (SAT 8231) | pre-cutoff | ID32 | `PIONEER BDR-XD05` |
| BDR-XD06U (SAT 8B30) | pre-cutoff | ID69 | `PIONEER BDR-XS06` |
| BDR-XD06U (SAT 8B30) | post-cutoff | ID69 | `XD05BK2/XV5     ` ← NEW! |
| BDR-AD07 (SAT 8D30) | — | — | `PIONEER BDR-BDS7` |
| BDR-XD08 (SAT 9330) | — | ID36 | `PIONEER BDR-BDS8` |
| BDR-211M (SAT 8801) | — | — | `PIONEER BDR-BDS5` |

**Key discovery:** Post-cutoff drives use a completely different internal model string format — NOT the `PIONEER BDR-XXX` pattern!

---

## Unlock Keys (NEW!)

| Key | Drive family | Notes |
|-----|-------------|-------|
| `0x6123789A` | Primary (most drives) | Confirmed from H8S/2000 assembly |
| `0x5CF2E094` | Secondary | Different handler |
| `0xBE4B8754` | XD05 post-cutoff (SAT 8232) | Found in BDR-XD05BKXL2 updater.exe |
| `0x08A98AF2` | XD06U post-cutoff (SAT 8B30) | Found in BDR-XD06J-UHD updater.exe ← NEW! |

---

## Post-Cutoff Protection

Pioneer introduced firmware version protection in **December 2022**. Post-cutoff firmware:
1. Uses different internal model string (e.g. `XD05BK2/XV5` instead of `PIONEER BDR-XS06`)
2. Requires `WRITE BUFFER mode=0x01` for service mode access
3. Post-cutoff flash sequence: normal → kernel → normal → trigger
4. Cannot be downgraded — post-cutoff kernel rejects older normal firmware (`ASC=4C`)

**Confirmed post-cutoff dates (December 2022):**
- BDR-XD08 / XD08LE — firmware 1.02 (Generated: 2022-12-27)
- BDR-XD07 / AD07 / XD07U — firmware 1.05
- BDR-XD06U — firmware 1.12 (Generated: 2023-03-03) ← NEW!
- BDR-XD05 — firmware 1.22 / 2.11 / 3.11

**Last safe pre-cutoff versions:**
- BDR-XD08 — **1.01** (2022-10-11), requires `ID36` firmware pair
- BDR-XD07U / AD07 — **1.04** (2022-05-31) ✅ UHD capable
- BDR-XD06U — **1.11** ✅ UHD capable
- BDR-XD05 — **3.01 / 2.10 / 1.21**

**Important:** Post-cutoff drives still support LibreDrive and UHD reading — the protection only blocks downgrading/crossflashing!

---

## Pioneer Updater.exe Reverse Engineering (NEW!)

Analysis of `BDR-XD05BKXL2_WXL2_RXL2_LE2_SVLE2\Updater.exe`:

- Firmware filename hardcoded: `S8232321.211`
- Kernel ID: `ID32`
- Internal model string: `PIONEER BDR-XD05`
- Post-cutoff key: `0xBE4B8754`
- Drive ID check at `0x00002E0C`: change `jnz` → `jmp` (opcode `75` → `EB`) to bypass
- Uses **WNASPI32** for SCSI (not IOCTL like DriveKit)
- `FOGEFOGE` and `DUMMY` are template placeholders for unlock key/model string

**Billy Carr's two-stage process** (from community intel):
1. Modified Pioneer official flasher downgrades same-model firmware (e.g. 1.54→1.53)
2. Power cycle
3. AutoFlasher/BDRFlash crossflashes to UHD target firmware

---

## Confirmed Crossflashes & Results

| From | To | Firmware | UHD | Notes |
|------|-----|---------|-----|-------|
| BDR-XD05 (8231) | BDR-XD06U (8B30) | 1.11 | ✅ | UHD ripping confirmed |
| BDR-AD07 (8D30) | BDR-XD07U (8D31) | 1.04 pre-cutoff | ✅ | UHD confirmed |
| BDR-XD08 (9330) | BDR-XD08 (9330) | 1.02 | ✅ | Recovered from kernel limbo |
| BDR-XD06U (8B30) | BDR-XD06U (8B30) | 1.12 post-cutoff | ✅ | LibreDrive + UHD works! ← NEW! |

---

## Drive File Naming Convention

```
S[platform][kernel_id][type].[version]

S9330 36 0 .102  = SAT 9330, Kernel ID36, type 0 (kernel), version 1.02
S9330 36 1 .101  = SAT 9330, Kernel ID36, type 1 (normal), version 1.01
S8B30 69 0 .112  = SAT 8B30, Kernel ID69, type 0 (kernel), version 1.12  ← NEW!
S8B30 69 1 .112  = SAT 8B30, Kernel ID69, type 1 (normal), version 1.12  ← NEW!
```

---

## Build

**Windows (MSVC):**
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
| `--file3 name` | Second normal firmware pass (post-cutoff drives) |
| `--force` | Skip compatibility checks |
| `--nounlock` | Skip unlock step |
| `--key 0x5CF2E094` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |

---

## Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| `unlock` | Service mode unlock (auto-detects pre/post-cutoff) |
| `flashfw` | Flash kernel + firmware |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB (auto-detects read/write direction) |
| `resetnormal` | Attempt to exit kernel/service mode |
| `triggerkernel` | Trigger kernel mode via 0xB0 |

> **Pre-cutoff flash sequence:**
> ```
> drivekit unlock G
> drivekit flashfw G --file kernel.bin --file2 normal.bin --nounlock
> ```

> **Post-cutoff NAND dump:**
> ```
> drivekit unlock G
> drivekit rawdump G --bufid 0xF4
> ```

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
sudo apt install libgtk-3-dev libcurl4-openssl-dev
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

**Year encoding** (confirmed by cxplay):

Old format (pre-2021): A=2001, B=2002 ... Z=2026

New format (post-2021 reset): A=2021/2022, B=2022, C=2023, D=2024, E=2025, F=2026

**Factory codes:** `DL` = Pioneer High Technology (Dongguan) Co., Ltd., Guangdong, China

---

## Buffer IDs

| ID | Description |
|----|-------------|
| `0x92` | Drive config + factory calibration |
| `0xA0` | Session token / model string + key |
| `0xB0` | Capability/calibration data, bus encryption flags |
| `0xF1` | Drive identity: serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash contents (requires service mode) |
| `0xFE` | Kernel area (RAM) |
| `0xF0` | Normal firmware area (RAM) |

---

## Credits

- **blackened2687** — BDRFlash / AutoFlasher original author, Pioneer flash protocol pioneer
- **MrPenguin** — H8S/2000 deep firmware analysis (pypcode + Ghidra SLA), rolling XOR cipher discovery, BDR-S12U analysis, NAND dump analysis
- **cxplay** — Massive firmware archive (1.4GB+), `S9330360/361` discovery, serial number year formula
- **Sayaka** — Firmware hunting methodology, first community Supabase contribution (BDR-UD04 UHD confirmed)
- **Coppervid** — Outstanding support, testing, community liaison, XD08LE firmware files
- **MakeMKV community** — Drive testing, firmware contributions, community database

**BDRFlash special thanks** (from BDRFlash v1.00 about box):
Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen, ala42, czary2mary, jadburner, cvs, alexx12345, seku, Leman39, wujooj, jurireal, alphaville0527, SnowFox, Kirby, haysey70, Majestic12, elflorek, floppydumper, redwine, cryptojoe3737, TeddyRaspin, BillyCar11, asmcom, payalnik23, aliter404

**Tools:** Wireshark + USBPcap, IDA Pro + hrtng plugin, x64dbg, pypcode, Visual Studio 2022, WSL, GCC

---

## Glossary

| Term | Description |
|------|-------------|
| **Session token** | Dynamic value from READ BUFFER 0xA0, used as unlock payload |
| **Internal model string** | Firmware's own model name — differs from INQUIRY string, post-cutoff uses different format |
| **Firmware pair** | Kernel + normal firmware must share the same Kernel ID or execution trigger rejects with ASC=4C |
| **Post-cutoff** | Firmware after December 2022 — blocks downgrade, uses mode=0x01 unlock |
| **Kernel mode** | Drive state after unlock — firmware shows `0000` |
| **Kernel limbo** | Drive stuck in kernel mode with empty normal firmware NAND partition |
| **ID69** | Kernel variant for BDR-XD06U post-cutoff — NEW discovery! |
| **mode=0x01** | Undocumented WRITE BUFFER mode that unlocks post-cutoff drives |
| **ASC=4C** | LOGICAL UNIT FAILED SELF-TEST — execution trigger rejected the firmware pair |
| **ASC=24** | INVALID FIELD IN PARAMETER LIST — wrong CDB field or payload |

---

Research and educational purposes only. Always back up firmware before flashing.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*
