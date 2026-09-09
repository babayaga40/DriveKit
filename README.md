# DriveKit v1.0
### Optical Drive Research Toolkit
**by cPix / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering of the flash protocol was done by capturing USB traffic between the third-party `BDRFlash` tool and a drive (Wireshark/USBPcap), then analyzing the resulting binary with IDA Pro and x64dbg — **reading x86 assembly only, no decompilation to C or other high-level languages was performed at any point**. This project documents the vendor's WRITE BUFFER unlock sequence, the model/key payload format, the READ BUFFER 0xB0 kernel-mode trigger, drive-family compatibility groups, and the internal model string table required for newer drive families.

---

## ⚠️ Risk

This tool talks to your optical drive at the raw SCSI/ATAPI command level and includes commands that **flash drive firmware** and **enter a vendor service/kernel mode**. Used incorrectly — wrong drive selected, incompatible firmware, or a command sent to an unsupported drive family — this can **brick the drive**. Some probe commands (`probevendor`, `unlock`) can also leave a drive unresponsive until it is power-cycled.

- Always confirm the drive letter before running a `flash*`, `unlock`, or `probevendor` command.
- Don't use `--force` unless you understand what compatibility check you're bypassing.
- Firmware flashing commands write a backup of the existing firmware — keep it.
- Run as Administrator on Windows; run with `sudo` on Linux.
- After the execution trigger the drive writes to NAND internally — **do not unplug** until the tool reports completion.

---

## Hardware Research

Pioneer BD drives use the **Renesas H8S/2000** processor — a big-endian 16/32-bit RISC CPU. Confirmed by decoding the 0xB0 READ BUFFER dump and disassembling as H8S/2000 assembly.

**Memory map confirmed from H8S/2000 assembly (SAT 8801 family):**
- `0x00100000` = bootloader start
- `0x00400000` = main firmware start
- `0x00410000` = model string storage (`PIONEER  BDR-211`)
- `0xFF414000` = physical address mapped via 0xB0 handler

**TWO unlock keys confirmed from WRITE BUFFER handler assembly (0x0044BC10):**
```asm
cmp.l   #h'9a782361, er0    ; 0x9A782361 BE = 0x6123789A LE (primary)
cmp.l   #h'94e0f25c, er0    ; 0x94E0F25C BE = 0x5CF2E094 LE (secondary)
```

---

## Flash Protocol — Confirmed from Wireshark Capture

Full reverse engineering of the BDRFlash protocol confirmed via USB capture. The complete working sequence:

### 1. Session Token (pre-cutoff drives)
```
READ BUFFER 0xA0 mode=2 offset=0x90 len=0x10  → get session token
```
Returns 16-byte dynamic token that changes each power-on. Pre-cutoff drives return the model string here instead (token not used).

### 2. Unlock
```
WRITE BUFFER mode=4 bufID=0xFF len=0x100  → send token as payload
```
For pre-cutoff drives: payload = internal model string (e.g. `PIONEER BDR-BDS7`) + 4-byte key at offset 0x10.
For post-cutoff drives: payload = 0xA0 session token (dynamic, read from drive).

### 3. Kernel firmware transfer
```
WRITE BUFFER mode=7 bufID=0xFE offset=0x0000 len=0x8000  → chunk 1
WRITE BUFFER mode=7 bufID=0xFE offset=0x8000 len=0x8000  → chunk 2
...  (0x8000 byte chunks)
```
**Critical: must use 0x8000 byte chunks — larger transfers prevent NAND commit!**

### 4. Normal firmware transfer
```
WRITE BUFFER mode=7 bufID=0xF0 offset=0x0000 len=0x8000  → chunk 1
WRITE BUFFER mode=7 bufID=0xF0 offset=0x8000 len=0x8000  → chunk 2
...  (0x8000 byte chunks)
```

### 5. Execution trigger
```
WRITE BUFFER mode=5 bufID=0xFF len=0x100  → same payload as unlock
```

### 6. Wait for NAND write + reboot
```
GET EVENT STATUS × 160   → poll while drive processes
TEST UNIT READY          → check if drive ready
REQUEST SENSE            → after every TUR (sense key 0x0C = NAND writing)
```
Drive reboots itself into normal mode when NAND write completes. **No power cycle needed.**

---

## Internal Model Strings

The WRITE BUFFER unlock handler compares the payload against the **internal firmware model string** — NOT the INQUIRY product string. These differ on newer drive families:

| Drive family | INQUIRY string | Internal model string |
|---|---|---|
| BDR-211M (SAT 8801) | `BD-RW   BDR-211M` | `PIONEER BDR-BDS5` |
| BDR-XD05 (SAT 8231) | `BD-RW   BDR-XD05` | `PIONEER BDR-XD05` |
| BDR-XD06U (SAT 8B30) | `BD-RW  BDR-XD06U` | `PIONEER BDR-XD06` |
| BDR-XD07/AD07 (SAT 8D30) | `BD-RW   BDR-AD07` | `PIONEER BDR-BDS7` |
| BDR-XD08 (SAT 9330) | `BD-RW   BDR-XD08` | `PIONEER BDR-BDS8` |

**BDRFlash bug confirmed:** Uses wrong model strings for BDS7/BDS8 families causing unlock failures. DriveKit implements correct internal model string lookup (`g_mdl_map` table).

---

## Post-Cutoff Protection

Pioneer introduced firmware version protection around 2022-2023. Post-cutoff firmware:

1. **Accepts the unlock command** with correct model string and key
2. **Accepts kernel/firmware data** transferred via WRITE BUFFER
3. **Execution trigger returns GOOD** — but NAND write never starts
4. **Cannot be downgraded** — same-version reflash also blocked

**Confirmed post-cutoff versions:**
- BDR-AD07 / BDR-XD07 — firmware **1.04** and later
- BDR-XD08 — firmware **1.04** and later
- BDR-XD05 — firmware **1.22 / 2.11 / 3.11** and later

**Last safe (pre-cutoff) versions:**
- BDR-AD07 / BDR-XD07 — **1.03** (CRC kernel: `0A48BD40`, normal: `3AEA3453`)
- BDR-XD05 — **3.01** / **2.10** / **1.21**
- BDR-XD06U — **1.11** (confirmed UHD capable)

**Post-cutoff recovery:** Drives in normal mode can be recovered using the `0xA0` session token unlock (reads token at offset `0x90`, sends it back as unlock payload). Drives stuck in kernel mode with empty NAND partition cannot currently be recovered — open research.

---

## Confirmed Crossflashes

| From | To | Firmware | UHD | Notes |
|------|-----|---------|-----|-------|
| BDR-XD05 (8231) | BDR-XD06U (8B30) | 1.11 | ✅ | Confirmed working, rips UHD |
| BDR-AD07 (8D30) | BDR-XD07U (8D31) | 1.04 | ✅ | Confirmed working, UHD identified by Windows |
| BDR-AD07 (8D30) | BDR-AD07 (8D30) | 1.03 | ❓ | Downgrade confirmed, UHD TBD |

---

## Supported Drives

DriveKit supports **365+ Pioneer BD drive firmware entries** across all major families, documented in `drives.json`. Key researched drives:

| Model | Platform | Drive ID | Notes |
|-------|----------|----------|-------|
| BDR-XD05 | SAT 8231 | ID35 | Crossflash to XD06U confirmed |
| BDR-XD06U | SAT 8B30 | ID69 | UHD ripping confirmed |
| BDR-AD07 | SAT 8D30 | ID32 | Downgrade to 1.03 confirmed |
| BDR-XD08 | SAT 9330 | ID36 | Post-cutoff research ongoing |
| BDR-211M | SAT 8801 | ID60 | H8S/2000 assembly analyzed |

---

## Build

**Windows (MSVC):**
```
cl drivekit.c /Fe:drivekit.exe /utf-8
```

**Linux (GCC):**
```
gcc drivekit.c -o drivekit -w
sudo ./drivekit inquiry /dev/sg1
```

---

## Usage

```
drivekit <command> <drive_letter> [options]
```

### Options

| Option | Description |
|---|---|
| `--bufid 0xF4` | Buffer ID for `rawdump` |
| `--file name` | Kernel firmware file |
| `--file2 name` | Normal firmware file |
| `--force` | Skip compatibility checks |
| `--nounlock` | Skip unlock step |
| `--key 0x5CF2E094` | Override unlock key |

---

## Commands

| Command | Description |
|---|---|
| `info` | Full drive information with serial decode |
| `inquiry` | Drive vendor/model/firmware |
| `unlock` | Service mode unlock (auto-detects token or model string method) |
| `flashfw` | Flash kernel + firmware (`--file`, `--file2`, `--nounlock`) |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump (`--bufid`) |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB |
| `resetnormal` | Attempt to exit kernel/service mode |
| `triggerkernel` | Trigger kernel mode via 0xB0 exploit |

> **Flash sequence:**
> ```
> drivekit unlock G
> drivekit flashfw G --file kernel.bin --file2 normal.bin --nounlock
> ```

---

## DriveBrowser

Graphical database browser for `drives.json` and `compatibility.json` with Supabase cloud sync.

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
|  |  country  sequence  year  market
|  month (A=Jan ... L=Dec)
plant code
```

Month encoding (UNICODE version — straight A=Jan through L=Dec).

---

## Buffer Research

| Buffer ID | Name | Notes |
|-----------|------|-------|
| `0x92` | Drive config | Capacity header + factory calibration |
| `0xA0` | Session token | Pre-flash challenge token (offset 0x90) |
| `0xB0` | Capability data | Bus encryption flags, laser calibration |
| `0xF1` | Drive identity | Serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash | Requires kernel mode trigger + disc |
| `0xFE` | Kernel RAM | Active kernel image |
| `0xF0` | Normal RAM | Active normal firmware image |

---

## Glossary

| Term | Description |
|------|-------------|
| **Session token** | Dynamic 16-byte value from READ BUFFER 0xA0 offset=0x90, used as unlock payload on post-cutoff drives |
| **Internal model string** | Firmware's own model name used in unlock payload — differs from INQUIRY string on newer drives |
| **Post-cutoff** | Firmware with NAND write protection — accepts data but silently refuses to commit |
| **Kernel mode** | Drive state after unlock — firmware shows `0000`, NAND write enabled |
| **Crossflash** | Flashing firmware from compatible different drive model |
| **0x8000 chunks** | Required transfer size for WRITE BUFFER — larger chunks prevent NAND commit |
| **key=0C** | Sense key during TUR polling indicating active NAND write in progress |

---

## Credits

- **blackened2687** — BDRFlash / AutoFlasher original author
- **Coppervid** — Outstanding support and testing
- **MakeMKV community** — Drive testing and research

**Tools:** Wireshark + USBPcap, IDA Pro, x64dbg, Visual Studio 2022, WSL, GCC

---

Research and educational purposes only. Always back up firmware before flashing. Authors take no responsibility for bricked drives.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*
