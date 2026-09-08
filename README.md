# DriveKit v1.0
### Optical Drive Research Toolkit
**by cPix / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

Reverse engineering of the flash protocol was done by capturing USB traffic between Pioneer's own official flasher and the freeware `BDRFlash` tool and a drive (Wireshark/USBPcap), then analyzing the resulting binary with IDA Pro and x64dbg — **reading x86 assembly only, no decompilation to C or other high-level languages was performed at any point**. This project documents the vendor's WRITE BUFFER unlock sequence, the model/key payload format, the READ BUFFER 0xB0 kernel-mode trigger, drive-family compatibility groups, and the internal model string table required for newer drive families.

---

## ⚠️ Risk

This tool talks to your optical drive at the raw SCSI/ATAPI command level and includes commands that **flash drive firmware** and **enter a vendor service/kernel mode**. Used incorrectly — wrong drive selected, incompatible firmware, or a command sent to an unsupported drive family — this can **brick the drive**. Some probe commands (`probevendor`, `unlock`) can also leave a drive unresponsive until it is power-cycled.

- Always confirm the drive letter before running a `flash*`, `unlock`, or `probevendor` command.
- Don't use `--force` unless you understand what compatibility check you're bypassing.
- Firmware flashing commands write a backup of the existing firmware — keep it.
- Run as Administrator on Windows; run with `sudo` on Linux.
- After flashing, wait **at least 2 minutes** before unplugging the drive — the NAND write continues internally after the USB transfer completes.

---

## Hardware Research

Pioneer BD drives use the **Renesas H8S/2000** processor — a big-endian 16/32-bit RISC CPU. Confirmed by decoding the 0xB0 READ BUFFER dump and disassembling as H8S/2000 assembly.

**Note:** Earlier community analysis suggested ARM Thumb-2 (ARMv6). H8S/2000 is now confirmed correct via direct assembly analysis.

**Memory map confirmed from H8S/2000 assembly (SAT 8801 family):**
- `0x00100000` = bootloader start
- `0x00400000` = main firmware start
- `0x00410000` = model string storage (`PIONEER  BDR-211`)
- `0xFF414000` = physical address mapped via 0xB0 handler
- `0x5E0000-0x5FFFFF` = hardcoded hole in 0xB0 handler

**TWO unlock keys confirmed from WRITE BUFFER handler assembly (0x0044BC10):**
```asm
cmp.l   #h'9a782361, er0    ; 0x9A782361 BE = 0x6123789A LE (primary)
cmp.l   #h'94e0f25c, er0    ; 0x94E0F25C BE = 0x5CF2E094 LE (secondary)
```

The unlock handler compares the first 16 bytes of the payload against the **internal firmware model string** — NOT the INQUIRY product string. These differ on newer drive families:

| Drive family | INQUIRY string | Internal model string |
|---|---|---|
| BDR-211M (SAT 8801) | `BD-RW   BDR-211M` | `PIONEER BDR-BDS5` |
| BDR-XD07/AD07 (SAT 8D30) | `BD-RW   BDR-AD07` | `PIONEER BDR-BDS7` |
| BDR-XD08 (SAT 9330) | `BD-RW   BDR-XD08` | `PIONEER BDR-BDS8` |

**This is a significant finding** — BDRFlash uses the wrong model string for newer BDS7/BDS8 family drives, causing unlock failures that appear as drive incompatibility. DriveKit implements a correct internal model string lookup table (`mdl_map`) for all known drive families.

---

## Post-Cutoff Protection

Pioneer introduced firmware version protection around 2022-2023. Post-cutoff firmware:

1. **Accepts the unlock command** with correct model string and key
2. **Accepts kernel/firmware data** transferred via WRITE BUFFER
3. **Silently refuses to commit** the data to NAND — execution trigger returns GOOD but nothing happens
4. **Cannot be downgraded** — same-version reflash also blocked

**Confirmed post-cutoff versions:**
- BDR-AD07 / BDR-XD07 — firmware **1.04** and later
- BDR-XD08 — firmware **1.04** and later
- BDR-209M — firmware **1.55** and later

**Last safe versions:**
- BDR-AD07 / BDR-XD07 — **1.03** (confirmed, checksum `0A48BD40` kernel, `3AEA3453` normal)
- BDR-XD08 — **1.01** or **1.02** (to be confirmed)

**Open research:** The post-cutoff protection mechanism in the NAND write handler has not yet been reversed. The execution trigger `WRITE BUFFER mode=5 bufID=0xFF` returns GOOD but does not commit. Dumping the trigger handler from H8S/2000 assembly is the next research target.

---

## Supported Drives

DriveKit supports **365+ Pioneer BD drive firmware entries** across all major families, documented in `drives.json`. Key researched drives:

| Model | Platform | Drive ID | Notes |
|-------|----------|----------|-------|
| BDR-XD05 (JP) | SAT 8231 | ID35 | Crossflash to XD06U confirmed |
| BDR-XD06U | SAT 8B30 | ID69 | Unlock key 0x6123789A confirmed |
| BDR-AD07 | SAT 8D30 | ID32 | Internal model `PIONEER BDR-BDS7`. Post-cutoff at 1.04 |
| BDR-XD08 | SAT 9330 | ID36 | Internal model `PIONEER BDR-BDS8`. Post-cutoff at 1.04 |
| BDR-209M | SAT 8601 | ID58 | Post-cutoff at 1.55 |
| BDR-211M | SAT 8801 | ID60 | ASUS OEM rebadge. H8S/2000 assembly analyzed |
| BDR-S12U | SAT 8F01 | ID43 | Firmware 1.02 documented |

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

Single source file — no separate headers needed.

---

## Usage

```
drivekit <command> <drive_letter> [options]
```

If the drive letter is omitted, DriveKit scans all optical drive letters and prompts you to pick one.

### Options

| Option | Description |
|---|---|
| `--bufid 0xF4` | Buffer ID for `rawdump` (default `0xF4`) |
| `--file name` | Output/input filename override |
| `--file2 name` | Secondary filename override |
| `--force` | Skip compatibility/ready checks |
| `--nounlock` | Skip the unlock step in flash commands |
| `--key 0x5CF2E094` | Override unlock key (default: derived from drive ID) |

---

## Commands

**Identification / probing**

| Command | Description |
|---|---|
| `inquiry` | Read drive vendor/model/firmware identity |
| `info` | Full drive information including serial decode |
| `driveinfo` | Full MMC feature probe and supported profile list |
| `discinfo` | Read and parse BD/DVD disc information |
| `modelcheck` | Look up Pioneer model against known drive-family table |
| `probevendor` | Probe vendor commands 0xC0-0xFF and report responses |
| `probeb0` | Probe READ BUFFER 0xB0 capability data |
| `rawdump` | Raw READ BUFFER dump (`--bufid`) |
| `checkcompat` | Check drive against compatibility.json for safe crossflash |

**Buffer / firmware dumping**

| Command | Description |
|---|---|
| `rawdump --bufid 0xB0` | Capability/calibration data |
| `rawdump --bufid 0x92` | Drive config and factory calibration |
| `rawdump --bufid 0xF1` | Drive identity (serial, platform, kernel ID) |
| `rawdump --bufid 0xF4` | NAND flash contents (requires kernel mode) |
| `rawdump --bufid 0xFE` | Kernel area in RAM (requires kernel mode) |
| `triggerkernel` | Trigger kernel mode via READ BUFFER 0xB0 exploit (disc required, patched on newer firmware) |

**Service mode / flashing**

| Command | Description |
|---|---|
| `unlock` | Send WRITE BUFFER 0xFF service mode unlock |
| `flashfw` | Flash kernel + firmware (`--file`, `--file2`, `--nounlock`) |
| `autoflash` | Auto-detect and flash from `firmware\` folder |
| `brutekey` | Try all known Pioneer unlock keys |
| `keycheck` | Show which unlock key would be used for connected drive |
| `resetnormal` | Attempt to exit kernel/service mode |
| `sendcdb` | Send raw SCSI CDB to drive (advanced) |

> **Flash sequence:** `unlock G` → `flashfw G --file kernel.bin --file2 normal.bin --nounlock`
>
> **NAND dump sequence:** `triggerkernel G` (with disc) → `rawdump G --bufid 0xF4`

---

## DriveBrowser

DriveKit includes `drivebrowser` — a graphical database browser for `drives.json` and `compatibility.json`.

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

Features: Supabase cloud sync, sortable columns, search/filter, edit/add/delete entries, crossflash compatibility view.

---

## Serial Number Decode

Pioneer serial format (e.g. `NIDL001216JP`):

```
N  I  D  L  0  0  1  2  1  6  J  P
|  |  |-----|  |-----|  |--|  |--|
|  |  country  sequence  year  market
|  month (UNICODE mapping A=Jan...L=Dec)
plant code
```

### Month Encoding

DriveKit uses the UNICODE version mapping (straight A=Jan through L=Dec):

| Letter | Month | Letter | Month |
|--------|-------|--------|-------|
| A | January | G | July |
| B | February | H | August |
| C | March | I | September |
| D | April | J | October |
| E | May | K | November |
| F | June | L | December |

### Country Encoding

Positions 2-3 form a little-endian 16-bit word. Key finding: the BDRFlash ANSI version **hardcodes "China"** for all drives. Only the UNICODE version has the full lookup table. DriveKit implements the full table.

### Year Encoding

The year formula remains an **open research question**. Known data points:
- `NIDL001216JP` → September 2014
- `SEDL056253WL` → May 2005

---

## Buffer Research (READ BUFFER IDs)

### READ BUFFER 0xB0 — Capability/Calibration Data

Available on BDR-211M (SAT 8801) at firmware 1.53. Returns drive calibration data. Handler accepts offsets up to `0x880300` with a hardcoded hole at `0x5E0000-0x5FFFFF`. The repeating `00 55 1F 1A` pattern contains the bus encryption flags (`0x55`) checked by MakeMKV/LibreDrive for UHD capability.

### READ BUFFER 0x92 — Drive Config / Calibration Blocks

Available without unlock. Three regions confirmed on BDR-211M and BDR-XD08:

| Block | Content |
|-------|---------|
| `0x000000` | Drive capability header |
| `0x001000` | Factory calibration — laser power (`F4 8C`), servo params, dates |
| `0x002000` | Uninitialized (`0xCC` fill) |

XD08 capacity: `0x00103700`. BDR-211M capacity: `0x00100300`.

### READ BUFFER 0xF1 — Drive Identity

Returns serial, platform string and kernel ID. Available on all drives. Layout:
- Offset `0x00`: Serial number (12 bytes)
- Offset `0x10`: Platform string e.g. `SAT 9330ID36`
- Offset `0x20`: Firmware version (`0000` = kernel mode active)

### READ BUFFER 0xF4 — NAND Flash Contents

Requires kernel mode trigger + disc inserted. Returns encrypted NAND (~16MB). Trigger exploit patched in post-cutoff firmware. On XD08 in half-flash state reports 0 bytes (normal firmware partition empty).

### READ BUFFER 0xFE — Kernel Area (RAM)

Returns `0xFF` unless kernel mode active. Contains running firmware image. Written during flash via WRITE BUFFER 0xFE.

---

## Notes

- All SCSI pass-through calls have a 35s timeout.
- `drives.json` (365+ entries) and `compatibility.json` (60+ firmware files) are the database files.
- `autoflash` matches firmware files by content (Pioneer header), not filename.
- After flashing wait 2+ minutes before unplugging — NAND write continues internally.
- Linux port in progress — USB→SATA adapter required for internal SATA drives.

---

## Credits

- **blackened2687** — BDRFlash / AutoFlasher author, Pioneer flash protocol pioneer
- **Coppervid** — Outstanding support and testing
- **MakeMKV community** — Drive testing and research
- **rpc1dev** — DVRFlash open source reference

**Tools:** Wireshark + USBPcap, IDA Pro + hrtng plugin, x64dbg, Visual Studio 2022, WSL, GCC

---

## Glossary

| Term | Description |
|------|-------------|
| **SCSI** | Command protocol used to communicate with optical drives, even over USB or SATA |
| **CDB** | Command Descriptor Block — raw bytes sent to the drive |
| **READ BUFFER** | SCSI opcode `0x3C` — reads internal drive memory regions |
| **WRITE BUFFER** | SCSI opcode `0x3B` — writes to internal drive memory; used for unlock and flash |
| **Kernel** | First firmware component (buffer 0xFE) — low-level drive control |
| **Normal** | Second firmware component (buffer 0xF0) — drive behaviour and features |
| **NAND** | Flash memory inside the drive storing firmware and config (buffer 0xF4) |
| **Platform ID** | Drive family identifier e.g. `SAT 9330` |
| **Internal model string** | Firmware's own model name, used in unlock payload — differs from INQUIRY string on newer drives |
| **Unlock** | WRITE BUFFER 0xFF command that enters service mode before flashing |
| **Kernel mode** | Drive state triggered via READ BUFFER 0xB0 exploit — enables NAND dump |
| **Crossflash** | Flashing firmware from a compatible but different drive model |
| **Post-cutoff** | Firmware versions with NAND write protection preventing downgrade/crossflash |
| **ASC/ASCQ** | Additional Sense Code / Qualifier — SCSI error codes in sense data |

---

Research and educational purposes only. Always back up firmware before flashing. Authors take no responsibility for bricked drives. Use at your own risk.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*
