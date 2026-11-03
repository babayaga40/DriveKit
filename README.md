# DriveKit v1.0
### Optical Drive Research Toolkit
**by BabaYaga / Razor 1911 (c) 2026**

Combined optical drive & storage research toolkit for Windows and Linux, targeting Pioneer BD-R/BD-RE optical drives. All functionality is bundled into a single binary, with the operation selected via a command-line subcommand.

---

## 🚀 Quick Start — Flashing Firmware

This section covers the most common operations. Read the [Risk](#️-risk) section first.

### Step 1 — Find your drive

```
drivekit info E
```

This shows the drive model, current firmware version, firmware date, platform (e.g. `SAT 8D31`), and kernel ID (e.g. `ID05`). The drive letter (`E`) is whatever Windows assigned — check Device Manager if unsure. On Linux use `/dev/sgX`.

> **Important:** Always verify the correct drive letter before running any flash command. Flashing the wrong drive is not recoverable.

### Step 2 — Get the firmware files

Pioneer firmware packages contain two files:
- **Kernel** — a small file (e.g. `S8D31050.104`, typically ~70 KB)
- **Normal** — the main firmware body (e.g. `S8D31051.104`, typically ~1.8 MB)

The filename convention is `S<platform><type><version>`:
- `S8D31` = platform SAT 8D31
- `050` = Kernel file, `051` = Normal file
- `104` = firmware version 1.04

Firmware files are not distributed with DriveKit — source them from Pioneer's official updater packages or community archives.

### Step 3 — Flash

```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104
```

DriveKit auto-detects the drive era, firmware era, and selects the correct flash protocol. You will be asked to confirm before anything is written.

**Downgrade with UHD patch** (POST→PRE, keeps UHD capability):
```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104 --patch
```

Use `--patch` when downgrading a UHD-capable drive to pre-cutoff firmware. It flips the generation marker byte in the kernel so UHD playback remains enabled.

**Drive already in kernel mode** (stuck showing firmware `0000`):
```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104 --nounlock
```

Use `--nounlock` when the drive is already in kernel/service mode from a previous failed flash. DriveKit skips the unlock step and flashes directly. Make sure the kernel file matches the kernel ID the drive is running (check with `drivekit info`).

### Step 4 — Wait

After the commit trigger is sent and the drive responds GOOD, **do not touch the drive for at least 20 seconds**. The drive is performing its internal reflash. Interrupting power at this point can brick the drive.

When the LED stops blinking, power-cycle the drive (unplug and replug USB, or restart the PC for internal drives), then run `drivekit info E` again to confirm the new firmware version.

---

## Protocol Auto-Detection

DriveKit selects the flash protocol automatically based on two things:

| Drive era | Target firmware era | Protocol used |
|-----------|-------------------|---------------|
| PRE-cutoff | PRE-cutoff | Single-pass (kernel + normal) |
| PRE-cutoff | POST-cutoff | 4-transfer upgrade layout |
| POST-cutoff | PRE-cutoff | 3-chunk flat kernel + downgrade layout |
| POST-cutoff | POST-cutoff | 4-transfer upgrade layout |

**Drive era** is detected by probing `READ BUFFER 0xB0` — pre-cutoff drives respond, post-cutoff drives return an error.

**Firmware era** is detected by decrypting the first 12 DWORDs of the Normal firmware body and checking byte `[0x28]` — `0x01` = post-cutoff (new layout), `0xFF` = pre-cutoff (old layout). This is more reliable than the date string in the header.

The cutoff date is **2022-12-27** — firmware generated before this date uses the old protocol; firmware after uses the new layout.

---

## Troubleshooting

**Drive shows firmware `0000` / stuck in kernel mode**

The drive entered kernel mode (e.g. after a failed flash or unlock) and didn't return. Use `--nounlock` to flash directly without a second unlock attempt. Make sure you use a kernel file whose Kernel Version matches what the drive reports — a mismatched kernel ID causes a silent failure where the drive stays in `0000`.

**Flash completes but firmware version didn't change**

The commit trigger returned GOOD but the drive's internal flash rejected the write. Most common causes:
- Wrong kernel ID for this drive (check the kernel header's `Kernel Version` field)
- Wrong flash protocol for the drive/firmware combination (DriveKit auto-detects, but `--nounlock` bypasses the drive era probe — double-check the drive era in this case)
- Power interrupted during the internal reflash window

**`04/4C/02` error (HARDWARE ERROR / LOGICAL UNIT FAILED SELF-CONFIGURATION)**

The drive rejected the commit. Usually means wrong protocol was used for the drive/firmware combination. If you used `flashfw` instead of `flash`, switch to `flash` — `flashfw` does not implement the 4-transfer new layout needed for post-cutoff firmware.

**PRE→PRE cross-family warning**

If you see a warning about PRE→PRE cross-family flash (different SAT platform on drive vs firmware), the flash will still proceed. This path is untested. If the drive ends up in kernel mode, power-cycle and retry with a firmware file that matches the drive's platform.

---

**November 2026 milestones:**
- DriveKit successfully performed a **pre-cutoff → post-cutoff upgrade** on a **Pioneer BDR-XD07U (SAT 8D31 / ID05)**: 1.04 → 1.06, using the new 4-transfer kernel layout. Commit returned SCSI GOOD; post-reflash INQUIRY confirmed firmware 1.06.
- DriveKit successfully performed a **post-cutoff → pre-cutoff downgrade**: post-cutoff firmware → 1.04 (patched kernel, `--patch`). Commit returned SCSI GOOD; post-reflash INQUIRY confirmed firmware 1.04.
- DriveKit successfully performed a **post-cutoff → post-cutoff same-era flash**: 1.06 → 1.05 using the same new 4-transfer kernel layout. Commit returned SCSI GOOD; post-reflash INQUIRY confirmed firmware 1.05.
- Added **`scankey`**, an offline scanner that extracts the update-entry unlock key directly from decoded Normal firmware. It recovered the known XD07 key and flagged a conflicting entry for `S8800601.153`.

All three results are verified on tested hardware; not a claim of universal compatibility.

See [Confirmed working](#-confirmed-working), [Flash Protocol](#flash-protocol), and [KernelFront patch validation](#kernelfront-patch-validation).

Reverse engineering was performed through multiple methods:

**Pre-cutoff / crossflash protocol:** greg1wto provided the tools we needed to perform Wireshark/USBPcap capture analysis. Combined with reverse engineering of official Pioneer updater executables by BabaYaga, this revealed the complete two-pass firmware write protocol, trigger payload structure, and unlock key format.

**Post-cutoff protocol:** Reverse engineered the official Pioneer updater executables (`BDR-XD06J-UHD`, `BDR-XD07UHD`) with IDA Pro — reading x86 assembly only, no decompilation. This revealed the session token mechanism, buffer IDs and offsets, drive-specific trigger keys, and the Engineering Mode unlock sequence.

**Drive firmware:** H8S/2600 assembly analysis of `READ BUFFER 0xB0` dumps (MrPenguin), revealing the rolling XOR stream cipher and the Engineering Mode gating conditions.

**KernelFront cipher:** Reverse engineered by MattJackson — the XOR/rotate cipher protecting Pioneer H8S/2600 kernel files, enabling direct kernel inspection and patching.

---

## ⚠️ Risk

This tool talks to your optical drive at the raw SCSI/ATAPI command level and includes commands that **flash drive firmware** and **enter a vendor service/kernel mode**. Used incorrectly — wrong drive selected, incompatible firmware, or a command sent to an unsupported drive family — this can **brick the drive**.

- Always confirm the drive letter before running any flash or unlock command
- Don't use `--force` unless you understand what compatibility check you're bypassing
- Run as Administrator on Windows
- After the execution trigger **do not unplug or interrupt power** while the drive performs its internal reflash; a GOOD commit response is not the end of the process
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

**Key selection is protocol- and drive-dependent.** The universal key (`0x6123789A`, wire bytes `9A 78 23 61`) has been used successfully on previously tested SAT 9330/9331 paths. In the verified BDR-XD07U SAT 8D31 / ID05 downgrade, **both unlock and commit** used `0xFF8A27B1` (wire bytes `B1 27 8A FF`). Do not assume the universal key applies to every `crossflash` path; compare the selected model/key and the complete 256-byte trigger payload with a known-good capture.

**Firmware-derived update-entry key detection (`scankey`):** The scanner examines *decoded Normal firmware* for a recognized H8S/2600 acceptance-handler instruction pattern, follows its branch displacement to a key-comparison instruction, and extracts the embedded four-byte key. The recognition method is based on MattJackson's content-derived receiver-control analysis. This is **not** the Normal firmware decryption key. The extracted bytes are reported in wire order and as a little-endian DWORD. The scanner requires an unambiguous keyed-handler match; a matching pattern does not by itself prove a flash protocol is safe for the target drive. See [scankey command](#scankey-command).

**Important key-table audit:** On decoded `S8800601.153`, `scankey` found `94 E0 F2 5C` (LE DWORD `0x5CF2E094`), while the existing table selected `0x6123789A`. This is a **discrepancy**, not yet a hardware-validated replacement for that drive/protocol. The old value corresponds to the fixed four-byte immediate `9A 78 23 61` within the acceptance signature; this makes accidental extraction of that signature constant a plausible explanation worth auditing, but does not invalidate all other previously successful uses of `0x6123789A`. Verify against a known-good capture before flashing.

**Pre vs post-cutoff detection:** DriveKit probes ordinary `READ BUFFER 0xB0` access before the special `hwdump` trigger sequence:
- Returns data → **pre-cutoff** drive (before 2022-12-27) — H8S/2600 code visible
- Returns error 05/24 → **post-cutoff** drive under the ordinary probe; the separate `hwdump` trigger sequence can enable `0xB0` reads on tested post-cutoff drives

**Pioneer firmware checksum algorithm (from IDA Pro analysis of official updater):**
```c
uint32_t checksum = 0;
for (uint32_t offset = 0x10000; offset < filesize; offset += 4) {
    checksum -= *(uint32_t*)(firmware + offset);
}
// Stored at firmware[0x8000]
// Date patch at 0x130 is OUTSIDE checksum range — safe to patch!
```

**KernelFront cipher (reverse engineered by MattJackson):**

Pioneer kernel files use a per-dword XOR/rotate cipher over the payload body. The key table and encrypted payload are both embedded in the file:

```
file[0x000:0x200]    — 512-byte ASCII envelope header
file[0x200:0x1200]   — 1024 × LE DWORD key table
file[0x1200:0x11200] — 65536-byte encrypted payload (16384 dwords)
```

Decryption per dword at index `i`:
```c
DWORD key = keytable[i % 1024];
DWORD plaintext = ROR32(ciphertext ^ key, key & 31);
```

The decoded payload contains:
- **Generation marker** at **decoded byte offset `0xFE`**, not DWORD index `0xFE`. The verified 1.04 patch changes `plain[0xFE]` from `0xFF` to `0x01`.
- **Body checksum compensator** at decoded byte offset `0x1020` (DWORD index `0x408`); the additive sum of all 16,384 BE32 words in the 64 KiB decoded body must be `0x00000000`.

For the verified BDR-XD07U 1.04 patch, DriveKit changes the checksum word from `0xB367511D` to `0xB3684F1D` and re-encrypts the body. **Use the verified `crossflash --patch` path for flashing.** Any standalone `decryptkernel --patch` output must be checked for the correct byte offset and re-encrypted kernel format before use.

### KernelFront patch validation

The successful BDR-XD07U 1.04 downgrade produced:

```text
plain[0xFE]        = 01
BE32(plain+0x1020) = B3684F1D
BE32 body sum      = 00000000
Encrypted kernel   = 0x11200 bytes
SHA-256            = 4d1fa7cbae04b7db36689f4539d45ff8e01c72a7c8341e762224f2a76a670b9a
```

The encrypted kernel SHA-256 matched the complete kernel reconstructed from Heisenberg's successful downgrade USB capture, **byte for byte**. A zero checksum alone is insufficient to validate the marker location: a compensating checksum can also make an incorrectly patched body sum to zero. The hash above applies only to this specific patched 1.04 kernel, not to other firmware versions.

---

## Flash Protocol

**Scope of the capture-backed procedures below:** the cross-era examples are from BDR-XD07U / SAT 8D31 / ID05. They are not universal Pioneer protocols. `WRITE BUFFER` offsets are protocol buffer offsets, not proven physical NAND addresses.

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

### Crossflash: New layout sequence — post-cutoff target firmware (PRE→POST upgrade or POST→POST same-era):
```
1. WRITE BUFFER mode=0x04 bufID=0xFF len=0x100   ← unlock trigger
   payload[0x00-0x0F] = internal model string (auto-detected from 0xA0/g_mdl_map)
   payload[0x10-0x13] = selected key for this drive/protocol (verify on wire)

2. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware prefix
   First 0x1D6600 bytes in 0x8000-byte chunks

3. WRITE BUFFER mode=0x07 bufID=0xFE             ← kernel, flat binary 4 transfers:
   off=0x000000  file[0x000000:0x000200]  len=0x0200   ← header (plain ASCII, sent as-is)
   off=0x001200  file[0x000200:0x008200]  len=0x8000   ← body1
   off=0x009200  file[0x008200:0x010200]  len=0x8000   ← body2
   off=0x011200  file[0x010200:0x011200]  len=0x1000   ← tail

4. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, full pass
   Full file (0x1E6600 bytes) in 0x8000-byte chunks

5. WRITE BUFFER mode=0x05 bufID=0xFF len=0x100   ← commit trigger (immediate, ~100ms after step 4)
   key = SAT 8D31 / ID05 key 0xFF8A27B1 (wire bytes B1 27 8A FF)
   Drive reflashes internally after GOOD — wait 13s before reconnecting
```
**Confirmed:** PRE→POST (1.04→1.06) from Heisenberg's capture and DriveKit; POST→POST (1.06→1.05) DriveKit verified November 2026.

### Crossflash: Downgrade sequence — post-cutoff drive → pre-cutoff firmware (DriveKit verified):
```
1. WRITE BUFFER mode=0x04 bufID=0xFF len=0x100   ← unlock trigger
   payload[0x00-0x0F] = internal model string
   payload[0x10-0x13] = SAT 8D31 / ID05 key B1 27 8A FF in the verified downgrade

2. WRITE BUFFER mode=0x07 bufID=0xFE             ← kernel, flat 3 chunks:
   off=0x000000  file[0x00000:0x08000]  len=0x8000
   off=0x008000  file[0x08000:0x10000]  len=0x8000
   off=0x010000  file[0x10000:0x11200]  len=0x1200

3. WRITE BUFFER mode=0x07 bufID=0xF0             ← normal firmware, single pass
   Full file in 0x8000-byte chunks

4. WRITE BUFFER mode=0x05 bufID=0xFF len=0x100   ← commit trigger (immediate, ~100ms after step 3)
   key = target firmware's kernel ID key (drive-specific)
   Drive reflashes internally after GOOD — wait 13s before reconnecting
```

**Commit timing:** In the successful Heisenberg upgrade capture, commit followed the last Normal transfer by about **62.5 ms**; the next captured device command occurred about **12.61 s after commit**. The successful DriveKit downgrade also committed immediately after the single Normal pass. The ~13-second validation/reflash interval is **after** commit, not a required sleep before it. Earlier `04/4C/02` failures were observed with different staging sequences; those captures do not isolate pre-commit delay as the sole cause.

**Kernel file layout (0x11200 bytes total) — flat binary format (post-cutoff kernel):**
```
file[0x000000:0x000200]  = 512-byte ASCII envelope header      → WRITE BUFFER off=0x000000 len=0x0200
file[0x000200:0x008200]  = 32KB encrypted payload body1        → WRITE BUFFER off=0x001200 len=0x8000
file[0x008200:0x010200]  = 32KB encrypted payload body2        → WRITE BUFFER off=0x009200 len=0x8000
file[0x010200:0x011200]  = 4KB tail                            → WRITE BUFFER off=0x011200 len=0x1000
```
Note: WRITE BUFFER offsets ≠ file offsets; they are not proven physical NAND addresses. The tail is 0x1000 bytes, not 0x1200. File regions confirmed by SHA-256 comparison against Heisenberg's ID05 USB capture.

**Header handling (tested SAT 8D31 / ID05):** Heisenberg's upgrade capture used a different first 0x200-byte payload from the ASCII header in the source Kernel file. DriveKit successfully upgraded 1.04 → 1.06 by sending the original ASCII header unchanged. Therefore the exact first-transfer bytes from that capture are not necessary for this tested path; acceptance of arbitrary header data or behavior on other platforms has not been established. An earlier attempt zero-filled the final 0x1000-byte tail and failed with CHECK CONDITION; copying the actual `file[0x10200:0x11200]` tail succeeded.

**Normal firmware file format (upgrade, post-cutoff target):**
```
[0x000000 - 0x1D65FF]  = NAND image prefix (sent first in upgrade)
[0x1D6600 - 0x1E65FF]  = continuation / ECC region
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

**Pre→Post upgrade crossflash (November 2026, DriveKit verified):**
- Drive: BDR-XD07U (SAT 8D31 ID05), firmware 1.04 (pre-cutoff)
- Confirmed: **1.04 → 1.06** using `drivekit crossflash E --file xd07_kernel_106_bin --file2 xd07_normal_106.bin` (no `--patch`)
- Protocol: new layout — normal prefix `0x1D6600` → flat 4-xfer kernel → full normal `0x1E6600` → immediate commit
- Kernel file layout confirmed by SHA-256 comparison against Heisenberg's ID05 USB capture (body1, body2, tail all matched)
- Unlock/commit key: `0xFF8A27B1` (`B1 27 8A FF` on wire)
- Commit returned **GOOD**; subsequent `drivekit info E` and INQUIRY reported **firmware 1.06**, date `24/10/09`.
- Protocol first captured from Heisenberg's bdrflashpp2 capture; independently reproduced by DriveKit.

**Post→Post same-era crossflash (November 2026, DriveKit verified):**
- Drive: BDR-XD07U (SAT 8D31 ID05), firmware 1.06 (post-cutoff)
- Confirmed: **1.06 → 1.05** using `drivekit crossflash E --file xd07u_kernel_1.05.bin --file2 xd07u_normal_1.05.bin`
- Protocol: new layout — same 4-xfer kernel sequence as upgrade path (`target_is_postcut=1`)
- Commit returned **GOOD**; subsequent INQUIRY reported **firmware 1.05**, date `23/01/06`.

**Post→Pre downgrade crossflash (November 2026, DriveKit verified):**
- Drive: BDR-XD07U (SAT 8D31 ID05), post-cutoff firmware
- Confirmed: **downgrade to 1.04** using `drivekit crossflash E --file S8D31050.104 --file2 S8D31051.104 --patch`
- Patched kernel: 0x11200 bytes, SHA-256 identical to Heisenberg's successful downgrade capture
- Protocol: flat three-chunk kernel → one full Normal pass → immediate commit
- Unlock/commit key: `0xFF8A27B1` (`B1 27 8A FF` on wire)
- Commit returned **GOOD**; subsequent `drivekit info` and INQUIRY independently reported **firmware 1.04**, date `22/05/31`.


---

## Drive Identification and Unlock Keys

DriveKit maintains internal lookup tables for Pioneer drive IDs, platform and kernel identifiers, internal model strings, unlock keys, and firmware execution trigger keys. These tables are considerably larger than a short README excerpt and are maintained in the **DriveKit source code**, which is the authoritative reference.

For supported drive/protocol combinations, DriveKit automatically selects the model string and the appropriate unlock or execution-trigger key. Key selection is **drive- and protocol-dependent**; unlock and commit keys are not necessarily interchangeable. The `--key` override is intended for advanced research and testing, not routine flashing.

For the verified BDR-XD07U **SAT 8D31 / ID05** crossflash procedure, both unlock and commit used the LE DWORD `0xFF8A27B1`, transmitted as `B1 27 8A FF`. Offline `scankey` analysis of decoded XD07 Normal 1.06 independently recovered this same key at offset `0x3BFEC`. This is a verified example, **not** a universal Pioneer key.

The key table should be treated as a cross-check rather than the sole source of truth when a decoded Normal image is available. `scankey` reports mismatches instead of silently replacing table values; the extracted key still needs hardware/capture validation for a new model or protocol.

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
gcc drivekit.c -o drivekit -Wall -Wextra
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
| `--file2 name` | Secondary input or output file (command-dependent) |
| `--file3 name` | Third filename (reserved / legacy second normal firmware pass) |
| `--force` | Skip compatibility checks and interactive prompts |
| `--nounlock` | Skip unlock step |
| `--key 0x6123789A` | Override unlock key |
| `--bufid 0xF4` | Buffer ID for rawdump |
| `--patch` | Apply generation marker patch (`decryptkernel`) |

### Commands

| Command | Description |
|---|---|
| `info` / `inquiry` | Full drive information with serial decode |
| **`flash`** | **Firmware flash — recommended (was `crossflash`)** |
| `crossflash` | Alias for `flash` (kept for compatibility) |
| `flash_legacy` | Legacy auto-detect wrapper (old `flash` command) |
| `flashfw` | Legacy flash command (pre/post-cutoff, complex sweep logic) |
| `unlock` | Service mode unlock |
| `e5test` | Test Engineering Mode flag |
| `kernellimbo` | Enter kernel limbo mode |
| `probevendor` | Probe vendor commands 0xC0-0xFF |
| `rawdump` | Raw READ BUFFER dump |
| `checkcompat` | Check crossflash compatibility |
| `sendcdb` | Send raw SCSI CDB |
| `resetnormal` | Attempt to exit kernel/service mode |
| `hwdump` | Dump H8S/2600 kernel from RAM via `0xB0` — works on both pre and post-cutoff |
| `xordiff` | XOR two encrypted firmware files to find version bytes |
| `patchfw` | Patch firmware ASCII header to spoof version |
| `decryptkernel` | Decode KernelFront XOR/rotate cipher on a Pioneer H8S kernel file; outputs raw plaintext body for IDA analysis. `--patch` additionally flips the generation marker (`0xFF→0x01`) and recomputes the body checksum |
| `decodenormal` | Decrypt normal firmware envelope; reports UHD capability |
| **`scankey`** | **Scan a decoded Normal firmware body for its update-entry unlock key; cross-check the internal key table** |

### scankey command

Extract the **update-entry unlock key** from a *decoded* Pioneer Normal firmware body. No optical drive is required and no firmware is written. Decode the Normal firmware first with `decodenormal` if necessary.

```powershell
.\drivekit scankey --file xd07_normal_106.bin_decoded.bin
.\drivekit scankey --file S8800601.153_decoded.bin
```

**XD07 Normal 1.06 — recovered key agrees with the known working ID05 key:**

```text
Keyed handler matches        : 1
Acceptance signature offset  : 0x3BFD6
Key comparison offset        : 0x3BFEA
Key bytes offset             : 0x3BFEC
Reject branch variant        : 10-byte
Unlock key (wire order)      : B1 27 8A FF
Unlock key (LE DWORD)        : 0xFF8A27B1
Cross-check: matches key-table entry  : OK
```

**`S8800601.153` — discrepancy detected:**

```text
scankey: S8800601.153_decoded.bin  (1858816 bytes = 0x1C5D00)

Keyed handler matches        : 1
Acceptance signature offset  : 0x3BBD4
Key comparison offset        : 0x3BBE4
Key bytes offset             : 0x3BBE6
Reject branch variant        : 10-byte
Unlock key (wire order)      : 94 E0 F2 5C
Unlock key (LE DWORD)        : 0x5CF2E094

WARNING: extracted key 0x5CF2E094 differs from key-table entry 0x6123789A
         Verify against a known-good capture before flashing.
```

The scanner identifies a recognizable **keyed update-entry handler** in the decoded firmware, not an arbitrary four-byte match. The extracted key is distinct from the cipher key used to decode Normal firmware. A single unambiguous match is strong static evidence of the embedded comparison value, but does not establish that the target drive accepts a particular unlock/commit payload. **Do not automatically flash using a newly extracted key without checking the descriptor, protocol, and known-good captures.** A missing key-table entry is different from a mismatch.

### flash command (recommended)

```
drivekit flash E --file kernel.bin --file2 normal.bin
```

Uses drive identification, `READ BUFFER 0xB0` behavior, and target firmware date to select a crossflash sequence (subject to firmware/platform compatibility checks):
- **Post-cutoff target firmware** (`target_is_postcut=1`) → new layout (normal prefix → flat 4-xfer kernel → full normal → commit). Covers PRE→POST upgrade and POST→POST same-era flash.
- **Pre-cutoff target firmware** (`target_is_postcut=0`) → downgrade layout (flat 3-chunk kernel → normal → commit). Covers POST→PRE downgrade.

Model string auto-detected from `READ BUFFER 0xA0` / `g_mdl_map` table.
Unlock/commit keys are selected for the detected drive and protocol. For the verified SAT 8D31 / ID05 downgrade, the on-wire key is `B1 27 8A FF` (`0xFF8A27B1` as a LE DWORD).

### flash_legacy command

```
drivekit flash_legacy E --file kernel.bin --file2 normal.bin
```

Older auto-detect wrapper. Use `flash` instead.

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

### decryptkernel command

```
drivekit decryptkernel --file S9331050.100
drivekit decryptkernel --file S9331050.100 --patch --file2 S9331050_decoded_patched.bin
```

Decodes the KernelFront XOR/rotate cipher and outputs a flat binary suitable for loading in IDA Pro as H8S/2600 code. `--patch` is intended to flip the generation marker byte (`0xFF→0x01`) and recompute the body checksum. Verify the standalone command's output format and byte offset before treating it as a flashable kernel; the verified flashing path is `crossflash --patch`. No drive needed.

### decodenormal command

Decrypts a Pioneer Normal firmware envelope and reports UHD capability.

```bash
drivekit decodenormal --file S8D31051.104
```

Optionally save the decoded firmware body:

```bash
drivekit decodenormal --file S8D31051.104 --file2 decoded_body.bin
```

- `--file` — Input Normal firmware file.
- `--file2` — Optional output filename for the decoded body.
- No drive required.

---

## KernelFront Cipher

Pioneer kernel files (e.g. `S9331050.100`) use a XOR/rotate cipher over the H8S/2600 payload (reverse engineered by MattJackson):

```
file[0x000:0x200]    — 512-byte ASCII envelope header
file[0x200:0x1200]   — 1024 × LE DWORD key table
file[0x1200:0x11200] — 65536-byte encrypted payload (16384 dwords)

decode(ciphertext, key) = ROR32(ciphertext ^ key, key & 31)
```

Key index wraps: `key = keytable[i % 1024]`

Use `decryptkernel` to produce a flat binary suitable for loading in IDA Pro as H8S/2600 code.

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
| `0x41` | H8S/2600 kernel dump enable — zero-length WRITE BUFFER (12-byte CDB). Pre-cutoff: offset `0x00AAAA`. Post-cutoff: offset `0xA5AAAA`. Drive requires power cycle between attempts |
| `0x92` | Drive config + factory calibration |
| `0xA0` | Model string + unlock key (post-cutoff) / capability data (pre-cutoff) |
| `0xB0` | H8S/2600 kernel code running in RAM — decrypted, ready for disassembly. After `hwdump`: read from offset `0x100000` in `0x800` chunks up to absolute limit `0x880800`. Pre-cutoff: 8.7MB dump. Post-cutoff: 7.5MB dump |
| `0xF1` | Drive identity: serial, platform, kernel ID, firmware version |
| `0xF4` | NAND flash contents — readable without unlock on post-cutoff drives. MakeMKV reads in sequential `0xA4` chunks |
| `0xFE` | Kernel/token write target (crossflash protocol) |
| `0xF0` | Normal firmware write target (both protocols) |
| `0xFF` | Execution trigger (commit flash to NAND) |
| `0xE5` | Engineering Mode flag setter |

---

## Pending Research

- **Audit unlock-key table entries with `scankey`:** investigate the `S8800601.153` mismatch (`0x5CF2E094` extracted vs `0x6123789A` in the table); validate new keys against captures/hardware and check for accidental use of the fixed acceptance-signature immediate.
- **Generalize the verified post→pre downgrade** beyond the tested BDR-XD07U SAT 8D31 / ID05 and 1.04 kernel; validate marker/checksum locations and transfer behavior for other kernel families before claiming support.
- **Standalone `decryptkernel --patch` verification:** ensure it patches decoded **byte** offset `0xFE`, not DWORD index `0xFE`; distinguish decoded 64 KiB output from the encrypted `0x11200`-byte flashable kernel.
- **H8S/2600 version-check analysis:** continue studying pre/post-cutoff `hwdump` captures to understand the underlying validation logic rather than relying only on observed protocol behavior.
- **UHD capability detection** — current scan of decrypted kernel body unreliable for some drives
  - Do not infer verified UHD playback from the model suffix or a detected firmware signature alone; confirm with an actual UHD disc read
  - Looking for distinguishing byte pattern in normal firmware binary that indicates UHD support
  - Goal: reliable auto-detection without manual override required
- **XD06U post-cutoff downgrade** — same encrypted binary barrier
- **BDR-L13SH** (`REC 8C00 ID92`) — unknown drive family, awaiting `0xB0` dump

---

## H8S/2600 Hardware Dump (`hwdump`)

**Confirmed working — September 17, 2026**

Discovered from Wireshark capture analysis of MakeMKV session on post-cutoff BDR-XD08U.

### The command

```
WRITE BUFFER — 12-byte CDB:
3B 02 41 A5 AA AA 00 00 00 00 00 00

opcode = 0x3B  (WRITE BUFFER)
mode   = 0x02
bufID  = 0x41
offset = 0x00AAAA  ← pre-cutoff offset (not data!)
offset = 0xA5AAAA  ← post-cutoff offset (not data!)
length = 0x000000  ← zero length write
```

**Critical discovery:** `A5 AA AA` is the BUFFER OFFSET in the CDB, NOT the payload data. Zero-length write to a specific offset acts as the unlock trigger.

### Full sequence (must execute back to back, ~5ms window):

**Post-cutoff:**
```
1. GET EVENT STATUS x4 (masks: 0x5A, 0x58, 0x50, 0x40)
2. WRITE BUFFER 12-byte CDB: 3B 02 41 A5 AA AA 00 00 00 00 00 00  (offset 0xA5AAAA)
3. READ BUFFER  10-byte CDB: 3C 02 F4 83 94 B4 00 00 08 00  (F4 trigger read)
4. READ BUFFER  10-byte CDB: 3C 02 B0 50 00 00 00 00 08 00  (H8S/2600 from 0x500000)
   → Keep reading sequential 0x800 chunks until 0x880800
```

**Pre-cutoff:**
```
1. GET EVENT STATUS x4 (masks: 0x5A, 0x58, 0x50, 0x40)
2. WRITE BUFFER 12-byte CDB: 3B 02 41 00 AA AA 00 00 00 00 00 00  (offset 0x00AAAA)
3. READ BUFFER  10-byte CDB: 3C 02 F4 83 94 B4 00 00 08 00  (F4 trigger read)
4. READ BUFFER  10-byte CDB: 3C 02 B0 10 00 00 00 00 08 00  (H8S/2600 from 0x100000)
   → Keep reading sequential 0x800 chunks until 0x880800
```

**Note:** Drive requires full power cycle between `hwdump` attempts.
DriveKit auto-detects pre/post-cutoff via INQUIRY date and uses the correct sequence.

### Result

After this sequence, `READ BUFFER 0xB0` returns decrypted H8S/2600 assembly code from the running kernel:
- **Post-cutoff**: 7.5MB (`0x780800` bytes) — reads from `0x500000`, stops at `0x880800`
- **Pre-cutoff**: 8.7MB — reads from `0x100000`, stops at `0x880800`

Chunk size: `0x800` bytes (2KB). Drive requires **power cycle** between `hwdump` attempts.

This dump has been sent to MrPenguin for H8S/2600 disassembly analysis to find the version check that blocks pre-cutoff downgrade.

### DriveKit command

```
drivekit hwdump E
```

Automatically executes the full sequence and dumps `hwdump_b0.bin`.

---

## Firmware Date

Firmware date is available in the standard INQUIRY response at byte offset `0x25`:

```
INQUIRY[0x08-0x0F] = vendor   "PIONEER "
INQUIRY[0x10-0x1F] = model    "BD-RW  BDR-XD08U"
INQUIRY[0x20-0x23] = version  "1.02"
INQUIRY[0x24]      = space
INQUIRY[0x25-0x2C] = date     "22/12/27"
```

Confirmed by MrPenguin: `sg_raw -b -r 16384 /dev/sg2 12 00 00 00 60 00 00`

DriveKit displays this as `FW Date` in drive information.

---

## AACS Version

Available from GET CONFIGURATION feature `0x010D` at response byte `[0x0C]`:

```
CDB: 46 00 01 0C 00 00 00 00 1C 00
Response[0x0C] = AACS version (e.g. 0x1B = version 27)
```

DriveKit displays this as `AACS ver` in drive information.


## Credits

**Heisenberg** — Wireshark/USBPcap captures including the SAT 8D31 / ID05 1.04 → 1.06 upgrade used to verify the four-transfer Kernel layout and nonzero tail; capture analysis for SAT 9331; trigger key extraction from Pioneer updater EXEs; development support and testing throughout. Huge thanks — this tool would not exist without you.

**MattJackson (Matthew Jackson)** — The main coder behind the decryption algorithms and the content-derived update-entry handler/key recognition approach used by `scankey`. Decrypted the kernel file and identified the patch locations required for a successful downgrade below version lock. Shared his code openly and has been invaluable in helping everyone with problems. ([GitHub](https://github.com/MattJackson)) ([cdrinfo.pl profile](https://forum.cdrinfo.pl/members/112645.html))

**MrPenguin** — H8S/2600 deep firmware analysis, rolling XOR cipher reverse engineering, BDR-S12U pypcode/Ghidra analysis, unlock key endianness clarification, `0xB0` READ BUFFER disassembly, and ongoing technical guidance invaluable throughout this project.

**greg1wto** — provided the tools we needed to perform Wireshark/USBPcap capture analysis, which combined with Pioneer updater reverse engineering made the NAND write protocol analysis possible.

Thank you for the inspiration and help from cxplay, Sayaka, Coopervid, blackened2687, MakeMKV Forum and cdrinfo.pl

**Special thanks (flash tool community):**
Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen, ala42, czary2mary, jadburner, cvs, alexx12345, seku, Leman39, wujooj, jurireal, alphaville0527, SnowFox, Kirby, haysey70, Majestic12, elflorek, floppydumper, redwine, cryptojoe3737, TeddyRaspin, asmcom, payalnik23, aliter404

**Tools:** Wireshark + USBPcap, IDA Pro + hrtng plugin, x64dbg, pypcode, Visual Studio 2022, WSL, GCC

Research and educational purposes only.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*

```
          /\
         /__\
        /\  /\
       /__\/__\
   RAZOR 1911 — SINCE 1985
   Still making hardware do things it wasn't supposed to do.
```
