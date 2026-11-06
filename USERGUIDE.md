# DriveKit User Guide

Practical guide to flashing Pioneer BD-R/BD-RE drive firmware with DriveKit.

> ⚠️ **Read the [Risk section in README.md](README.md#️-risk) before proceeding.** This tool writes directly to drive firmware. Flashing the wrong drive or using incompatible firmware can brick the drive.

---

## Step 1 — Find your drive

```
drivekit info E
```

Replace `E` with the drive letter Windows assigned. On Linux use `/dev/sgX` (e.g. `/dev/sg1`). Check Device Manager (Windows) or `lsscsi` (Linux) if unsure which letter/device to use.

Example output:
```
  Drive     : \\.\e:
  Vendor    : PIONEER
  Model     : BD-RW   BDR-XD07U
  Firmware  : 1.04
  FW Date   : 22/05/31
  Platform  : SAT 8D31ID05
  Kernel    : ID05
```

Note the **Platform** and **Kernel** fields — you'll need these to pick the right firmware files.

> **Always verify the correct drive letter before running any flash command. Flashing the wrong drive is not recoverable.**

---

## Step 2 — Get the firmware files

Pioneer firmware packages contain two files:

| File | Role | Typical size |
|------|------|-------------|
| **Kernel** | Boot/controller code | ~70 KB |
| **Normal** | Main firmware body | ~1.8 MB |

**Filename convention:** `S<platform><type><version>`

Example: `S8D31050.104`
- `S8D31` = platform SAT 8D31
- `0` = file series prefix
- `50` = Kernel (`50`), Normal (`51`)
- `104` = firmware version 1.04

So for version 1.04 on a SAT 8D31 drive:
- Kernel → `S8D31050.104`
- Normal → `S8D31051.104`

**The kernel file must match your drive's Kernel ID.** Check the kernel header — it lists `Kernel Version : ID35` (or similar). This must match what `drivekit info` shows for your drive. A mismatch causes a silent failure where the drive stays in kernel mode showing firmware `0000`.

Firmware files are not distributed with DriveKit — source them from Pioneer's official updater packages or community firmware archives.

---

## Step 3 — Flash

### Standard flash (upgrade or same-era)

```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104
```

DriveKit auto-detects both the drive era and the firmware era, then selects the correct protocol. You will be asked to confirm before anything is written. **Eject any disc before flashing.**

### Downgrade from post-cutoff to pre-cutoff firmware

```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104 --patch
```

Use `--patch` when flashing pre-cutoff firmware onto a post-cutoff drive. Without it, the drive will reject the kernel. The patch flips the generation marker byte in the kernel so the drive accepts it, and recomputes the body checksum before sending.

### Recovery flash — drive stuck in kernel mode (firmware shows `0000`)

```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104 --nounlock
```

Use `--nounlock` when the drive is already in kernel/service mode from a previous failed flash or interrupted unlock. DriveKit skips the unlock step and flashes directly. The kernel file must match the kernel ID currently running in the drive.

---

## Step 4 — Wait

After the commit trigger is sent and the drive responds GOOD, **do not touch the drive for at least 20 seconds.** The drive is performing its internal reflash — this happens after the SCSI command returns, not during it. Interrupting power at this point can brick the drive.

When the drive LED stops blinking, power-cycle the drive (unplug and replug USB, or reboot for internal SATA drives), then confirm the result:

```
drivekit info E
```

Check that `Firmware` and `FW Date` show the expected new version.

---

## Protocol Auto-Detection

DriveKit selects the flash protocol automatically based on the drive era and the target firmware era:

| Drive era | Target firmware era | Protocol used |
|-----------|-------------------|---------------|
| PRE-cutoff | PRE-cutoff | Single-pass (kernel + normal) |
| PRE-cutoff | POST-cutoff | 4-transfer upgrade layout |
| POST-cutoff | PRE-cutoff | 3-chunk flat kernel + downgrade layout |
| POST-cutoff | POST-cutoff | 4-transfer upgrade layout |

**Drive era** is detected by probing `READ BUFFER 0xB0` — pre-cutoff drives respond with data, post-cutoff drives return an error.

**Firmware era** is detected by decrypting the first 12 DWORDs of the Normal firmware body and checking byte `[0x28]` — `0x01` = post-cutoff (new layout), `0xFF` = pre-cutoff (old layout). This is more reliable than the date string in the firmware header.

The cutoff date is **2022-12-27**.

---

## Troubleshooting

### Drive shows firmware `0000` / stuck in kernel mode

The drive entered kernel/service mode and didn't return after a previous operation. Use `--nounlock` to flash directly:

```
drivekit flash E --file kernel.bin --file2 normal.bin --nounlock
```

Make sure the kernel file's `Kernel Version` field matches what `drivekit info` shows as the running kernel ID. A mismatch causes a silent failure — the drive accepts the protocol but its internal flash validator rejects the write, and the drive stays in `0000`.

### Flash completes but firmware version didn't change

The commit trigger returned GOOD but the drive's internal flash rejected the write. Common causes:

- **Wrong kernel ID** — the kernel file's `Kernel Version` doesn't match the drive's running kernel. Check both with `drivekit info` and by inspecting the kernel file header (`drivekit decryptkernel` shows the header fields).
- **`--nounlock` used but drive era unknown** — without the `READ BUFFER 0xB0` probe, DriveKit falls back to inferring the drive era from the firmware date. If that inference is wrong, the wrong protocol is selected. Try the flash without `--nounlock` if the drive can be unlocked first.
- **Power interrupted during reflash** — the drive performs its internal reflash after the commit GOOD, not before. If power was cut during the ~20 second window, the flash may be incomplete.

### `04/4C/02` error (HARDWARE ERROR / LOGICAL UNIT FAILED SELF-CONFIGURATION)

The drive rejected the commit. Usually means the wrong flash protocol was used. If you used `flashfw` instead of `flash`, switch to `flash` — `flashfw` does not implement the 4-transfer new layout required for post-cutoff firmware.

### PRE→PRE cross-family warning

If the drive platform (e.g. `SAT 8D31`) differs from the target firmware's platform (e.g. `SAT 8D30`), and both are pre-cutoff, DriveKit prints a warning but still proceeds. This path has been tested and confirmed working in practice, but if the drive ends up stuck in kernel mode after the commit, power-cycle and retry using a firmware file that matches the drive's exact platform.

### Drive not detected / access denied (Windows)

Run DriveKit as **Administrator**. Right-click Command Prompt → Run as administrator.

### Drive not detected (Linux)

Run with `sudo`, or add your user to the `disk` group:
```
sudo drivekit info /dev/sg1
```

---

## The Generation Marker and `--patch`

Pioneer kernel files contain a generation marker byte at `0xFE` in the decrypted kernel body:

- `0xFF` = pre-cutoff generation
- `0x01` = post-cutoff generation

When flashing pre-cutoff firmware onto a post-cutoff drive, the drive checks this marker and will reject a kernel where it doesn't match expectations. `--patch` flips this byte from `0xFF` to `0x01` and re-encrypts the kernel before sending, allowing the drive to accept the pre-cutoff firmware. DriveKit also recomputes the body checksum automatically.

---

## Last pre-cutoff firmware versions

| Drive | Last pre-cutoff version | Date |
|-------|------------------------|------|
| BDR-XD08U | 1.01 | 2022-10-11 |
| BDR-XD07U | 1.04 | 2022-05-31 |
| BDR-XD06U | 1.11 | — |

---

## Live Firmware Extraction — `b0probe` / `b0scankey` / `b0dumpfw`

These three commands read firmware directly from the running drive via `READ BUFFER 0xB0`. No firmware file is needed. They work on both pre-cutoff and post-cutoff drives — the correct enable sequence (`0x00AAAA` or `0xA5AAAA`) is auto-detected from the INQUIRY date.

> **Note:** The drive requires a full power cycle between repeated `0xB0` enable attempts. If a command fails with a SCSI error on the second run, unplug and replug the drive first.

---

### `b0probe` — quick access check

```
drivekit b0probe E
```

Runs the enable sequence and reads the first chunk to confirm whether `0xB0` is accessible. Fast (~2 seconds). Use this first if you're not sure the drive will respond, or after a power cycle to confirm the drive is ready.

Expected output on success:
```
Generation: POST-CUTOFF (offset 0xA5AAAA, 0xB0 from 0x100000)
WRITE BUFFER 0x41 offset=0xA5AAAA: GOOD
0xB0 ACCESSIBLE!
Base[0..7]: 7A 07 00 00 04 00 07 80
```

---

### `b0scankey` — live unlock key extraction

```
drivekit b0scankey E
```

Streams `0xB0` from live address `0x100000` through the Normal firmware region, then scans the Normal body for the update-entry unlock key — the same algorithm as the offline `scankey` command, but reading straight from the drive.

The result box identifies the drive fully from live data alone:

```
  +--------------------------------------------------+
  |  B0SCANKEY — LIVE FIRMWARE IDENTIFICATION        |
  +--------------------------------------------------+
  Physical drive                : BDR-XD07U
  Internal model identifier     : PIONEER BDR-BDS7
  Internal model source         : Normal +0x000000
  Platform                      : SAT 8D31
  Kernel ID                     : ID05
  Firmware revision             : 1.06

  Keyed handler matches         : 1
  Key bytes offset in Normal    : 0x3BFEC
  Reject branch variant         : 10-byte
  Unlock key (wire order)       : B1 27 8A FF
  Unlock key (LE DWORD)         : 0xFF8A27B1

  Cross-check                   : MISMATCH
  Key-table value               : 0x6123789A
```

**What to look for:**

- **Physical drive** — model from INQUIRY (last word, e.g. `BDR-XD07U`).
- **Internal model identifier** — first 16 bytes of the decrypted Normal body. This is the string used in bytes `0x00–0x0F` of the unlock/commit trigger payload. `PIONEER BDR-BDS7` is an internal protocol identifier shared by multiple physical models — not a separate drive.
- **Platform / Kernel ID** — from `READ BUFFER 0xF1`. Useful for identifying an unknown drive.
- **Unlock key** — the key embedded in the firmware's update-entry handler. This is a firmware-derived candidate; a **Cross-check: MISMATCH** means it differs from the internal key table. The table may be outdated or the drive may use a drive-specific key. Verify against a known-good capture before flashing on a new model.
- **Cross-check: OK** — key matches the internal table. High confidence.

Takes ~30 seconds. Saves a raw dump to `b0scankey_dump.bin`.

---

### `b0dumpfw` — live firmware file extraction

```
drivekit b0dumpfw E
```

Streams `0xB0` from live address `0x100000` through the full Normal firmware region, then carves out the Kernel (64 KiB) and Normal (~1.8 MB) at their confirmed offsets and writes named output files:

```
pioneer_BDR-XD07U_ID05_8D31_1.06_kernel.bin    64 KiB
pioneer_BDR-XD07U_ID05_8D31_1.06_normal.bin    ~1.8 MB
pioneer_BDR-XD07U_ID05_8D31_1.06_raw.bin       ~5 MB  (full sequential dump)
pioneer_BDR-XD07U_ID05_8D31_1.06_info.txt      sidecar: identity, file sizes
```

The filename is built from live drive data — model, kernel ID, platform, and firmware revision — so each dump is self-labelled.

Takes ~90 seconds. The Normal output (`_normal.bin`) can be fed directly to `scankey` without running `decodenormal` first, since the `0xB0` stream is already decrypted.

> ⚠️ **These are research images, not flash packages.** The extracted Kernel and Normal are decrypted, in-memory bodies. They are **not** the encrypted KernelFront/Normal update envelopes the flashing protocol expects. Do not pass them to `flash`/`crossflash`.

---

### Confirmed layout (tested BDR-XD07U SAT 8D31/ID05)

| Region | Raw dump offset | Live B0 address | Size |
|--------|----------------|-----------------|------|
| Kernel | `0x300000` | `0x400000` | 64 KiB (`0x010000`) |
| Normal | `0x310000` | `0x410000` | ~1.8 MB (`0x1C9E00`) |

The sequential capture starts at live B0 `0x100000` = raw dump offset `0x000000`. These offsets are confirmed on the tested SAT 8D31/ID05 hardware; other Pioneer families have not yet been verified.
