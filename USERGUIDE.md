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

### Downgrade with UHD patch (POST→PRE, keeps UHD capability)

```
drivekit flash E --file S8D31050.104 --file2 S8D31051.104 --patch
```

Use `--patch` when downgrading a UHD-capable drive to pre-cutoff firmware. Without it, the drive will lose UHD playback capability after the downgrade. The patch flips a single generation marker byte in the kernel and recomputes the body checksum before sending.

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

## UHD Playback and the Generation Marker

Pioneer post-cutoff firmware (after 2022-12-27) disables UHD playback on drives that previously supported it. The generation marker at byte `0xFE` in the decrypted kernel body controls this:

- `0xFF` = old/pre-cutoff generation, UHD disabled
- `0x01` = new/post-cutoff generation, UHD enabled on supported hardware

When downgrading a UHD-capable drive to pre-cutoff firmware, use `--patch` to flip this byte from `0xFF` to `0x01` and re-encrypt the kernel before flashing. DriveKit also recomputes the body checksum automatically so the patched kernel passes the drive's integrity check.

`--patch` has no effect on drives that don't have UHD hardware capability (e.g. BDR-XD07, which is not a UHD drive).

---

## Pre-cutoff firmware versions with UHD capability

| Drive | Last safe pre-cutoff version | Date |
|-------|----------------------------|------|
| BDR-XD08U | 1.01 | 2022-10-11 |
| BDR-XD07U | 1.04 | 2022-05-31 |
| BDR-XD06U | 1.11 | — |

These are the last firmware versions before Pioneer's post-cutoff update. Downgrading to one of these (with `--patch`) restores UHD playback on supported hardware.
