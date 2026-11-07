# DriveKit — H8S/2600 Disassembly & Firmware Investigation

> **Living research record — through Stage 9.16 (2026-11-07).**  
> Scope: offline analysis of Pioneer BDR-XD07U firmware, H8S/2600 Advanced decoder, Kernel, boot region, and B0 memory captures.  
> **This is an evidence ledger, not a hardware register manual or proof of executed code.**

## 1. Purpose and maintenance rules

`README.md` remains the user-facing guide for DriveKit commands, hardware procedures, supported drives, build instructions, and safety warnings. `DISASM.md` holds the growing reverse-engineering evidence: reproducible inputs, exact byte observations, disassembler coverage, bounded CFG analysis, hypotheses, unresolved questions, and next experiments. Preserve raw stage reports alongside this file; do not replace them with prose summaries.

Every assertion must be distinguished as follows:

| Label | Meaning |
|---|---|
| **OBSERVED** | Directly checked bytes, hash, dump offset, decoded instruction encoding, or actual tool output. |
| **STATIC-PROVEN (bounded)** | A conclusion established for explicitly modeled bytes/paths and stated assumptions. |
| **CONDITIONAL** | Valid only if a separate hypothesis (such as runtime mapping) is true. |
| **INFERRED** | Plausible interpretation supported by patterns, but not demonstrated. |
| **UNKNOWN** | Not established; retain as unknown rather than silently promoting. |
| **HARDWARE-VERIFIED** | Behavior measured on the running device, with method and firmware identified. |

A candidate CFG edge is **not** an executed path. A raw opcode pattern is **not** necessarily a decoded instruction. A known MMIO address is **not** an identified peripheral. A decoded call to a Kernel address is **not** proof that the call executes on hardware. Never promote indirect call targets or reachability without the required complete path and side-effect proof.

**Project policy:** Keep the existing native C H8S decoder; Stage 9.13–9.16 are separate read-only audits. Do not push to GitHub before beta. Offline investigations do not issue firmware writes or flashing commands.

## 2. Evidence inputs and coordinate systems

### 2.1 Tested image identities

| Input | Size | SHA-256 |
|---|---:|---|
| BDR-XD07U 1.06 Kernel (decrypted, extracted) | `0x10000` (65,536 bytes) | `15b44e63383237036c2c4616d224bc14855ca1183001f92225b21f11f0c3e0eb` |
| Full B0 capture (`hwdump_b0.bin`) | `0x780800` (7,866,368 bytes) | `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603` |

**OBSERVED:** The 64 KiB Kernel matches the B0 file at offset `0x300000`. B0 contains the `AzHI2000/3` marker at offset `0x003018`. The marker is not present at B0 offset `0x103018` in the tested capture.

### 2.2 Addresses: never mix these up

For the tested BDR-XD07U sequential B0 capture, the observed layout is consistent with `live B0 address = raw file offset + 0x100000`. This is a **capture/address correspondence**, not blanket proof of the CPU's memory-controller configuration or every runtime alias.

| Raw B0 file offset | Corresponding live B0 address | Evidence / region |
|---|---|---|
| `0x000000` | `0x100000` | Beginning of sequential B0 stream |
| `0x000022` | `0x100022` | `5A 10 00 26` / `JMP @0x100026` |
| `0x000026` | `0x100026` | Boot continuation bytes |
| `0x003018` | `0x103018` | `AzHI2000/3` marker in raw B0 |
| `0x0058DC` | `0x1058DC` | Candidate external helper bytes; runtime mapping not hardware-proven |
| `0x300000` | `0x400000` | Kernel, size `0x10000`; byte-identical to extracted Kernel |
| `0x310000` | `0x410000` | Decrypted Normal firmware begins |
| `0x4D9E00` | `0x5D9E00` | Normal exclusive end in documented tested layout |

**Important negative observation:** B0 file offset `0x1058DC` contains zeroes at the inspected bytes; it must not be confused with runtime address `0x1058DC`, whose *candidate* raw offset is `0x0058DC`. The boot jump and Kernel match strongly support the capture translation, but they do not alone prove which physical memory is selected at CPU runtime.

### 2.3 Live B0 acquisition and its limitations

The existing DriveKit `README.md` documents the B0 unlock/enable and sequential extraction, including `b0probe`, `b0scankey`, `b0dumpfw`, and `hwdump`. The observed stream starts at live B0 address `0x100000`; Kernel is found at `0x400000` and Normal at `0x410000`. The read sequence uses `READ BUFFER` vendor-specific B0 behavior following an enable/trigger sequence; `hwdump` uses `0x800`-byte chunks. User experience with `b0keyscan`/`b0scankey` indicates seeking was not available in that tested workflow and reading had to start at the beginning. **Do not generalize this to all diagnostic interfaces or claim arbitrary live reads are supported.**

The eventual editor/live-memory backend is a **future research objective**. Start with an independently verified, read-only mechanism, if available; distinguish a sequential B0 stream from true random-access live CPU memory, and avoid MMIO reads with possible side effects until their behavior is understood. Do not treat decrypted in-memory Kernel/Normal bodies as directly flashable update packages.

### 2.4 README reconciliation: confirmed live acquisition details

The supplied source README is `DriveKit_README_disassembler_stage8_6(1).md` (DriveKit v1.0; Stage 8.6 disassembler milestone). It is an **older public-facing disassembler snapshot**, even though its other firmware and B0 sections contain later November 2026 results. Do not assume its "Stage 9 planned" text describes the current development state; Stages 9.0–9.16 have since been investigated offline.

**README-DOCUMENTED / HARDWARE-REPORTED (tested BDR-XD07U SAT 8D31/ID05, not all Pioneer drives):**

| Topic | README record | Interpretation / limitation |
|---|---|---|
| B0 enable | Pre-cutoff zero-length `WRITE BUFFER` buffer `0x41`, offset `0x00AAAA`; post-cutoff offset `0xA5AAAA`; preceded by GET EVENT STATUS and followed by an F4 read | This is the documented tested acquisition procedure, **not** a general-purpose arbitrary memory read API |
| B0 capture | `READ BUFFER` buffer `0xB0`, starting at live `0x100000`; `hwdump` uses `0x800`-byte chunks | Sequential stream; seeking must not be assumed |
| Extractors | `b0scankey` and `b0dumpfw` use `0x8000`-byte chunks | Reported ~30 seconds for key scan and ~90 seconds for full firmware extraction; host/drive-dependent |
| Kernel | B0 raw `0x300000` → live `0x400000`, `0x10000` bytes | Byte identity independently checked for the present B0 and Kernel input |
| Normal | B0 raw `0x310000` → live `0x410000`, documented `0x1C9E00` bytes | In-memory plaintext body begins with `PIONEER `; **not** a flashable envelope |
| Normal end | B0 raw `0x4D9E00` → live `0x5D9E00` (exclusive) | Specific documented tested layout; full B0 capture can extend farther |
| `open_drive()` | Earlier B0 command dispatch once failed to open the drive handle | Historical debugging incident; ensure a valid handle before attributing I/O failures to firmware behavior |

**Evidence separation:** the README reports successful *live* B0 extraction on tested pre-/post-cutoff hardware. The Stage 9.12–9.16 analyses operate on captured bytes and do **not** themselves validate CPU bus/MMIO execution or arbitrary live-memory access.

**Firmware image safety:** `b0dumpfw`'s `_kernel.bin` and `_normal.bin` are decoded in-memory research images. They are not encrypted KernelFront/Normal update envelopes and must not be passed directly to `flash`/`crossflash`.

**Attribution conflict to preserve:** the README's Hardware Research section calls `0xFF3FF000` a "Crypto/DMA engine" address based on MrPenguin's **BDR-S12U** work. Our Stage 9.15 confirms that the **BDR-XD07U** boot routine writes through an ER6 base of `0xFF3FF000`, but neither that address coincidence nor the offline write-value analysis independently establishes the peripheral identity or its exact functions on the XD07U. Record **"Crypto/DMA" as a cross-model attribution/hypothesis**, not a newly proven XD07U register label.

### 2.5 Source reference material and credits

The supplied README cites the *Renesas H8S/2600 Series, H8S/2000 Series Software Manual* (REJ09B0139-0400, Rev. 4.00) and the *Renesas H8S/2368 Group Hardware Manual* (REJ09B0050). It credits **Matthew Jackson / MattJackson** for the MIT-licensed H8S instruction-length reference and KernelFront work, and **MrPenguin** for H8S firmware analysis, rolling XOR and B0 investigations. Preserve original upstream copyright/license notices in any reused decoder code. The existing C decoder remains the project implementation; these references do not authorize replacing it silently.

### 2.6 Reference material caveat

Matt's BDR-UD04 SAT 8A10 firmware notes suggest OS/bring-up addresses `0x103000–0x10FFFF`, `AzHI2000/3` at reference runtime `0x103018`, Kernel `0x400000–0x40FFFF`, Normal `0x410000+`. These are **reference-model observations**, not automatic verification for the BDR-XD07U.

## 3. Decoder and reachability history

The project uses a native C H8S/2600 Advanced decoder, instruction-length handling, and a separate flow classifier. Decoder output is evidence of the implemented semantics, not a guarantee that every H8S instruction variant is fully modeled. Opaque/unknown semantics remain boundaries.

| Stage | What changed / measured | Evidence status |
|---|---|---|
| 8.6 | 1,721 candidate instructions, 5,656 code bytes; 0 reached unknown, 14 outside-image targets, 0 overlaps, 0 unresolved direct branches | Earlier Kernel coverage baseline |
| 9.0 | `--xrefs`: 274 direct edges (109 calls, 33 jumps, 132 branches); 24 indirect sites; 67 entry candidates | Candidate graph |
| 9.1 | Five adjacent constant indirect calls resolved; 19 remain unknown | Narrow local proofs |
| 9.2 | `--discover`: 85 additional candidate instructions in previously unvisited targets; no unknown/overlap | Discovery only |
| 9.3 | `--promote-indirect`: 1,806 reachable instructions, 5,946 code bytes; 2 referenced candidate bytes, 59,588 unvisited, 0 reached unknown, 14 outside-image targets, 0 overlaps, 0 invalid direct targets; 285 expanded direct edges, 69 entry candidates | Windows-verified promoted baseline |
| 9.4 | 24 indirect calls: 5 adjacent proven, 18 earlier loads with intervening changes, 1 without contiguous origin | Register audit |
| 9.5 | CFG audit: 5 adjacent, 18 blocked, 1 no origin, 0 newly proven | Conservative |
| 9.6 | Identified ER3 wrapper/helper chain and external `0x1058DC` dependency | Investigative |
| 9.7–9.12 | External helper CFG, ER3 preservation, wrapper effects, runtime-mapping hypothesis, caller-window validation | Detailed below; no new promotions |
| 9.13 | Bounded boot reconnaissance using unchanged decoder | Candidate CFG |
| 9.14 | Boot MMIO direct absolute accesses and Kernel-call sequence | Static evidence |
| 9.15 | Bounded ER6-derived MMIO effective-address resolution | Static evidence |
| 9.16 | Forward abstract provenance for values written to ER6-derived MMIO addresses | Static evidence; not execution proof |

### 3.1 Five resolved adjacent indirect calls (Stage 9.1)

| Call site | Target |
|---|---|
| `0x40012C JSR @ER3` | `0x405E02` |
| `0x4052EC JSR @ER4` | `0x405D2C` |
| `0x4052FA JSR @ER5` | `0x405D76` |
| `0x405706 JSR @ER6` | `0x405836` |
| `0x40571E JSR @ER5` | `0x401322` |

**Counterexample to unsafe promotion:** `0x406912 JSR @ER5` follows `0x4068FA MOV.L #0x406B12,ER5`, but an intervening `MOV.L ER1,ER5` overwrites ER5; the immediate is **not** a proven call target.

## 4. Kernel ER3 call-chain investigation (Stages 9.6–9.12)

### 4.1 Call-chain map

```text
0x400126  MOV.L #0x405E02,ER3
0x40012C  JSR @ER3       [adjacent target proven]
0x400140  JSR @ER3       [caller chain NOT promoted]
0x400166  JSR @ER3       [caller chain NOT promoted]
0x40018C  JSR @ER3       [caller chain NOT promoted]

0x405E02  wrapper -> 0x4069A0
0x4069A0  helper  -> 0x1058DC (outside 64-KiB Kernel)
0x405E1A  wrapper -> 0x4069BE
0x4069BE  helper with bounded ER3 preservation proof

0x400150, 0x400176 -> direct calls to 0x405E1A
```

### 4.2 Exact-byte helper and preservation evidence

- **Stage 9.7:** B0 file offset `0x0058DC` has H8S-like routine bytes and a save/restore signature. `0x1058DC` maps to this offset **only under the runtime mapping hypothesis**. The raw sequence `5E 10 58 DC` occurs 379 times in B0, 68 in its first 64 KiB; these are **raw byte-pattern counts, not 379 validated calls**.
- **Stage 9.8:** Bounded CFG for exact B0 bytes `0x0058DC–0x005943`: **47 decoded instructions, 55 traversed edges, 1 validated RTS**; ER3 preservation proven for the exact bytes on modeled paths. Does **not** prove those bytes execute at runtime address `0x1058DC`.
- **Stage 9.9:** Kernel helper `0x4069BE` preserves ER3 on modeled paths: **24 instructions, 30 edges, 1 RTS**. The wrapper `0x405E02` remained unknown due to its external dependency.
- **Stage 9.10:** `0x405E1A` preserves ER3 under the proven callee `0x4069BE` contract. `0x405E02` still blocked by `0x4069A0 -> 0x1058DC`.
- **Stage 9.11:** Exact Kernel bytes for `0x4069A0` and `0x405E02` match. Both **conditionally** preserve ER3 **if** runtime `0x1058DC` executes the validated B0 routine at offset `0x0058DC`.
- **Stage 9.12:** Exact caller window `0x40012C–0x40018D` matches expected instructions. No explicit caller-side ER3 stack save/restore in that verified window. Two direct calls to `0x405E1A` at `0x400150` and `0x400176`. Alternative caller-save proof not established.

**CURRENT CONCLUSION:** `0x400140`, `0x400166`, `0x40018C` are **UNKNOWN_NOT_PROMOTED**. Do not turn conditional ER3 preservation into a proven indirect target or reachability seed.

### 4.3 Other postponed Kernel research

At `0x400164` and `0x400174`, instructions reference Normal at `0x410000` and Kernel table at `0x40648C` with a comparison at `0x40017C` and mismatch branch/call at `0x40017E–0x400180`. A 16-byte model-ID comparison and mismatch/unlock behavior are **hypotheses**, not complete control-flow or hardware proofs. Possible generation gate around `0x400212–0x400222` is likewise pending. Kernel feature analysis was deliberately postponed in favor of boot/decoder evidence.

## 5. Boot reconnaissance (Stages 9.12–9.14)

### 5.1 Boot entry and candidate Kernel call

```asm
100022  JMP @0x100026
100026  MOV.L ER4,@-ER7
10002A  SUB.L ER4,ER4
10002C  JSR @0x104D00
10003C  JSR @0x108000
100040  JSR @0x107DF0
...
1000A0  JSR @0x107000
1000A4  BRA ...
1000A6  JSR @0x400000
1000AA  MOV.L @ER7+,ER4
1000AE  RTS
```

**OBSERVED:** `0x1000A6` encodes a direct **JSR**, not a terminal JMP. A return sequence follows it. Branch conditions leading to the call and actual return behavior are **not hardware-proven**. The boot code includes conditional branches and a possible Kernel-presence check near `0x100086–0x10009E`; its semantics require separate path analysis. Another candidate direct call leaves the boot region at `0x100120 JSR @0x000400`.

### 5.2 Stage 9.13 bounded candidate CFG

| Metric | Result |
|---|---:|
| Decoded instructions | 1,081 |
| Candidate edges | 1,211 |
| Unknown boundaries | 0 |
| Opaque semantic boundaries | 5 |
| Direct targets outside boot region | 2 |
| Overlaps | 0 |

Opaque semantic sites: `0x1073CA` (`7F287250`), `0x10729C` (`7F287000`), `0x10732E` (`7F287030`), `0x1072FA` (`7F287030`), `0x1073AC` (`7E087700`). The audit does not resolve indirect targets or reconstruct full call/return context. It treats edges as candidates, not execution proof.

### 5.3 Stage 9.14 direct absolute MMIO evidence

**FF42 initialization (`0x104D00–0x104D5E`):** 18 decoded starts, 10 direct absolute MMIO writes, 0 direct reads.

| Site | Destination | Decoded operation |
|---|---|---|
| `0x104D06` | `0xFF421034` | `MOV.L ER0,@abs` |
| `0x104D10` | `0xFF421030` | `MOV.W R0,@abs` |
| `0x104D1A` | `0xFF420030` | `MOV.W E0,@abs` |
| `0x104D24` | `0xFF420034` | `MOV.W E0,@abs` |
| `0x104D2A` | `0xFF420038` | `MOV.W R0,@abs` |
| `0x104D36` | `0xFF421004` | `MOV.L ER1,@abs` |
| `0x104D3E` | `0xFF421000` | `MOV.W R0,@abs` |
| `0x104D44` | `0xFF420000` | `MOV.W R0,@abs` |
| `0x104D4E` | `0xFF420004` | `MOV.W E0,@abs` |
| `0x104D58` | `0xFF420008` | `MOV.W E0,@abs` |

**FF3F control (`0x107DF0–0x107F1C`):** 92 decoded starts, 12 direct absolute writes and 2 direct reads. Writes occur at `0xFF3F100B`, `0xFF3F1028`, `0xFF3F102A`, `0xFF3F1010`, `0xFF3F1011`, `0xFF3F1009`; reads at `0xFF3F100B` and `0xFF3F1009`. The region includes `BSET`, `BCLR`, `BST`, polling/branch instructions and calls to `0x107D4A` and `0x107DC6`. See Stage 9.14 raw report for all sites and opcodes.

**FF3F block setup (`0x108000–0x1082C4`):** 159 decoded starts. Stage 9.14 counted **zero direct absolute** reads/writes here, explicitly excluding **register-relative** MMIO; Stage 9.15 resolves the latter. Do not misread the zero as absence of MMIO.

## 6. ER6-derived MMIO addresses (Stage 9.15)

At `0x10800C`, the bounded analysis establishes `ER6 = 0xFF3FF000`. For each modeled access, effective address = ER6 + displacement. ER6 is restored from stack at `0x1082BC` (`LDM.L @SP+,(ER4-ER6)`), after which its value is **UNKNOWN** to the analysis.

| Stage 9.15 metric | Value |
|---|---:|
| Region | `0x108000–0x1082C4` |
| Decoded / CFG-reached instruction starts | 159 / 159 |
| CFG propagated edges | 172 |
| Resolved register-relative write sites | 42 |
| Uncertain register-relative sites | 0 |
| Distinct effective destination addresses | 7 |

| Effective address | Write sites | Notes |
|---|---:|---|
| `0xFF3FF000` | 1 | Initial ER1 source |
| `0xFF3FF004` | 5 | ER1 and ER0 sources |
| `0xFF3FF05C` | 1 | Final ER0 write; full value unknown |
| `0xFF3FF080` | 1 | Initial ER1 source |
| `0xFF3FF088` | 2 | ER0 source |
| `0xFF3FF0C0` | 25 | Repeated writes, constants and memory-derived values |
| `0xFF3FF0C4` | 7 | Mostly immediate constants |
| **Total** | **42** | Instruction sites, not necessarily executed writes |

The Stage 9.15 address calculation and Stage 9.16 value provenance are **bounded static analyses**. Register aliases, missing instruction effects, and alternate paths can require re-audit. No peripheral names/functions have been established.

## 7. MMIO write-value provenance (Stage 9.16)

The Stage 9.16 Windows run reproduced **42 writes: 22 `IMM_...` provenance, 20 `UNKNOWN` or `MEMORY_READ`**. Region `0x108000–0x1082C4`; 159 trace instructions, 159 reached, 210 CFG propagations. Method: conservative forward abstract register provenance. Calls clobber all tracked registers; partial-width writes kill full-register constants; memory contents are not assumed known.

**Provenance is not execution proof.** `IMM_0x...` is the constant identified by this model at a write site; `MEMORY_READ` identifies source type but not its source address or actual contents. `UNKNOWN` is intentionally preserved.

### 7.1 Complete Stage 9.16 write-site table

| Site | Destination | Source | Provenance | Instruction |
|---|---|---|---|---|
| `0x108020` | `0xFF3FF000` | `ER1` | `UNKNOWN` | `MOV.L ER1,@ER6` |
| `0x108024` | `0xFF3FF080` | `ER1` | `UNKNOWN` | `MOV.L ER1,@(128:16,ER6)` |
| `0x10802A` | `0xFF3FF004` | `ER1` | `UNKNOWN` | `MOV.L ER1,@(4:16,ER6)` |
| `0x108044` | `0xFF3FF088` | `ER0` | `IMM_0x00008002` | `MOV.L ER0,@(136:16,ER6)` |
| `0x108050` | `0xFF3FF0C4` | `ER0` | `IMM_0x030E0A89` | `MOV.L ER0,@(196:16,ER6)` |
| `0x108064` | `0xFF3FF0C0` | `ER0` | `IMM_0xB4269534` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108070` | `0xFF3FF0C0` | `ER0` | `IMM_0x3F86B89D` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10807C` | `0xFF3FF0C0` | `ER0` | `IMM_0xB98FC466` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108084` | `0xFF3FF0C0` | `ER0` | `UNKNOWN` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108094` | `0xFF3FF088` | `ER0` | `UNKNOWN` | `MOV.L ER0,@(136:16,ER6)` |
| `0x1080A0` | `0xFF3FF0C4` | `ER0` | `IMM_0x030F0A09` | `MOV.L ER0,@(196:16,ER6)` |
| `0x1080B4` | `0xFF3FF0C0` | `ER0` | `IMM_0x48A155E2` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1080C0` | `0xFF3FF0C0` | `ER0` | `IMM_0x13DA9F3D` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1080CC` | `0xFF3FF0C0` | `ER0` | `IMM_0x373AE172` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1080D6` | `0xFF3FF0C0` | `ER0` | `UNKNOWN` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1080E2` | `0xFF3FF0C4` | `ER0` | `IMM_0x030E0A89` | `MOV.L ER0,@(196:16,ER6)` |
| `0x1080F6` | `0xFF3FF0C0` | `ER0` | `IMM_0xAF528B55` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108102` | `0xFF3FF0C0` | `ER0` | `IMM_0x497F4A36` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10810E` | `0xFF3FF0C0` | `ER0` | `IMM_0x8A20367C` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108118` | `0xFF3FF0C0` | `ER0` | `UNKNOWN` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10812C` | `0xFF3FF0C4` | `ER0` | `IMM_0x03490A09` | `MOV.L ER0,@(196:16,ER6)` |
| `0x108140` | `0xFF3FF0C0` | `ER0` | `IMM_0xF0560128` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10814C` | `0xFF3FF0C4` | `ER0` | `IMM_0x01950E11` | `MOV.L ER0,@(196:16,ER6)` |
| `0x108158` | `0xFF3FF004` | `ER0` | `IMM_0x00080001` | `MOV.L ER0,@(4:16,ER6)` |
| `0x10818E` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108198` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1081A8` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1081B2` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x1081E6` | `0xFF3FF0C4` | `ER0` | `IMM_0x00108C01` | `MOV.L ER0,@(196:16,ER6)` |
| `0x1081F2` | `0xFF3FF004` | `ER0` | `IMM_0x00040001` | `MOV.L ER0,@(4:16,ER6)` |
| `0x108218` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108224` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108230` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10823C` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108248` | `0xFF3FF0C4` | `ER0` | `IMM_0x030F0A89` | `MOV.L ER0,@(196:16,ER6)` |
| `0x108254` | `0xFF3FF004` | `ER0` | `IMM_0x00040001` | `MOV.L ER0,@(4:16,ER6)` |
| `0x108268` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108274` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x108280` | `0xFF3FF0C0` | `ER0` | `MEMORY_READ` | `MOV.L ER0,@(192:16,ER6)` |
| `0x10828C` | `0xFF3FF0C0` | `ER5` | `MEMORY_READ` | `MOV.L ER5,@(192:16,ER6)` |
| `0x1082A0` | `0xFF3FF004` | `ER0` | `IMM_0x00001001` | `MOV.L ER0,@(4:16,ER6)` |
| `0x1082AA` | `0xFF3FF05C` | `ER0` | `UNKNOWN` | `MOV.L ER0,@(92:16,ER6)` |

**Integrity check:** 42 write-site rows transcribed from the Stage 9.16 reference report.

### 7.2 Patterns to investigate, not yet explained

- `0xFF3FF0C0` receives 25 writes. Example immediate runs: `0xB4269534`, `0x3F86B89D`, `0xB98FC466`, followed by an `UNKNOWN` site; later `0x48A155E2`, `0x13DA9F3D`, `0x373AE172`, followed by another `UNKNOWN` site. This is **pattern evidence**, not proof of a FIFO, cryptographic function, microcode loader, or register semantics.
- At `0x10818E`, `0x108198`, `0x1081A8`, `0x1081B2` and later sites, ER0 is classified `MEMORY_READ` before writes to `0xFF3FF0C0`. At `0x10828C`, the source is ER5 (`MEMORY_READ`). The **source addresses** and actual values remain unresolved.
- At `0x1082AA`, ER0 is `UNKNOWN` before a 32-bit write to `0xFF3FF05C`. An immediately preceding partial-width write cannot justify claiming a full 32-bit constant.
- `0xFF3FF0C4` receives seven write sites with modeled immediate values; their function is unknown.

## 8. Reproducing the offline audits

Use exact input hashes above. Run from the extracted Stage ZIP directory or copy scripts/reports to `C:\Firmware`. Stage reports are evidence artifacts and should be archived unchanged with the corresponding scripts and firmware hashes.

```bat
REM Stage 9.12 - Kernel/B0 cross-check
py stage912_offline_audit.py --kernel kernel.bin --b0 hwdump_b0.bin --out stage912_evidence.txt

REM Stage 9.13 - build separate C boot audit (Visual Studio Developer Prompt)
cl /nologo /W3 stage913_boot_audit.c /Fe:stage913_boot_audit.exe
stage913_boot_audit.exe hwdump_b0.bin stage913_boot_report.txt

REM Stage 9.14 - direct absolute MMIO / handoff audit
py stage914_boot_register_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage914_boot_register_report.txt

REM Stage 9.15 - ER6 effective addresses
py stage915_er6_mmio_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage915_er6_mmio_report.txt

REM Stage 9.16 - MMIO value provenance
py stage916_mmio_value_provenance.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage916_mmio_value_report.txt
```

`kernel.bin` above is a placeholder for the actual matching extracted Kernel filename; `stage913_boot_report_windows.txt` is the bundled trace filename and may be replaced with the user's matching Stage 9.13 report. Verify `--help`/stage-specific README when invoking older bundles. Stage 9.13's C tool must be compiled separately; the Stage 9.14–9.16 Python scripts are read-only. Keep the original reports rather than reconstructing them from this document.

### 8.1 Evidence artifact inventory

| Stage | Artifact / report |
|---|---|
| 9.7 | `--b0-er3-audit` output |
| 9.8 | `--b0-er3-cfg` output |
| 9.9 | `--er3-chain-audit` output |
| 9.10 | wrapper-chain audit output |
| 9.11 | `--er3-link-report` output |
| 9.12 | `stage912_evidence.txt` (or chosen output filename) |
| 9.13 | `stage913_boot_report.txt` / `stage913_boot_report_windows.txt` |
| 9.14 | `stage914_boot_register_report.txt` |
| 9.15 | `stage915_er6_mmio_report.txt` |
| 9.16 | `stage916_mmio_value_report.txt` |

**Archival recommendation:** Keep a manifest with file SHA-256, stage/tool version, source ZIP, input hashes, host environment, and date. Preserve reports and source scripts in versioned folders; use `DISASM.md` as an index and interpretation layer, not a substitute for raw evidence.

## 9. Open questions and next investigations

| Priority | Question | Required evidence / constraint |
|---|---|---|
| Stage 9.17 follow-up | Which exact memory addresses feed `MEMORY_READ` values written to `0xFF3FF0C0`? | Bounded register-pointer/source tracking, joins/aliases, unknowns retained; no decoder rewrite or promotions |
| High | What are the FF3F/FF42 peripheral functions? | Hardware docs, independent firmware references, or controlled measurements; do not label from address pattern alone |
| High | Does runtime `0x1058DC` execute raw B0 offset `0x0058DC`? | Hardware mapping proof or independently validated runtime translation |
| High | Which boot branches actually reach `0x1000A6`? | Exact branch predicates, side effects, and eventually runtime evidence |
| High | Does the Kernel return to `0x1000AA`? | Runtime trace or sufficiently complete semantic analysis |
| High | Can ER3 call sites `0x400140/0x400166/0x40018C` be promoted? | Proven complete caller path effects plus external mapping and callee effects |
| Later | Can DriveKit read arbitrary live addresses, not just sequential B0? | Investigate supported read-only diagnostics; establish seekability, state requirements, side effects and safety on actual hardware |
| Later | Can an editor overlay static disassembly, xrefs, live values, and annotations? | Separate UI/transport design; maintain provenance and image/version identity |
| Later | Kernel model-ID comparison / generation gates | Exact-byte path validation; no speculative patching |


### Stage 9.17 — bounded memory-source inventory (candidate, not pointer proof)

The initial Stage 9.17 tool inventories the syntactically adjacent load instruction feeding each write to `0xFF3FF0C0` and records nearby pointer setup. It **does not** claim full control-flow-sensitive pointer provenance: a branch can bypass an adjacent instruction, register pointers may have multiple reaching definitions, and a memory read does not reveal runtime contents.

Notable candidate: `0x10820E MOV.L #0x10881E,ER5` establishes a base on one decoded path, while `0x108208 MOV.L @ER7,ER5` is an alternative. The `@(4/8/12/16/20/24/28,ER5)` loads may be table-like, but exact effective addresses are **conditional** on the path and ER5 value. The preceding `0x10818A` load uses a calculated ER0 pointer; its source address is not established.

Windows command: `py stage917_mmio_source_inventory.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage917_mmio_source_report.txt`. The Stage 9.17 archive includes the reference report, previous tools, and the unchanged disassembler. No hardware access or firmware writes.

## 10. Updating this document

For each new stage, add: **goal; exact input hashes; command; tool/source version; bounded region; raw report filename; numerical results; notable exact addresses/bytes; proof level; remaining unknowns; regression against prior stage**. Keep a chronological changelog and correct mistakes explicitly rather than quietly overwriting the historical claim. If a later hardware measurement contradicts static analysis, preserve both with the explanation.

### Changelog

- **2026-11-07 — Stage 9.17 inventory:** Added bounded syntactic source-load inventory and explicit requirement for future CFG-sensitive pointer analysis. No hardware access or promotions.

- **2026-11-07 — README reconciliation:** Compared the supplied 934-line `DriveKit_README_disassembler_stage8_6(1).md` against the Stage 9.16 evidence ledger. Added B0 acquisition protocol details, extractor chunk sizes and observed timing, decoded-image safety, historical `open_drive()` issue, source manuals/credits, and the important cross-model `0xFF3FF000` Crypto/DMA attribution caveat. Preserved the README as the user-facing source; no code, firmware, or GitHub changes.

- **2026-11-07 — Initial `DISASM.md`:** Consolidated existing README B0 address mapping and documented Stage 8.6–9.16 investigations, ER3 preservation constraints, boot entry/Kernel call, FF42/FF3F MMIO, complete 42-site Stage 9.16 provenance table, reproduction commands, and Stage 9.17 backlog. No firmware or decoder changes.

### Related documentation

- `README.md` — DriveKit usage, hardware support, B0 commands, flashing precautions, and user-facing workflows.
- `README_STAGE*.txt` in stage archives — implementation notes for individual audits.
- Stage-specific raw reports — authoritative per-site output for each exact firmware image.
- `DISASM.md` — evolving analysis, conclusions, limitations, and investigation roadmap.

### Stage 9.18 — CFG-sensitive pointer provenance and conditional B0 source bytes (2026-11-07)

**Status:** Local reference audit completed; Windows confirmation pending. The read-only `stage918_cfg_pointer_audit.py` analyzes the Stage 9.13 bounded trace (`0x108000–0x1082C4`) using forward may-constant sets, candidate CFG joins, loop fixpoint propagation, and conservative unknowns. Input B0 SHA-256: `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`. The analysis does not prove actual execution, complete H8S register effects, or physical memory mapping.

**Critical branch split:** `0x108206 BCC $+8:8` may reach `0x10820E MOV.L #0x10881E,ER5`; its other path reaches `0x108208 MOV.L @ER7,ER5` and `0x10820C BRA $+8:8`, joining at `0x108214`. Since the stack-derived pointer is unknown, the **full candidate CFG resolves zero of twelve adjacent memory-load pointers unconditionally**. This is an intentional conservative result, not a failure of the tool.

**Conditional scenario:** If the `0x108206` BCC branch is taken and ER5 receives `0x10881E`, eight loads feeding `0xFF3FF0C0` have the following *candidate* addresses. File offsets and bytes are from the supplied B0 under the **not-hardware-proven** translation `runtime - 0x100000`. Four earlier memory-source sites (`0x10818E`, `0x108198`, `0x1081A8`, `0x1081B2`) remain unresolved.

| MMIO write site | Source runtime address, conditional | B0 file offset | Observed B0 bytes (file order) |
|---|---|---|---|
| `0x108218` | `0x10881E` | `0x00881E` | `2E C9 95 0C` |
| `0x108224` | `0x108822` | `0x008822` | `D3 E6 41 BE` |
| `0x108230` | `0x108826` | `0x008826` | `0D CD 1E FD` |
| `0x10823C` | `0x10882A` | `0x00882A` | `26 4D 45 C5` |
| `0x108268` | `0x10882E` | `0x00882E` | `A5 2A 48 7E` |
| `0x108274` | `0x108832` | `0x008832` | `0C 2F 1A D3` |
| `0x108280` | `0x108836` | `0x008836` | `D7 A7 CC F8` |
| `0x10828C` | `0x10883A` | `0x00883A` | `65 B3 9F B1` |

At `0x108286 MOV.L @(28:16,ER5),ER5`, the address is evaluated using the **old ER5**, then ER5 is overwritten with memory-derived data; `0x10828C` writes that new value. The bytes above are **not measured runtime MMIO values**, nor is the hardware role of `0xFF3FF0C0` established. This stage makes no decoder changes, firmware writes, or xref/reachability promotions.

**Reproduction (Windows):**

```bat
py stage918_cfg_pointer_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage918_cfg_pointer_report.txt
```

Archive `DriveKit_Stage_9_18_CFG_Pointer_Provenance.zip` includes the new tool, reference report, `README_STAGE9_18.txt`, and all prior project files. Follow-up: investigate stack-derived ER5 origin and the earlier ER0/ER3/ER4 pointers; verify runtime mapping independently before promoting any source address to hardware-proven status.

**Changelog:** 2026-11-07 — Stage 9.18 local reference analysis: 12 adjacent memory-source loads, 0 unconditionally resolved, 8 conditional candidate addresses with observed B0 bytes; Windows verification pending.

### Stage 9.18 Windows verification — 2026-11-07

**USER-REPORTED / OBSERVED OUTPUT:** Windows invocation `py stage918_cfg_pointer_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage918_cfg_pointer_report.txt` completed with 159 traced instructions, 159 CFG-reached, 1,162 CFG propagations, 12 adjacent memory-load/write pairs, **0 unconditional source addresses**, and **12 unresolved**. The forced BCC-taken scenario reached 157 instructions with 1,100 propagations and resolved **8 conditional candidate sources**. These values match the previously documented reference results. The earlier "Windows confirmation pending" sentence above is retained as historical pre-verification status, superseded by this record.

### Stage 9.19 — BLD/BCC condition source and candidate stack argument (2026-11-07)

**Status:** Local reference audit completed against B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`; **Windows verification pending**. Read-only script: `stage919_branch_stack_audit.py`; report: `stage919_branch_stack_report_reference.txt`; trace region `0x108000–0x1082C4`, 159 decoded instructions. This stage is a bounded *instruction-dependency inventory*, not a complete flag-aware or stack-aware symbolic executor.

**Exact branch-condition evidence:** `0x108200` bytes `6A10FE797730` decode as `BLD #3,@H'FE79:16`; `0x108206` bytes `4406` decode as `BCC $+8:8`. These are adjacent decoded instructions, with no intervening decoded instruction. This points to the bit-load as the **candidate immediate flag producer** for the branch. The exact H8S carry/bit semantics and the meaning of the encoded 16-bit address `0xFE79` require manual verification; the runtime value and actual branch outcome remain **UNKNOWN**. Do not label `0xFE79` as a proven physical MMIO register. The earlier `0x1081FC BLD #6,R0L` and `0x1081FE BCC $-6:8` form a separate polling candidate.

**Candidate stack origin:** Routine prologue `0x108000 STM.L (ER2-ER3),@-SP`, `0x108004 STM.L (ER4-ER6),@-SP`, `0x108008 SUB.W #H'C:16,R7`; `0x108012 MOV.L ER0,@ER7` stores a value. The branch-not-taken arm `0x108208 MOV.L @ER7,ER5` appears to read the saved slot, while `0x10820C BRA` joins the immediate-base arm at `0x108214`. **INFERRED / UNPROVEN:** this may forward the routine's entry ER0 as a caller-supplied source pointer. A complete SP delta, alias, intervening store, and caller-argument analysis is required before promoting that interpretation. The immediate-base arm at `0x10820E` remains `ER5 = 0x10881E`, conditional on branch outcome; eight offline B0 table values remain as listed in Stage 9.18.

**Local audit summary:** 159 trace instructions validated against exact B0 bytes; one local BLD/BCC candidate flag chain; one candidate stack store/load chain; eight conditional 32-bit B0 table entries. **No branch predicate solved, no stack pointer value proven, no hardware execution proof, no firmware writes, no decoder changes, no reachability promotions.**

**Windows reproduction:**

```bat
py stage919_branch_stack_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage919_branch_stack_report.txt
```

**Next steps:** Verify H8S `BLD`/`BCC` semantics against the Renesas manual; inspect full ER7/SP evolution and possible alias writes between `0x108012` and `0x108208`; investigate the caller's ER0 setup before `JSR @0x108000`; keep both branch outcomes candidate-only until the flag input is independently established. MrPenguin's cross-model B0 notes may be compared when available, with attribution and model-specific evidence labels.

**Changelog:** 2026-11-07 — Stage 9.18 Windows confirmation recorded; Stage 9.19 local reference audit added. Windows Stage 9.19 verification pending.

### Stage 9.19 Windows verification — 2026-11-07

**USER-REPORTED / OBSERVED:** `stage919_branch_stack_audit.py` completed on Windows against B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`: 159 trace instructions; one adjacent `BLD`/`BCC` local flag chain (`0x108200`/`0x108206`); candidate entry-ER0 stack origin (`0x108012` to `0x108208`); eight conditional B0 longwords at `0x10881E–0x10883D`. Branch outcome, memory bit value, stack alias safety, physical mapping, and execution remain unproven. This supersedes the earlier Stage 9.19 "Windows verification pending" historical status.

### Stage 9.20 — direct boot caller and bounded stack-slot inventory (2026-11-07)

**Status:** Local reference audit completed; Windows verification pending. Tool `stage920_stack_caller_audit.py`, reference output `stage920_stack_caller_report_reference.txt`. Read-only exact-B0-byte verification of Stage 9.13 candidate trace, B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`; bounded `0x108000–0x1082C4` contains 159 decoded candidate instructions. No firmware writes, decoder edits, or reachability promotions.

**New caller evidence:** `0x100036` bytes `7A0000000154` decode `MOV.L #H'154:32,ER0`, followed immediately by `0x10003C` bytes `5E108000` decode `JSR @H'108000:24`. For **this particular decoded call site**, the candidate entry ER0 is `0x00000154`. This is not a universal statement about every possible caller or runtime execution. Do not treat `0x154` as a B0 offset, a physical memory address, or an already dereferenced pointer.

**Stack evidence:** `0x108012 MOV.L ER0,@ER7` stores into slot `ER7+0`; branch-not-taken `0x108208 MOV.L @ER7,ER5` reads the same *syntactic* slot. Other accesses are `0x10816E MOV.L ER0,@(8:16,ER7)`, `0x10819E MOV.L @(8:16,ER7),ER0`, `0x1081C2 MOV.L @(8:16,ER7),ER0`, `0x1081CE MOV.L ER0,@(8:16,ER7)`. If ER7 is stable and access widths are interpreted as expected, `ER7+8` does not overwrite `ER7+0`. The local reference inventory counted **six explicit ER7 references**, **zero decoded calls/traps** in `0x108012–0x108208`, and **34 candidate memory write/bit-operation instructions**. This is a *syntactic* inventory, not an exhaustive proof against aliases, unmodeled instruction effects, interrupts, or unusual memory mapping. Prologue `0x108008 SUB.W #H'C:16,R7` and its full-register effect require manual verification.

**Two separate conditional pointer hypotheses:** `0x108206 BCC` taken -> `0x10820E MOV.L #0x10881E,ER5` -> eight candidate 32-bit B0 source values already documented in Stages 9.18–9.19. BCC not taken -> `0x108208 MOV.L @ER7,ER5` -> **candidate `0x00000154` only under the specific direct caller, stable stack, and no-alias assumptions**. Neither branch outcome is known at runtime. The decoded `0x108200 BLD #3,@H'FE79:16` flag producer remains subject to independent Renesas manual semantic verification; the encoded operand `0xFE79` is not hardware-proven as a physical address. The value of its tested bit is unknown.

**Reproduction (Windows):**

```bat
py stage920_stack_caller_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage920_stack_caller_report.txt
```

**Next:** Verify `BLD`, `BCC`, and `SUB.W R7` semantics against the Renesas manual; examine all incoming callers to `0x108000`, stronger SP and memory-alias invariants, and whether `0x154` is a meaningful caller-supplied buffer pointer in the runtime map. Never promote either pointer to hardware proof based on this offline audit alone.

**Changelog:** 2026-11-07 — Stage 9.19 Windows results confirmed by user; Stage 9.20 local caller/stack evidence added, Windows confirmation pending.

### Stage 9.20 Windows verification — 2026-11-07

**USER-REPORTED / OBSERVED:** `stage920_stack_caller_audit.py` completed on Windows using B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`: 159 candidate trace instructions; direct caller `0x100036 MOV.L #0x154,ER0` to `0x10003C JSR @0x108000`; 6 syntactic ER7 references; 0 decoded calls/traps in the inspected store-to-load interval; 34 potential write/bit-operation sites (this count includes `BLD`, which is **not a memory write**). Slot `ER7+0` is the candidate saved caller argument; `ER7+8` has separate accesses. The reported values match the local reference run. Physical mapping, branch execution, alias safety and exact runtime stack contents remain unproven.

### Stage 9.21 — Renesas manual semantics and bounded stack audit (2026-11-07)

**Status:** Local reference script `stage921_manual_semantics_audit.py` completed against exact B0 SHA-256 above and Stage 9.13 Windows trace; Windows Stage 9.21 verification pending. Read-only; 159 instructions in bounded region `0x108000–0x1082C4`. Reference output: `stage921_manual_semantics_report_reference.txt`. This is a manual-informed static evidence check, **not a full CFG stack/alias proof**.

**Primary source:** Renesas, *H8S/2600 Series, H8S/2000 Series Software Manual*, REJ09B0139-0400, Rev. 4.00 (24 February 2006), https://www.renesas.com/en/document/mah/h8s2600-series-h8s2000-series-software-manual . Section 2.2.14 p.74: `BLD` loads the selected bit into CCR.C and leaves the memory operand unchanged. Section 2.2.7 p.60: `BCC` is taken if C=0, with displacement relative to the next instruction. Section 1.7 pp.33–35: in Advanced mode, 16-bit absolute data addresses are **sign-extended** to 32 bits; `R7` is the 16-bit register portion of `ER7` (general-register description in Section 1). The exact target MCU's operating mode and external bus mapping are not established by these software semantics.

**New documented conditional interpretation:** `0x108200` bytes `6A10FE797730` decode `BLD #3,@H'FE79:16`; `0x108206` bytes `4406` decode `BCC $+8:8`. In Advanced mode, the encoded `@H'FE79:16` gives the **CPU effective data address `0xFFFFFE79`**, not `0x0000FE79`; this does **not** identify the physical peripheral. If bit 3 of the byte read is zero, C=0 and BCC goes to `0x10820E` (ER5=`0x10881E`, conditional fixed-table path). If bit 3 is one, C=1 and execution falls through to `0x108208` (ER5 loaded from saved-stack-slot candidate). The bit's actual value and runtime path are **UNKNOWN**. `BLD` reads a bit; it is **not a write**.

**Stack-register semantics:** `0x108008 SUB.W #0x000C,R7` subtracts from the **low 16 bits** of ER7; the upper 16-bit E7 portion is not modified by this word-sized operation. Thus it must not be casually modeled as `SUB.L #0xC,ER7`: low-word underflow differs. This prologue operation precedes the `0x108012` store. Between the saved-slot store at `0x108012` and load at `0x108208`, the candidate trace has four other explicit ER7 references, all at `ER7+8` (`0x10816E`, `0x10819E`, `0x1081C2`, `0x1081CE`), and no other *explicit* SP adjustments in that interval. This is not an alias/interrupt proof. Caller value `0x154` remains conditional on the specific direct call site and stack stability, and is not a verified address-space pointer.

**x86 learning bridge (conceptual, not machine-code equivalent):** `BLD #3,@H'FE79:16; BCC` roughly resembles `bt byte [mapped_address],3; jnc fixed_table` in the sense of carry-bit testing and branching, although x86 `BT` operand forms and memory semantics differ. `SUB.W #12,R7` resembles changing only the low 16 bits of a 32-bit stack register, **not** `sub esp,12` when the low half underflows.

**Windows reproduction:**

```bat
py stage921_manual_semantics_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage921_manual_semantics_report.txt
```

**Next:** Investigate whether the firmware is executing in the assumed CPU mode, locate MCU-specific hardware address maps for `0xFFFFFE79`, strengthen alias/stack proofs, and avoid equating caller argument `0x154` with a B0 offset. No decoder changes, firmware writes, or reachability promotions.

### Stage 9.21 Windows verification — 2026-11-07

**USER-REPORTED / OBSERVED:** `stage921_manual_semantics_audit.py` completed on Windows for B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`, with 159 candidate instructions in `0x108000–0x1082C4`, Advanced-mode effective address `0xFFFFFE79` for encoded `@H'FE79:16`, Renesas-documented `BLD`/`BCC` behavior, and four interim ER7+8 references. This matches the local Stage 9.21 reference output. The user pasted a report truncated at `N` after the `SLOT_STABILITY` line; the preceding displayed evidence and command completion are confirmed, while the unseen trailing lines are not independently attested by that paste. Stage 9.21 is Windows verified for the displayed results; earlier pending status is historical.

### Stage 9.22 — low-memory argument reuse and peripheral identification boundary (2026-11-07)

**Status:** Local read-only reference completed, **Windows verification pending**. Script `stage922_register_lowmem_audit.py`; reference report `stage922_register_lowmem_report_reference.txt`. Inputs: exact B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603` and Stage 9.13 candidate trace. The script checks B0 bytes against the decoded trace, verifies eight selected instruction encodings, counts 159 candidate instructions in the bounded routine, and inventories exact immediate `#H'154:32` occurrences in the candidate trace. This is **not** a complete search of all possible B0 code, a live execution trace, or a proof of the hardware register map.

**New exact instruction evidence:** `0x100036` bytes `7A0000000154` decode `MOV.L #H'154:32,ER0`; `0x10003C` bytes `5E108000` decode `JSR @H'108000:24`. Following the call in decoded address order, `0x100046` bytes `7A0100000154` decode `MOV.L #H'154:32,ER1`, and `0x10004C` bytes `01006994` decode `MOV.L ER4,@ER1`. Thus the **same immediate 0x154 appears twice in the candidate boot trace**, and the post-call instruction is a **candidate longword store to address 0x00000154** if ER1 is unchanged. Because the store is *after* the call, it cannot be used as evidence for the contents of address 0x154 during the preceding call. The call returning, the subsequent instructions executing, and the physical mapping are unproven. There are two immediate `#H'154:32` sites in this candidate trace; this count is not a firmware-wide exhaustive reference search.

**Capture coverage:** The observed B0 stream convention maps file offset zero to nominal runtime `0x100000`, not `0x000000`. Consequently runtime `0x00000154` is **outside this captured B0 interval**. Reading B0 file offset `0x154` would yield data corresponding to nominal runtime `0x100154`, **not** contents of low-memory address `0x154`. No live low-memory value has been obtained.

**Peripheral research and limitations:** The Renesas H8S/2600 Series Software Manual, REJ09B0139-0400 Rev 4.00, establishes that in Advanced mode encoded absolute-16 `0xFE79` sign-extends to effective data address `0xFFFFFE79`; `BLD #3` reads bit 3 into carry, and `BCC` takes the branch if carry is zero. The exact peripheral name and bit function at this address are **NOT IDENTIFIED**: H8S/2600 is a CPU family, and a product-specific hardware manual/register table and confirmed Pioneer MCU part number are needed. Other H8S group hardware manuals cannot be silently substituted. The address's placement in a plausible high on-chip-I/O area is not an identification of the register or a measurement of its value. Renesas reference: https://www.renesas.com/en/document/mah/h8s2600-series-h8s2000-series-software-manual ; comparative *different-group* examples (not device proof): https://www.renesas.com/en/document/mah/h8s2628-group-hardware-manual .

**x86 conceptual bridge:** `MOV.L #0x154,ER1; MOV.L ER4,@ER1` resembles `mov ecx,154h; mov [ecx],esi` in purpose (a pointer register and a 32-bit store), but is not an assertion of matching calling conventions, memory maps, or instruction encodings. A post-call store is not evidence for a pre-call memory value.

**Reproduction (Windows):**

```bat
py stage922_register_lowmem_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage922_register_lowmem_report.txt
```

**Next:** Identify exact Pioneer MCU variant or reliable on-chip register table for `0xFFFFFE79`; inspect potential initialization of low-memory `0x154` on *pre-call* paths and other references using bounded CFG-aware analysis. No firmware writes, no decoder changes, no reachability promotions, no GitHub push.

### Stage 9.23 — ER4 preservation and boot zero-loop structure (2026-11-07)

**Status:** Local read-only reference audit completed; **Windows verification pending**. Script `stage923_er4_preservation_audit.py`; reference output `stage923_er4_preservation_report_reference.txt`. Input B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603` and the Stage 9.13 candidate boot trace. The script checks all parsed trace bytes against the B0 capture using the established **candidate** `runtime - 0x100000` translation and verifies exact bytes at 26 critical instruction addresses. This is a static structural audit, **not** complete symbolic execution, proof of runtime execution, or a verified hardware map. No firmware writes, decoder edits, reachability promotions, or GitHub push.

**Direct caller and ER4 origin:** `0x100026 01006DF4 MOV.L ER4,@-ER7`; `0x10002A 1AC4 SUB.L ER4,ER4` (sets ER4 to zero in the modeled instruction semantics); `0x10002C 5E104D00 JSR @H'104D00:24`; `0x10003C 5E108000 JSR @H'108000:24`; `0x100040 5E107DF0 JSR @H'107DF0:24`. For ER4 to remain zero at the later stores, each intervening callee must preserve the caller's ER4 and return normally.

**Callee `0x104D00`:** The candidate trace contains a direct, straight-line entry-to-return segment `0x104D00–0x104D5E` ending in `0x104D5E 5470 RTS`. The Stage 9.23 local inventory finds **zero explicit ER4 register mentions** and **zero decoded calls/traps** within that bounded segment. This is positive evidence for preservation along the observed decoded segment, **not** a universal guarantee against alternative entries, unmodeled side effects, or interrupts. Instructions beyond `0x104D5E` are not silently merged into this entry's straight-line function.

**Callee `0x107DF0`:** Entry `0x107DF0 01006DF3 MOV.L ER3,@-ER7`; save `0x107DF4 01206DF4 STM.L (ER4-ER6),@-SP`; **ER4 overwritten** at `0x107DFE 7A04FF3F1018 MOV.L #H'FF3F1018:32,ER4`; restore `0x107F14 01206D76 LDM.L @SP+,(ER4-ER6)`; `0x107F18 01006D73 MOV.L @ER7+,ER3`; `0x107F1C 5470 RTS`. The bounded candidate trace contains **9 ER4 mentions** (including save/restore and reads through `@ER4`) and **12 nested JSR sites** to `0x107D4A` or `0x107DC6`. Thus a naive rule “callee never writes ER4” would be **wrong**. The matching save/restore strongly suggests caller-visible ER4 preservation on the modeled return path, conditional on saved-stack-slot integrity and the completeness of candidate return-path coverage. Nested callees have **not** been independently summarized here.

**Callee `0x108000`:** Prior Stage 9.13–9.22 evidence shows `0x108004 STM.L (ER4-ER6),@-SP`, `0x1082BC LDM.L @SP+,(ER4-ER6)`, and terminal `0x1082C4 5470 RTS`. This supports preservation on its modeled normal-return path, still subject to stack alias and other unmodeled effects.

**Loop correction and exact bytes:** `0x100044 1888 SUB.B R0L,R0L`; `0x100046 7A0100000154 MOV.L #0x154,ER1`; `0x10004C 01006994 MOV.L ER4,@ER1`; `0x100050 0A08 INC.B R0L`; `0x100052 0B91 ADDS #4,ER1`; `0x100054 01006994 MOV.L ER4,@ER1`; `0x100058 0A08 INC.B R0L`; `0x10005A 0B91 ADDS #4,ER1`; `0x10005C A808 CMP.B #8,R0L`; `0x10005E 45EC BCS $-18:8` (candidate back-edge to `0x10004C`). **There are two stores and two counter increments per iteration.** Assuming the normal branch/counter semantics and no interfering effects, this is **four iterations and eight longword stores**, not eight iterations. Candidate store addresses: `0x154, 0x158, 0x15C, 0x160, 0x164, 0x168, 0x16C, 0x170`, covering `[0x154,0x174)` (32 bytes). This corrects any earlier phrasing implying eight loop iterations. If ER4 remains zero through the calls and the loop executes as modeled, the candidate operation is a 32-byte zero fill. Neither runtime execution nor the physical meaning of low-memory `0x154` is proven; `0x154` is outside the observed B0 stream address range and is **not** B0 file offset `0x154`.

**x86 conceptual analogy:** A function may temporarily `mov ebx,constant` after `push ebx` and later `pop ebx; ret`, leaving the caller's EBX intact. Likewise, an x86 loop with **two** `mov [ptr],ebx` operations and **two** counter increments per pass reaches eight stores in **four** passes. This is pedagogical, not a claim of identical calling conventions or register encodings.

**Reproduction (Windows):**

```bat
py stage923_er4_preservation_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage923_er4_preservation_report.txt
```

**Next:** Windows-confirm the exact report; perform bounded CFG return-path verification for both callees, review the 12 nested calls and possible stack aliases, and strengthen the loop semantics using the Renesas software manual before promoting zero fill beyond a conditional static hypothesis. Stage 9.22 Windows verification has **not** been reported and remains pending.

### Stage 9.23 Windows verification (2026-11-07)

**Windows verified by user:** `stage923_er4_preservation_audit.py` produced the expected B0 SHA-256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`, 0 explicit ER4 mentions in bounded `0x104D00`, 9 in bounded `0x107DF0`, 12 nested calls, and eight conditional longword stores. This confirms reference-report reproduction on the Windows capture; it is not a hardware execution or alias proof.

### Stage 9.24 — nested helpers and bounded stack/ER4 inventory (2026-11-07)

**Status:** Local reference completed; Windows verification pending. Read-only script `stage924_nested_callee_audit.py` and report `stage924_nested_callee_report_reference.txt`. Exact B0 bytes are compared against all parsed Stage 9.13 candidate trace instructions; critical helper entry/return and parent save/restore bytes are checked. No decoder or firmware changes.

All 12 nested `JSR` sites in `0x107DF0` target one of two bounded helpers. `0x107D4A–0x107D6A` contains 10 candidate instructions, 0 explicit ER4 references, 0 explicit SP references, 0 direct calls/traps, and a candidate terminal `RTS` at `0x107D6A`. `0x107DC6–0x107DEE` contains 11 candidate instructions, 0 explicit ER4 references, 0 explicit SP references, 0 direct calls/traps, and a candidate terminal `RTS` at `0x107DEE`. Both include MMIO polling branches; bounded instruction inventories do **not** prove the polls terminate, that all possible paths are enumerated, that saved stack slots are unaliased, or that hardware interrupts have no effect. The parent `0x107DF0` retains the Stage 9.23 structural ER4 save at `0x107DF4`, restore at `0x107F14`, and candidate return at `0x107F1C`.

**Conclusion:** The two nested helpers introduce no *explicit* ER4 or SP register accesses in the bounded candidate trace, strengthening (but not proving) caller-visible ER4 preservation. The candidate `[0x154,0x174)` 32-byte zero fill remains conditional on parent stack-slot integrity, return-path completeness, and runtime control-flow/memory assumptions. `0x154` remains outside the B0 capture's nominal runtime range. No firmware writes, no reachability promotions, no GitHub push.

**Windows:** `py stage924_nested_callee_audit.py --b0 hwdump_b0.bin --trace stage913_boot_report_windows.txt --out stage924_nested_callee_report.txt`

### Stage 9.24 Windows verification (2026-11-07)

**Windows verified by user:** `stage924_nested_callee_audit.py` produced the expected B0 SHA-256, 12 nested call sites, 10 candidate instructions at `0x107D4A` and 11 at `0x107DC6`, zero explicit ER4/SP references in both helpers, and matching bounded return instructions. Reproduction is not proof of hardware execution, MMIO poll termination, or saved-slot nonaliasing.

### Stage 9.25 — bounded CFG returns and explicit stack-write sites (2026-11-07)

**Local reference completed; Windows pending.** Read-only `stage925_stack_return_audit.py` checks Stage 9.13 trace bytes against the B0 capture and inventories candidate CFG edges, return sites, SP operands, and explicit stack stores. The script uses the trace's displayed `$+N` / `$-N` branch offsets relative to the instruction address (not next-PC), with direct JSR treated as returning to the next instruction; this assumption is not a runtime guarantee.

For `0x107DF0–0x107F1C`, 92 candidate instructions are CFG-reached, one RTS at `0x107F1C` is reached, zero early RTS, zero unresolved branch targets, zero outside-region branch targets, and 12 nested call sites. Explicit SP operand sites are entry `MOV.L ER3,@-ER7`, `STM.L (ER4-ER6),@-SP`, `LDM.L @SP+,(ER4-ER6)`, and exit `MOV.L @ER7+,ER3`. No parent-body explicit SP-relative store was found between save and restore. Nested helper effects and indirect aliases remain unproven.

For `0x108000–0x1082C4`, 159 candidate instructions are CFG-reached, one RTS at `0x1082C4` is reached, zero early RTS, zero unresolved branch targets, and zero outside-region targets. Explicit SP-related writes are `0x108012 MOV.L ER0,@ER7`, `0x10816E MOV.L ER0,@(8:16,ER7)`, and `0x1081CE MOV.L ER0,@(8:16,ER7)`. After saving registers, `0x108008 SUB.W #0xC,R7` allocates 12 bytes by changing only low R7; `0x1082B8 ADD.W #0xC,R7` reverses this on the modeled return path. Under no low-word wrap and stable SP assumptions, offsets 0 and 8 are inside that local 12-byte area, not the earlier ER4 save slot. **The exact ER4 save-slot ordering and complete alias proof are not established.** At `0x1082B4 BMI $+4`, the taken path reaches `0x1082B8` and the restore; the not-taken path reaches `0x1082B6 BRA $+0`, a self-loop. Thus static RTS reachability does not establish termination or that the function returns in practice.

**Verdict:** All reached RTS sites in the two bounded candidate CFGs occur after their matching LDM restores; no explicit stack-slot collision is apparent under modeled stack arithmetic. But unmodeled pointer aliases, low-word SP wrap, interrupts, and runtime branch outcomes prevent promotion of the candidate `[0x154,0x174)` eight-longword zero fill to hardware-proven memory contents. No firmware writes, decoder changes, reachability promotions, or GitHub push.

## Stage 9.26 - native C integration (Linux portable harness tested; Windows pending)

The Stage 9.18 native source baseline was recovered from the user's all-files bundle. A new reusable `drivekit_analysis.h` is included from `drivekit.c`; `drivekit analyze` dispatches before any device/SCSI initialization. The new read-only command accepts `--file`, `--out`, `--base`, `--entry`, and exclusive `--end` arguments. It reuses the existing H8S decoder and flow classifier to perform bounded candidate-CFG traversal and emit instruction bytes, decoded operands, return count, SP/ER4 reference counts, memory operand count, unresolved boundaries and out-of-bound edges. Direct calls are treated as fallthrough for this bounded inventory; callee effects are not summarized. No reachability promotions or decoder changes. No register-value propagation or alias proof is claimed.

Portable native C harness tested against B0 SHA256 8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603: `0x107DF0..0x107F1E` reaches 92 candidate instructions, 1 RTS, 0 unknowns, 4 SP operand sites and 9 ER4 operand sites; `0x108000..0x1082C6` reaches 159 candidate instructions, 1 RTS, 0 unknowns and 12 SP operand sites. Windows compilation and integration remain unverified. These are structural findings, not hardware execution or proof of the proposed low-memory zero-fill.

## Stage 9.27 - native C concise CFG overview (Linux portable harness tested; Windows pending)

- Extends the native `drivekit analyze` command with optional `--overview`. Existing full instruction listing remains the default; no decoder or firmware changes.
- The overview emits in-range backward and self-loop CFG edges and compact metrics for candidate calls, conditional branches, returns, and reachability. This is a *syntactic CFG inventory*, not dominance-based natural-loop recognition or hardware execution proof.
- Local B0 reference (SHA256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`): `0x108000` reaches 159 candidate instructions, 1 RTS, 12 backward edges and 1 self-loop (`0x1082B6`); `0x107DF0` reaches 92, 1 RTS, 12 call sites, 3 backward edges and 0 self-loops.
- The full default report still emits individual instruction lines. The overview does not assert ER4 preservation, memory contents, stack alias safety, or that polling loops terminate.
- Windows validation is pending. No firmware writes, no decoder changes, no GitHub push.

## Stage 9.28 — native C basic-block graph (2026-11-07)

`drivekit analyze ... --overview --blocks` now emits candidate basic-block starts,
exclusive ends, instruction counts, and branch/fallthrough edges from the existing
bounded H8S CFG. `--blocks` can also be used without `--overview`.
No device access or firmware writes. Existing output without `--blocks` remains
unchanged apart from the Stage version label.

Portable GCC harness against B0 SHA256 `8dbac55532258ee9e8c40cdeea737e9111dcc2082868690ffdb1cb4ac4cfe603`:
- `0x108000..0x1082C6`: 159 candidate instructions, 29 blocks, 42 edges, 0 unresolved block edges.
- `0x107DF0..0x107F1E`: 92 candidate instructions, 23 blocks, 28 edges, 0 unresolved block edges.

These are *candidate static CFG* edges; indirect destinations, dynamic execution,
interrupts, and hardware reachability are not proven. Windows build pending user verification.

## Stage 9.29 — Native C bounded call cross-references

The native `drivekit analyze` command now accepts `--xrefs`, which emits a
`CALL_XREF_BEGIN` / `CALL_XREF_END` section containing reached H8S `BSR` and
`JSR` call sites, direct destinations where encoded, explicitly unknown
indirect destinations, and a per-target site-count summary. It operates only
within the caller-specified bounded candidate CFG; it does not recursively
disassemble callees or claim that a syntactic target is a validated function
entry. `OUTSIDE_BOUNDED_REGION` is relative to the chosen function window,
not necessarily outside the firmware image. `--overview` and `--blocks` remain
independent options.

Portable GCC regression on B0 (`0x100000` image base):

- `0x107DF0..0x107F1E`: 92 candidate instructions, 23 blocks, 12 direct
  calls: ten to `0x107D4A` and two to `0x107DC6`; zero unknown indirect calls.
- `0x108000..0x1082C6`: 159 candidate instructions, 29 blocks, zero calls.

These are candidate static disassembly observations, not hardware execution.
No firmware writes, decoder behavior changes, or GitHub publishing.

## Stage 9.30 — native bounded call-graph traversal (2026-11-07)

Implemented `analyze --callgraph` in `drivekit_analysis.h`, with configurable
`--max-depth`, `--max-functions`, and `--callee-window`. A visited/queued
function-entry set prevents duplicate function analysis. Direct call sites
are collected from reached candidate CFG instructions, and queued callees
are analyzed with the existing native decoder. Output includes `GRAPH_FUNCTION`,
`GRAPH_CALL`, and graph summary counters. The default callee window is 0x100
bytes, a **syntactic bound**, not an inferred function end.

Linux portable C test on the B0 dump, starting at 0x107DF0 with depth 2,
8-function limit, and 0x100-byte callee window: 3 candidate functions,
12 direct call edges, 0 limited edges; reached instruction counts 92,
10 (0x107D4A), and 11 (0x107DC6); 0 unknown instructions in these regions.
These are offline candidate CFG findings, not runtime execution or verified
function boundaries. Indirect calls remain unresolved; firmware is never
written. Windows verification pending.

## Stage 9.31 — Native C candidate function boundary discovery (2026-11-07)

**IMPLEMENTED / LOCAL GCC TEST:** `drivekit_analysis.h` now supports `--boundaries` with `--callgraph`. For each discovered callee, a bounded native C CFG pass calculates the maximum end-exclusive address of reached decoded instructions and records candidate RTS, unknown decode/semantics, and escaped-edge counts. If an RTS is reached and both unknown and escaped counts are zero, the graph analyzes the narrowed candidate extent; otherwise it retains the search window and marks the boundary uncertain. The explicit root `--end` remains authoritative.

B0 local regression, `--entry 0x107DF0 --end 0x107F1E --callee-window 0x100`: `0x107D4A` candidate end `0x107D6C` (10 reached, 1 RTS, 0 unknown, 0 escaped); `0x107DC6` candidate end `0x107DF0` (11 reached, 1 RTS, 0 unknown, 0 escaped). Graph totals unchanged: 3 functions, 12 call edges, 0 limited edges. Existing Stage 9.30 behavior remains available without `--boundaries`.

**LIMITATIONS:** `CLOSED_CANDIDATE` means closed only under the bounded syntactic CFG model. Indirect jumps, overlapping instructions, interrupt effects, entry aliases, and actual runtime behavior are not proven. A max-reached-instruction end is not a formal function size. Windows verification pending.

## Stage 9.32 — native C function index (2026-11-07)

Added `--index` to the native `analyze --callgraph` path. It emits an
address-sorted `FUNCTION_INDEX_BEGIN` / `FUNCTION_INDEX_END` section with
entry, candidate end-exclusive, span, discovery depth, incoming/outgoing direct
call-site counts, distinct discovered callers/callees, and status. The root
is `SUPPLIED_ROOT`; discovered callees are `CLOSED_CANDIDATE` or
`OPEN_OR_UNCERTAIN` according to the bounded candidate CFG audit. `--index`
performs the boundary audit for discovered functions even without the separate
`--boundaries` report option. The original graph traversal order is retained.

Portable C regression on B0 with root `0x107DF0` found three sorted entries:
`0x107D4A` size `0x22` (10 incoming calls), `0x107DC6` size `0x2A`
(2 incoming calls), and `0x107DF0` size `0x12E` (12 outgoing calls).
Graph compatibility remains three functions, twelve call edges, zero limited
edges. This index does not prove exact function boundaries, execution, or
whole-firmware coverage. No decoder changes or firmware writes.

### Stage 9.33 experimental symbol annotations

The optional `drivekit_symbols.txt` file is looked up beside the executable.
Use `--symbols PATH` to select another file or `--no-symbols` to disable
loading. Use `--symbol-scope B0_HW_DUMP_0x100000` to select a scoped group;
for `hwdump_b0.bin` with `--base 0x100000`, that scope is selected by default.
Other firmware images require explicit scope selection, even when a file is
present. The file uses five whitespace-separated fields per record:
`ADDRESS NAME KIND CONFIDENCE SCOPE`, preceded by `[scope SCOPE]`.
Semicolon comments and `#` lines are allowed. Unknown/other scopes are ignored;
duplicate addresses in the selected scope and malformed records are errors.
The loader does not verify that labels correspond to the actual firmware bytes.

Labels are read-only report annotations (`FUNCTION_SYMBOL`, `CALL_TARGET_SYMBOL`,
and `SYMBOL` suffixes in graph lines). They do not change CFG discovery,
function boundaries, decoder output, or write/flash behavior. Numeric addresses
are always retained. Region/boundary/MMIO labels are not promoted to functions.
