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
| Next: Stage 9.17 | Which exact memory addresses feed `MEMORY_READ` values written to `0xFF3FF0C0`? | Bounded register-pointer/source tracking, joins/aliases, unknowns retained; no decoder rewrite or promotions |
| High | What are the FF3F/FF42 peripheral functions? | Hardware docs, independent firmware references, or controlled measurements; do not label from address pattern alone |
| High | Does runtime `0x1058DC` execute raw B0 offset `0x0058DC`? | Hardware mapping proof or independently validated runtime translation |
| High | Which boot branches actually reach `0x1000A6`? | Exact branch predicates, side effects, and eventually runtime evidence |
| High | Does the Kernel return to `0x1000AA`? | Runtime trace or sufficiently complete semantic analysis |
| High | Can ER3 call sites `0x400140/0x400166/0x40018C` be promoted? | Proven complete caller path effects plus external mapping and callee effects |
| Later | Can DriveKit read arbitrary live addresses, not just sequential B0? | Investigate supported read-only diagnostics; establish seekability, state requirements, side effects and safety on actual hardware |
| Later | Can an editor overlay static disassembly, xrefs, live values, and annotations? | Separate UI/transport design; maintain provenance and image/version identity |
| Later | Kernel model-ID comparison / generation gates | Exact-byte path validation; no speculative patching |

## 10. Updating this document

For each new stage, add: **goal; exact input hashes; command; tool/source version; bounded region; raw report filename; numerical results; notable exact addresses/bytes; proof level; remaining unknowns; regression against prior stage**. Keep a chronological changelog and correct mistakes explicitly rather than quietly overwriting the historical claim. If a later hardware measurement contradicts static analysis, preserve both with the explanation.

### Changelog

- **2026-11-07 — README reconciliation:** Compared the supplied 934-line `DriveKit_README_disassembler_stage8_6(1).md` against the Stage 9.16 evidence ledger. Added B0 acquisition protocol details, extractor chunk sizes and observed timing, decoded-image safety, historical `open_drive()` issue, source manuals/credits, and the important cross-model `0xFF3FF000` Crypto/DMA attribution caveat. Preserved the README as the user-facing source; no code, firmware, or GitHub changes.

- **2026-11-07 — Initial `DISASM.md`:** Consolidated existing README B0 address mapping and documented Stage 8.6–9.16 investigations, ER3 preservation constraints, boot entry/Kernel call, FF42/FF3F MMIO, complete 42-site Stage 9.16 provenance table, reproduction commands, and Stage 9.17 backlog. No firmware or decoder changes.

### Related documentation

- `README.md` — DriveKit usage, hardware support, B0 commands, flashing precautions, and user-facing workflows.
- `README_STAGE*.txt` in stage archives — implementation notes for individual audits.
- Stage-specific raw reports — authoritative per-site output for each exact firmware image.
- `DISASM.md` — evolving analysis, conclusions, limitations, and investigation roadmap.
