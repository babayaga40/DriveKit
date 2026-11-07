# DriveKit Renesas register comparison — Stage 9.34 evidence pass

## Sources

- Renesas **H8S/2600 Series, H8S/2000 Series Software Manual**, REJ09B0139-0400 Rev.4.00: https://www.renesas.com/en/document/mah/h8s2600-series-h8s2000-series-software-manual
- Renesas **H8S/2368 Group Hardware Manual**, REJ09B0050-0600 Rev.6.00: https://www.renesas.com/en/document/mah/h8s2368-group-hardware-manual

## Comparison

The software manual documents architectural registers and instruction encoding, not a universal device-specific memory-mapped register map. The H8S/2368 manual's section 3, figure 3.11 (H8S/2360F example), places on-chip I/O near `0xFFFC00` through `0xFFFFFF` (with gaps, device/mode dependent). This does not match the B0 disassembly's full 32-bit operands `0xFF3F1000`, `0xFF3F1008`, `0xFF3F100B`, `0xFF3F1018`, `0xFF3F1028`, `0xFF3F102A`, and `0xFF3FF000`.

**Result:** zero B0 addresses have been verified as named Renesas on-chip registers. The exact Pioneer MCU/device and external bus/address mapping remain unproven. It would be misleading to name these as e.g. `P1DDR` or `SYSCR` based only on a family manual. Existing neutral names are retained, with `MMIO_CANDIDATE` classification.

The 16-bit low-address register candidates in the third scope are also retained as observations, not promoted to Renesas register names. Their address-extension semantics have not been established.

## What would allow promotion

Exact MCU/ASIC identification, the corresponding hardware manual and revision, a matching register address under the established operating mode, and access-width/bit-field corroboration. If the address is on a Pioneer ASIC, a Renesas on-chip peripheral label is inappropriate regardless of similar low bits.

No firmware or C code was changed. This pass updates the human-readable evidence comments in `drivekit_symbols.txt` only.
