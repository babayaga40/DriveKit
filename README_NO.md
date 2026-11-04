# DriveKit v1.0

> **Norsk utgave (bokmål).** Oversatt fra den engelske README-en. Kommandoer, kode, måleverdier og teststatus er beholdt fra originalen.
### Verktøykasse for forskning på optiske stasjoner
**av BabaYaga / Razor 1911 (c) 2026**

DriveKit er en samlet verktøykasse for forskning på optiske stasjoner og lagringsenheter, særlig Pioneer BD-R/BD-RE-stasjoner. Prosjektet retter seg mot Windows og Linux. Funksjonene er samlet i ett program og velges med kommandoer i terminalen.

---

## 📖 Brukerveiledning

Er du ny i DriveKit? Se **[USERGUIDE.md](USERGUIDE.md)** for trinnvise instruksjoner om fastvareoppdatering, filnavn, automatisk gjenkjenning av protokoller og feilsøking. Denne veiledningen er foreløpig på engelsk.

---

**Milepæler i november 2026:**
- DriveKit gjennomførte en vellykket **oppgradering fra før til etter sperredatoen** på en **Pioneer BDR-XD07U (SAT 8D31 / ID05)**: fra 1.04 til 1.06 med den nye metoden der kjernen sendes i fire overføringer. Stasjonen svarte `SCSI GOOD`, og en etterfølgende `INQUIRY` bekreftet fastvare 1.06.
- DriveKit klarte også å **nedgradere fra etter til før sperredatoen**: tilbake til 1.04 med modifisert kjerne (`--patch`). Stasjonen svarte `SCSI GOOD`, og `INQUIRY` bekreftet fastvare 1.04 etterpå.
- En **oppdatering innenfor perioden etter sperredatoen** fungerte også: 1.06 → 1.05 med samme overføringsmetode. `SCSI GOOD` og etterfølgende `INQUIRY` bekreftet versjon 1.05.
- Kommandoen **`scankey`** ble lagt til. Den finner nøkkelen for å åpne oppdateringsmodus direkte i dekryptert Normal-fastvare, uten tilkoblet stasjon. Den fant den kjente XD07-nøkkelen og avdekket et avvik for `S8800601.153`.

Alle de tre resultatene er bekreftet på testet maskinvare. Det betyr ikke at metoden fungerer på alle Pioneer-stasjoner.

Se [Bekreftet fungerende](#-confirmed-working), [Fastvareprotokoll](#flash-protocol) og [Validering av KernelFront-endringen](#kernelfront-patch-validation).

Reverseringen av teknologien ble gjort med flere metoder:

**Protokoll før sperredatoen / crossflash:** greg1wto skaffet verktøyene vi trengte for å analysere USB-trafikk med Wireshark/USBPcap. Sammen med BabaYagas analyse av Pioneers offisielle oppdateringsprogrammer avdekket dette hele protokollen for skriving i to omganger, strukturen til utløserdataene og formatet på opplåsingsnøkkelen.

**Protokoll etter sperredatoen:** De offisielle oppdateringsprogrammene (`BDR-XD06J-UHD`, `BDR-XD07UHD`) ble analysert i IDA Pro ved å lese x86-assembler, uten dekompilering. Slik ble sesjonsnøkler, buffer-ID-er og adresser, stasjonsspesifikke nøkler og sekvensen for å åpne Engineering Mode avdekket.

**Fastvaren inne i stasjonen:** MrPenguin analyserte H8S/2600-assembler fra `READ BUFFER 0xB0`-minnedumper. Dette avslørte en løpende XOR-strømkryptering og betingelsene som styrer tilgangen til Engineering Mode.

**KernelFront-kryptering:** MattJackson reverserte XOR-/rotasjonsalgoritmen som beskytter Pioneers H8S/2600-kjernefiler. Dermed ble det mulig å lese og endre selve kjernen.

---

## ⚠️ Risiko

Verktøyet kommuniserer direkte med den optiske stasjonen gjennom SCSI/ATAPI-kommandoer. Det kan **skrive ny fastvare** og **aktivere produsentens service-/kjernemodus**. Feil stasjon, inkompatibel fastvare eller feil kommando kan gjøre stasjonen **ubrukelig**.

- Kontroller alltid stasjonsbokstaven før du oppdaterer fastvaren eller låser opp stasjonen.
- Ikke bruk `--force` uten å forstå hvilke kompatibilitetskontroller du omgår.
- Kjør programmet som administrator i Windows.
- Etter at skrivingen er utløst, må du **ikke koble fra stasjonen eller bryte strømmen** mens den oppdaterer seg internt. Et `GOOD`-svar betyr ikke at hele prosessen er ferdig.
- En plate i stasjonen kan hindre opplåsing. Ta alltid ut platen først.

---

## Forskning på maskinvaren

Pioneer Blu-ray-stasjoner bruker prosessoren **Renesas H8S/2600**, en 16-/32-biters CISC-prosessor. Dette ble bekreftet ved å dekode en `READ BUFFER 0xB0`-dump og tolke innholdet som H8S/2600-assembler (MrPenguin).

**Fastvaren bruker også en løpende strømkryptering.** Analyse av BDR-S12U (MrPenguin, pypcode/Ghidra) viste blant annet:
- En XOR-nøkkel som forskyves over flere byte, styrt av en lineær kongruensgenerator: `currentKey = (currentKey * 16807) % 0x7FFFFFFF`.
- En krypto-/DMA-enhet ved `0xFF3FF000` håndterer skriving til flashminnet og kontroll av nøkler og sertifikater.
- Versjonskontrollen finnes inne i den **krypterte** binære fastvaren. Å endre tekstfeltet i filhodet er derfor ikke nok.
- Fastvaren kobler bufferen for opplåsingsdata til minneadressen `0xA00000`.

**Format på opplåsingsnøklene – BIG ENDIAN (bekreftet gjennom MrPenguins H8S/2600-analyse):**
```
H8S/2600 assembly: CMP.L #0x9a782361:32, ER0
→ Universal key 0x9A782361 must be sent as bytes: 9A 78 23 61
→ UD04 key     0x426623FD must be sent as bytes: 42 66 23 FD
→ XD08U key    0xA44F2F55 must be sent as bytes: A4 4F 2F 55
```
DriveKit lagrer nøklene som little-endian DWORD-verdier (`0x6123789A`). Når verdien sendes i little-endian-rekkefølge, blir bytefølgen på forbindelsen riktig: `9A 78 23 61`.

**Valg av nøkkel avhenger av både stasjon og protokoll.** Den såkalte universelle nøkkelen (`0x6123789A`, sendt som `9A 78 23 61`) fungerte i tidligere tester med SAT 9330/9331. Ved den bekreftede nedgraderingen av BDR-XD07U SAT 8D31 / ID05 ble `0xFF8A27B1` (byte `B1 27 8A FF`) brukt både ved **opplåsing og fullføring**. Ikke anta at den universelle nøkkelen fungerer for alle `crossflash`-metoder. Sammenlign modell, nøkkel og hele utløserblokken på 256 byte med et opptak som er kjent for å fungere.

**Finne opplåsingsnøkkelen direkte i fastvaren (`scankey`):** Programmet leter i *dekryptert Normal-fastvare* etter et gjenkjennelig instruksjonsmønster i H8S/2600-koden. Deretter følger det en greninstruksjon til nøkkelsammenligningen og henter ut nøkkelen på fire byte. Metoden bygger på MattJacksons analyse av hvordan fastvaren godtar oppdateringskommandoer. Dette er **ikke** nøkkelen som dekrypterer Normal-filen. Resultatet vises både som byte på forbindelsen og som little-endian DWORD. Ett gjenkjent mønster beviser ikke at en gitt flashprotokoll er trygg for stasjonen. Se [kommandoen scankey](#scankey-command).

**Viktig avvik i nøkkeltabellen:** I den dekrypterte filen `S8800601.153` fant `scankey` bytefølgen `94 E0 F2 5C` (LE DWORD `0x5CF2E094`), mens den eksisterende tabellen brukte `0x6123789A`. Dette er et **avvik**, ikke en ny nøkkel som er bekreftet på maskinvare. Den gamle verdien tilsvarer konstanten `9A 78 23 61` i gjenkjenningsmønsteret, så det er mulig at akkurat denne konstanten tidligere ble hentet ut ved en feil. Det betyr ikke at alle tidligere vellykkede bruksområder for `0x6123789A` var feil. Sammenlign med et kjent, fungerende trafikkopptak før flashing.

**Slik skiller DriveKit mellom fastvare før og etter sperredatoen:** Før den spesielle `hwdump`-sekvensen prøver programmet vanlig `READ BUFFER 0xB0`:
- Data kommer tilbake → stasjon med **fastvare før sperredatoen** (27. desember 2022); H8S/2600-koden er tilgjengelig.
- Feilkode 05/24 → stasjon med **fastvare etter sperredatoen**, slik den vanlige testen oppfatter den. En egen `hwdump`-sekvens kan likevel åpne `0xB0`-lesing på testede stasjoner.

**Pioneers kontrollsumalgoritme (funnet ved analyse av det offisielle oppdateringsprogrammet i IDA Pro):**
```c
uint32_t checksum = 0;
for (uint32_t offset = 0x10000; offset < filesize; offset += 4) {
    checksum -= *(uint32_t*)(firmware + offset);
}
// Lagret i firmware[0x8000]
// Datoendringen ved 0x130 er UTENFOR kontrollsumområdet – kan endres!
```

**KernelFront-kryptering (reversert av MattJackson):**

Pioneers kjernefiler bruker en XOR-/rotasjonsoperasjon for hvert 32-biters ord. Både nøkkeltabellen og den krypterte kjernen ligger i samme fil:

```
file[0x000:0x200]    — 512-byte ASCII envelope header
file[0x200:0x1200]   — 1024 × LE DWORD key table
file[0x1200:0x11200] — 65536-byte encrypted payload (16384 dwords)
```

Dekryptering av hvert 32-biters ord med indeks `i`:
```c
DWORD key = keytable[i % 1024];
DWORD plaintext = ROR32(ciphertext ^ key, key & 31);
```

Den dekrypterte kjernen inneholder blant annet:
- **Generasjonsmarkør** på **byteposisjon `0xFE`** i den dekrypterte filen, ikke DWORD-indeks `0xFE`. Den bekreftede endringen for 1.04 setter `plain[0xFE]` fra `0xFF` til `0x01`.
- **Kompensasjonsverdi for kontrollsum** ved byteposisjon `0x1020` (DWORD-indeks `0x408`). Summen av alle de 16 384 big-endian 32-biters ordene i den dekrypterte kjernen på 64 KiB skal bli `0x00000000`.

For den bekreftede BDR-XD07U 1.04-endringen justerer DriveKit kontrollsumordet fra `0xB367511D` til `0xB3684F1D` og krypterer kjernen på nytt. **Bruk den testede `crossflash --patch`-metoden ved flashing.** Resultater fra frittstående `decryptkernel --patch` må kontrolleres for riktig byteposisjon og riktig rekryptert filformat før de brukes.

### Validering av KernelFront-endringen <a id="kernelfront-patch-validation"></a>

Den vellykkede nedgraderingen til BDR-XD07U 1.04 ga følgende resultat:

```text
plain[0xFE]        = 01
BE32(plain+0x1020) = B3684F1D
BE32 body sum      = 00000000
Encrypted kernel   = 0x11200 bytes
SHA-256            = 4d1fa7cbae04b7db36689f4539d45ff8e01c72a7c8341e762224f2a76a670b9a
```

SHA-256-verdien til den krypterte kjernen stemte **byte for byte** med kjernen som ble rekonstruert fra Heisenbergs vellykkede USB-opptak av nedgraderingen. En kontrollsum på null beviser ikke alene at markøren er endret på riktig sted; også en feilaktig endring kan kompenseres til null. Hashverdien gjelder bare akkurat denne modifiserte 1.04-kjernen.

---

## Flashprotokoll <a id="flash-protocol"></a>

**Avgrensning:** Eksemplene på kryssing av sperredatoen kommer fra BDR-XD07U / SAT 8D31 / ID05. De er ikke universelle Pioneer-protokoller. Offsetene i `WRITE BUFFER` er posisjoner i protokollens buffere, ikke dokumenterte fysiske NAND-adresser.

### Sekvens før sperredatoen (bekreftet fungerende – `cmd_flashfw_precut`):
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

### Crossflash: Ny overføringssekvens – målfastvare etter sperredatoen (PRE→POST eller POST→POST):
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
**Bekreftet:** PRE→POST (1.04→1.06) fra Heisenbergs opptak og DriveKit; POST→POST (1.06→1.05) bekreftet med DriveKit i november 2026.

### Crossflash: Nedgradering – stasjon etter sperredatoen → eldre fastvare (bekreftet med DriveKit):
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

**Tidspunkt for fullføring:** I Heisenbergs vellykkede oppgraderingsopptak kom `commit` omtrent **62,5 ms** etter siste Normal-overføring. Neste registrerte kommando kom omtrent **12,61 sekunder etter commit**. Også den vellykkede DriveKit-nedgraderingen sendte `commit` umiddelbart etter Normal-overføringen. Ventetiden på rundt 13 sekunder gjelder altså **etter** fullføringskommandoen, ikke før. Tidligere feil av typen `04/4C/02` oppstod med andre sekvenser og beviser ikke at ventetid alene var årsaken.

**Oppbygning av kjernefilen (totalt `0x11200` byte) – flatt binærformat for nyere kjerne:**
```
file[0x000000:0x000200]  = 512-byte ASCII envelope header      → WRITE BUFFER off=0x000000 len=0x0200
file[0x000200:0x008200]  = 32KB encrypted payload body1        → WRITE BUFFER off=0x001200 len=0x8000
file[0x008200:0x010200]  = 32KB encrypted payload body2        → WRITE BUFFER off=0x009200 len=0x8000
file[0x010200:0x011200]  = 4KB tail                            → WRITE BUFFER off=0x011200 len=0x1000
```
Merk: Offsetene i `WRITE BUFFER` er ikke det samme som filposisjoner, og er heller ikke dokumenterte fysiske NAND-adresser. Sluttdelen er `0x1000` byte, ikke `0x1200`. Filområdene er bekreftet med SHA-256-sammenligning mot Heisenbergs ID05 USB-opptak.

**Håndtering av filhodet (testet SAT 8D31 / ID05):** Heisenbergs oppgraderingsopptak hadde en annen første blokk på `0x200` byte enn ASCII-hodet i kildefilen. DriveKit klarte likevel å oppgradere 1.04 → 1.06 ved å sende det originale ASCII-hodet uendret. De eksakte byteverdiene fra opptaket er derfor ikke nødvendige i denne testede metoden. Det er ikke bevist at vilkårlige filhoder godtas eller at dette gjelder andre plattformer. Et tidligere forsøk med nuller i de siste `0x1000` byte feilet med `CHECK CONDITION`; den faktiske sluttdelen fra `file[0x10200:0x11200]` fungerte.

**Normal-filformat (oppgradering til fastvare etter sperredatoen):**
```
[0x000000 - 0x1D65FF]  = NAND image prefix (sent first in upgrade)
[0x1D6600 - 0x1E65FF]  = continuation / ECC region
```

---

## ✅ Bekreftet fungerende <a id="-confirmed-working"></a>

**Crossflash/nedgradering etter sperredatoen (14. september 2026):**
- Stasjon: BDR-XD08U (SAT 9331 ID05)
- Bekreftet: 1.04 ↔ 1.02, crossflash i begge retninger med én kommando.
- Protokoll: NAND-skriving i to omganger med ECC-sluttdel.
- Nøkkel: `0x6123789A` (universell).

**Nedgradering før sperredatoen (16. september 2026):**
- Stasjon: BDR-XD07U (SAT 8D31 ID05)
- Bekreftet: nedgradering fra 1.04 til 1.03.
- Protokoll: én overføring av hele filen fra offset 0.
- Modellstreng: `PIONEER BDR-BDS7` (fra `g_mdl_map[0x8D31]`).
- Nøkkel: `0x6123789A` (universell).

**Crossflash fra PRE til POST (november 2026, bekreftet med DriveKit):**
- Stasjon: BDR-XD07U (SAT 8D31 ID05), fastvare 1.04 (før sperredatoen).
- Bekreftet: **1.04 → 1.06** med `drivekit crossflash E --file xd07_kernel_106_bin --file2 xd07_normal_106.bin` (uten `--patch`).
- Protokoll: ny sekvens – Normal-prefiks `0x1D6600` → fire kjerneoverføringer → hele Normal-filen `0x1E6600` → umiddelbar `commit`.
- Oppbygningen av kjernefilen ble bekreftet med SHA-256 mot Heisenbergs ID05 USB-opptak; begge hoveddelene og sluttdelen stemte.
- Nøkkel for opplåsing/fullføring: `0xFF8A27B1` (sendt som `B1 27 8A FF`).
- `Commit` ga **GOOD**; etterpå viste `drivekit info E` og `INQUIRY` **fastvare 1.06**, datert `24/10/09`.
- Protokollen ble først fanget opp i Heisenbergs bdrflashpp2-opptak og deretter gjenskapt uavhengig med DriveKit.

**Crossflash fra POST til POST (november 2026, bekreftet med DriveKit):**
- Stasjon: BDR-XD07U (SAT 8D31 ID05), fastvare 1.06 (etter sperredatoen).
- Bekreftet: **1.06 → 1.05** med `drivekit crossflash E --file xd07u_kernel_1.05.bin --file2 xd07u_normal_1.05.bin`.
- Protokoll: ny sekvens med de samme fire kjerneoverføringene som ved oppgradering (`target_is_postcut=1`).
- `Commit` ga **GOOD**; etterfølgende `INQUIRY` viste **fastvare 1.05**, datert `23/01/06`.

**Crossflash fra POST til PRE (november 2026, bekreftet med DriveKit):**
- Stasjon: BDR-XD07U (SAT 8D31 ID05), fastvare etter sperredatoen.
- Bekreftet: **nedgradering til 1.04** med `drivekit crossflash E --file S8D31050.104 --file2 S8D31051.104 --patch`.
- Endret kjerne: `0x11200` byte; SHA-256 identisk med Heisenbergs vellykkede nedgraderingsopptak.
- Protokoll: kjerne i tre sammenhengende blokker → én full Normal-overføring → umiddelbar `commit`.
- Nøkkel for opplåsing/fullføring: `0xFF8A27B1` (sendt som `B1 27 8A FF`).
- `Commit` ga **GOOD**; etterpå viste både `drivekit info` og `INQUIRY` **fastvare 1.04**, datert `22/05/31`.


---

## Stasjonsidentifikasjon og opplåsingsnøkler

DriveKit har interne oppslagstabeller for Pioneer-stasjons-ID-er, plattform- og kjerneidentifikatorer, interne modellnavn, opplåsingsnøkler og nøkler som starter selve fastvareskrivingen. Tabellene er omfattende og vedlikeholdes i **DriveKits kildekode**, som er den autoritative referansen.

For støttede kombinasjoner av stasjon og protokoll velger DriveKit modellstreng og riktig nøkkel automatisk. Nøkkelvalget avhenger av **både stasjon og protokoll**; opplåsings- og fullføringsnøkler er ikke nødvendigvis ombyttbare. Valget `--key` er beregnet på avansert forskning og testing, ikke vanlig bruk.

I den bekreftede BDR-XD07U **SAT 8D31 / ID05**-prosedyren ble LE DWORD `0xFF8A27B1` brukt til både opplåsing og fullføring, sendt som `B1 27 8A FF`. `scankey` fant den samme nøkkelen uavhengig i dekryptert XD07 Normal 1.06 på offset `0x3BFEC`. Dette er et bekreftet eksempel, **ikke** en universell Pioneer-nøkkel.

Når en dekryptert Normal-fil finnes, bør nøkkeltabellen brukes som en kontroll, ikke som eneste sannhetskilde. `scankey` rapporterer avvik uten å erstatte verdier automatisk. En ny nøkkel må fortsatt bekreftes med maskinvare eller trafikkopptak for nye modeller og protokoller.

---

## Tidslinje for sperredatoen

- Oktober 2022 – de siste trygge versjonene (XD08 1.01 fra 11. oktober 2022).
- 27. desember 2022 – Pioneer innfører fastvare etter sperredatoen på nye stasjoner.

**Siste trygge fastvareversjoner før sperredatoen:**
- BDR-XD08U — **1.01** (2022-10-11), kernel ID05
- BDR-XD08U — **1.00** (2022-04-03), kernel ID05
- BDR-XD07U — **1.04** (2022-05-31), kernel ID05 ✅ UHD capable
- BDR-XD06U — **1.11** ✅ UHD capable
- BDR-XD05 — **3.01 / 2.10 / 1.21**

---

## Kompilering

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

## Bruk

```
drivekit <command> <drive_letter> [options]
```

### Valg og parametere

| Parameter | Forklaring |
|---|---|
| `--file name` | Kjernefil med fastvare |
| `--file2 name` | Ekstra inn- eller utfil, avhengig av kommando |
| `--file3 name` | Tredje filnavn (reservert / eldre ekstra Normal-overføring) |
| `--force` | Hopp over kompatibilitetskontroller og spørsmål |
| `--nounlock` | Hopp over opplåsingen |
| `--key 0x6123789A` | Overstyr opplåsingsnøkkelen |
| `--bufid 0xF4` | Buffer-ID for rådump |
| `--patch` | Endre generasjonsmarkøren (`decryptkernel`) |

### Kommandoer

| Kommando | Forklaring |
|---|---|
| `info` / `inquiry` | Detaljert stasjonsinformasjon og dekoding av serienummer |
| **`flash`** | **Skriv ny fastvare – anbefalt (tidligere `crossflash`)** |
| `crossflash` | Alternativt navn for `flash` (beholdt for kompatibilitet) |
| `flash_legacy` | Eldre kommando med automatisk gjenkjenning |
| `flashfw` | Eldre flashkommando med mer omfattende søkelogikk |
| `unlock` | Lås opp servicemodus |
| `e5test` | Test flagget for Engineering Mode |
| `kernellimbo` | Gå inn i kernel-limbo-modus |
| `probevendor` | Undersøk produsentspesifikke kommandoer `0xC0–0xFF` |
| `rawdump` | Les ut rådata med `READ BUFFER` |
| `checkcompat` | Kontroller kompatibilitet for crossflash |
| `sendcdb` | Send en rå SCSI-CDB-kommando |
| `resetnormal` | Forsøk å forlate kjerne-/servicemodus |
| `hwdump` | Hent H8S/2600-kjernen fra RAM via `0xB0`; fungerer både før og etter sperredatoen |
| `xordiff` | Sammenlign to krypterte filer med XOR for å finne versjonsbyte |
| `patchfw` | Endre ASCII-filhodet for å etterligne en annen versjon |
| `decryptkernel` | Dekrypter KernelFront-kjernen til rådata for IDA. `--patch` endrer også generasjonsmarkøren (`0xFF→0x01`) og beregner kontrollsummen på nytt |
| `decodenormal` | Dekrypter Normal-fastvaren og rapporter UHD-egenskaper |
| **`scankey`** | **Finn oppdateringsnøkkelen i dekryptert Normal-fastvare og sammenlign med den interne tabellen** |

### Kommandoen scankey <a id="scankey-command"></a>

Hent ut **opplåsingsnøkkelen for oppdateringsmodus** fra en *dekryptert* Pioneer Normal-fil. Du trenger ikke en optisk stasjon, og ingen fastvare blir skrevet. Bruk først `decodenormal` hvis filen fortsatt er kryptert.

```powershell
.\drivekit scankey --file xd07_normal_106.bin_decoded.bin
.\drivekit scankey --file S8800601.153_decoded.bin
```

**XD07 Normal 1.06 – nøkkelen som ble funnet, stemmer med den kjente ID05-nøkkelen:**

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

**`S8800601.153` – avvik oppdaget:**

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

Skanneren finner en gjenkjennelig **kodefunksjon som kontrollerer oppdateringsnøkkelen**, ikke bare fire tilfeldige byte. Nøkkelen er forskjellig fra nøkkelen som brukes til å dekryptere Normal-filen. Ett entydig funn er sterk dokumentasjon på hvilken verdi som ligger i koden, men beviser ikke at stasjonen vil godta en bestemt opplåsings- eller fullføringsblokk. **Ikke skriv fastvare automatisk med en ny nøkkel uten å kontrollere stasjons-ID, protokoll og kjente, vellykkede trafikkopptak.** En manglende tabellverdi er noe annet enn et avvik.

### Kommandoen flash (anbefalt)

```
drivekit flash E --file kernel.bin --file2 normal.bin
```

DriveKit bruker stasjonsidentifikasjon, oppførselen til `READ BUFFER 0xB0` og datoen til målfastvaren for å velge riktig crossflash-sekvens, med forbehold om kompatibilitetskontroll:
- **Målfastvare etter sperredatoen** (`target_is_postcut=1`) → ny sekvens (Normal-prefiks → fire kjerneblokker → hele Normal-filen → `commit`). Brukes ved PRE→POST og POST→POST.
- **Målfastvare før sperredatoen** (`target_is_postcut=0`) → nedgraderingssekvens (tre kjerneblokker → Normal → `commit`). Brukes ved POST→PRE.

Modellstrengen identifiseres automatisk med `READ BUFFER 0xA0` og tabellen `g_mdl_map`.
Opplåsings- og fullføringsnøkler velges ut fra stasjonen og protokollen. I den bekreftede SAT 8D31 / ID05-nedgraderingen sendes `B1 27 8A FF` (`0xFF8A27B1` som LE DWORD).

### Kommandoen flash_legacy

```
drivekit flash_legacy E --file kernel.bin --file2 normal.bin
```

Eldre kommando med automatisk gjenkjenning. Bruk heller `flash`.

### Kommandoen xordiff

```
drivekit xordiff --file fw_new.bin --file2 fw_old.bin
```

Utfører XOR mellom to krypterte fastvarefiler. Posisjoner som ikke blir null, kan avsløre versjons- og datobyte.
Ingen stasjon nødvendig.

### Kommandoen patchfw

```
drivekit patchfw --file fw_ref.bin --file2 fw_target.bin
```

Endrer ASCII-filhodet i `fw_target` slik at versjon og dato samsvarer med `fw_ref`.
Bare utskrivbare ASCII-tegn endres; binære og kryptografiske områder bevares.
Utfil: `fw_target_patched.bin`. Ingen stasjon nødvendig.

### Kommandoen decryptkernel

```
drivekit decryptkernel --file S9331050.100
drivekit decryptkernel --file S9331050.100 --patch --file2 S9331050_decoded_patched.bin
```

Dekrypterer KernelFront med XOR/rotasjon og lager en flat binærfil som kan åpnes som H8S/2600-kode i IDA Pro. `--patch` skal endre generasjonsmarkøren (`0xFF→0x01`) og beregne kontrollsummen på nytt. Kontroller utformatet og byteposisjonen i den frittstående kommandoen før filen eventuelt brukes til flashing. Den bekreftede metoden er `crossflash --patch`. Ingen stasjon nødvendig.

### Kommandoen decodenormal

Dekrypterer en Pioneer Normal-fastvarefil og rapporterer UHD-egenskaper.

```bash
drivekit decodenormal --file S8D31051.104
```

Du kan også lagre den dekrypterte fastvaren:

```bash
drivekit decodenormal --file S8D31051.104 --file2 decoded_body.bin
```

- `--file` – Normal-fastvarefilen som skal leses.
- `--file2` – Valgfritt filnavn for den dekrypterte utfilen.
- Ingen stasjon nødvendig.

---

## Kryptering og dekryptering av fastvare – KernelFront og Normal

Pioneers KernelFront- og Normal-filer bruker en beslektet **32-biters XOR-/rotasjonskryptering**. DriveKit har støtte for begge gjennom `decryptkernel` og `decodenormal`. Nøkkeltabellen ligger inne i hver fastvarefil. Dette er en annen mekanisme enn den løpende XOR-krypteringen som ble omtalt i maskinvareforskningen. **MattJackson** skal ha æren for forskningen på og dekrypteringen av KernelFront.

### Den felles krypteringsalgoritmen

La \(C_i\) være det krypterte ordet med indeks \(i\), \(P_i\) det tilsvarende dekrypterte ordet og \(K_i\) den valgte 32-biters nøkkelen. Symbolet \(\oplus\) betyr bitvis XOR, mens \(\operatorname{ROR}_{32}\) roterer en 32-biters verdi mot høyre:

$$
\boxed{P_i = \operatorname{ROR}_{32}\left(C_i \oplus K_i,\; K_i \bmod 32\right)}
$$

Bare de fem laveste bitene i nøkkelen bestemmer hvor mange plasser verdien roteres:

$$
r_i = K_i \mathbin{\&} 0x1F
$$

Den motsatte operasjonen, som brukes til å kryptere et endret ord på nytt, er:

$$
\boxed{C_i = \operatorname{ROL}_{32}(P_i, r_i) \oplus K_i}
$$

Alle nøkkeltabellverdier og krypterte ord leses som **little-endian 32-biters heltall**. De dekrypterte ordene skrives tilbake som little-endian-byte. `ROR` og `ROL` er *bitrotasjoner*, ikke vanlige forskyvninger: biter som går ut på én side, kommer inn igjen på den andre.

### Filformatet til KernelFront

| Filområde (sluttposisjon ikke medregnet) | Størrelse | Innhold |
|---|---:|---|
| `0x000–0x200` | `0x200` (512 byte) | ASCII-filhode |
| `0x200–0x1200` | `0x1000` (4 KiB) | 1 024 little-endian 32-biters nøkler |
| `0x1200–0x11200` | `0x10000` (64 KiB) | Kryptert kjerne |

Kjernens nøkkeltabell med 1 024 oppføringer brukes om igjen når alle de 16 384 krypterte ordene dekrypteres:

$$
K_i = T[i \bmod 1024]
$$

$$
\boxed{P_i = \operatorname{ROR}_{32}\left(C_i \oplus T[i \bmod 1024],\; T[i \bmod 1024] \mathbin{\&} 31\right)}
$$

`decryptkernel` lager en dekryptert kjerne på 64 KiB som kan analyseres som H8S/2600-kode, for eksempel i IDA Pro. **Denne råfilen kan ikke uten videre flashes som en KernelFront-fil.** Flashprosessen må bevare eller gjenskape riktig kryptert filformat og tilhørende integritetsfelter.

### Filformatene til Normal-fastvare

Normal-fastvare bruker samme XOR-/rotasjonsoperasjon for hvert ord, men har en **nøkkeltabell med 16 384 oppføringer** (64 KiB). DriveKit kjenner igjen to observerte filoppsett:

| Område | Standardoppsett | Utvidet oppsett |
|---|---|---|
| Filhode / foranstilte data | `0x000–0x200` | `0x000–0x10200` |
| Nøkkeltabell | `0x200–0x10200` | `0x10200–0x20200` |
| Krypterte data begynner | `0x10200` | `0x20200` |
| Antall nøkler | 16 384 | 16 384 |

For begge filoppsettene gjelder:

$$
K_i = T[i \bmod 16384]
$$

$$
\boxed{P_i = \operatorname{ROR}_{32}\left(C_i \oplus T[i \bmod 16384],\; T[i \bmod 16384] \mathbin{\&} 31\right)}
$$

DriveKits `normal_fw_probe_layout()` prøver først standardoffsetene og deretter de utvidede. Funksjonen dekrypterer de første **to 32-biters ordene** på hvert mulig startpunkt og kontrollerer om de åtte dekrypterte byteverdiene tilsvarer `PIONEER ` (inkludert mellomrommet til slutt). Hvis ingen passer, melder `decodenormal` om ukjent filformat i stedet for å gjette.

Den dekrypterte Normal-filen kan undersøkes for interne datastrukturer og kode som håndterer fastvareoppdatering. Den brukes også som inndata til `scankey`. Nøkkeltabellen for **dekryptering av filen** må ikke forveksles med den separate **opplåsings-/fullføringsnøkkelen** som `scankey` finner.

### Hvorfor dette er viktig

En kryptert fastvarefil kan ikke leses direkte som H8S/2600-instruksjoner. Når filen er dekryptert, kan man undersøke programkoden, versjonskontrollene og rutinene som håndterer oppdatering. **At en fil kan dekrypteres, betyr ikke at en modifisert fil er trygg å skrive til stasjonen.** Generasjonsmarkører, kontrollsummer, filstruktur og stasjonsspesifikke protokoller er fortsatt avgjørende.

---

## DriveBrowser

Et grafisk program for å bla i databasen, med synkronisering gjennom Supabase.

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

## Dekoding av serienummer

Eksempel på serienummerformat fra Pioneer: `NKDL005825JP`

```
N  K  D  L  0  0  5  8  2  5  J  P
|  |  |-----|  |-----|  |--|  |--|
|  |  factory  sequence  year  market
|  month (A=Jan ... L=Dec)
year letter (N=2022, O=2023, P=2024...)
```

| Felt | Posisjon | Eksempel | Betydning |
|-------|----------|---------|---------|
| Årsbokstav | [0] | `N` | Produksjonsår (N=2022, O=2023, P=2024) |
| Måned | [1] | `K` | Måned (A=januar, B=februar … L=desember) |
| Fabrikk | [2-3] | `DL` | Fabrikkode |
| Løpenummer | [4-7] | `0058` | Enhetens løpenummer |
| År (to siffer) | [8-9] | `25` | Årssuffiks |
| Marked | [10-11] | `JP` | Markedsregion (JP=Japan, EU=Europa, US=USA) |

---

## Buffer-ID-er

| ID | Beskrivelse |
|----|-------------|
| `0x41` | Aktiverer H8S/2600-kjernedump via `WRITE BUFFER` uten datalengde (12-byte CDB). Før sperredatoen: `0x00AAAA`. Etter: `0xA5AAAA`. Stasjonen må slås helt av og på mellom forsøk |
| `0x92` | Stasjonskonfigurasjon og fabrikkalibrering |
| `0xA0` | Modellstreng og opplåsingsnøkkel (etter sperredatoen) / egenskapsdata (før sperredatoen) |
| `0xB0` | Dekryptert H8S/2600-kode fra kjernen i RAM, klar for disassemblering. Etter `hwdump` leses blokker på `0x800` byte opp til `0x880800`; før sperredatoen fra `0x100000` (8,7 MB), etter fra `0x500000` (7,5 MB) |
| `0xF1` | Stasjonsidentitet: serienummer, plattform, kjerne-ID og fastvareversjon |
| `0xF4` | Innhold fra NAND-flash, lesbart uten opplåsing på nyere stasjoner. MakeMKV leser sekvensielle blokker på `0xA4` |
| `0xFE` | Målbuffer for kjerne-/token-skriving i crossflash |
| `0xF0` | Målbuffer for Normal-fastvare i begge protokoller |
| `0xFF` | Utløser for å fullføre skrivingen til NAND |
| `0xE5` | Setter flagget for Engineering Mode |

---

## Videre forskning

- **Kontrollere nøkkeltabellen med `scankey`:** undersøke avviket for `S8800601.153` (`0x5CF2E094` funnet, mot `0x6123789A` i tabellen). Nye nøkler må verifiseres med trafikkopptak og maskinvare; undersøk om en konstant fra gjenkjenningsmønsteret ble brukt ved en feil.
- **Utvide den bekreftede POST→PRE-nedgraderingen** utover BDR-XD07U SAT 8D31 / ID05 og 1.04-kjernen. Kontroller markører, kontrollsummer og overføringsmåter for andre kjernefamilier før støtte loves.
- **Kontrollere frittstående `decryptkernel --patch`:** sikre at den endrer **byteposisjon** `0xFE`, ikke DWORD-indeks `0xFE`, og skille mellom dekryptert utfil på 64 KiB og kryptert, flashbar kjerne på `0x11200` byte.
- **Analysere H8S/2600-versjonskontrollen:** fortsette å studere `hwdump` fra begge perioder for å forstå hvorfor bestemte versjoner godtas eller avvises.
- **Gjenkjenning av UHD-egenskaper:** dagens søk i dekryptert kjerne er upålitelig for enkelte stasjoner.
  - Ikke konkluder med bekreftet UHD-avspilling bare ut fra modellnavn eller signatur i fastvaren. Test med en faktisk UHD-plate.
  - Lete etter et særskilt bytemønster i Normal-fastvaren som viser UHD-støtte.
  - Målet er pålitelig automatisk gjenkjenning uten manuell overstyring.
- **Nedgradering av XD06U etter sperredatoen:** samme hindring med kryptert binærkode.
- **BDR-L13SH** (`REC 8C00 ID92`): ukjent stasjonsfamilie; venter på `0xB0`-dump.

---

## Uttrekk av H8S/2600-minne (`hwdump`)

**Bekreftet fungerende – 17. september 2026**

Oppdaget ved analyse av Wireshark-opptak fra en MakeMKV-økt på BDR-XD08U med nyere fastvare.

### Kommandoen

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

**Avgjørende oppdagelse:** `A5 AA AA` er **buffer-offseten i CDB-kommandoen**, ikke data som sendes. En skrivekommando med lengde null til en bestemt offset fungerer som opplåsingsutløser.

### Fullstendig sekvens (må kjøres sammenhengende, omtrent 5 ms tidsvindu):

**Etter sperredatoen:**
```
1. GET EVENT STATUS x4 (masks: 0x5A, 0x58, 0x50, 0x40)
2. WRITE BUFFER 12-byte CDB: 3B 02 41 A5 AA AA 00 00 00 00 00 00  (offset 0xA5AAAA)
3. READ BUFFER  10-byte CDB: 3C 02 F4 83 94 B4 00 00 08 00  (F4 trigger read)
4. READ BUFFER  10-byte CDB: 3C 02 B0 50 00 00 00 00 08 00  (H8S/2600 from 0x500000)
   → Keep reading sequential 0x800 chunks until 0x880800
```

**Før sperredatoen:**
```
1. GET EVENT STATUS x4 (masks: 0x5A, 0x58, 0x50, 0x40)
2. WRITE BUFFER 12-byte CDB: 3B 02 41 00 AA AA 00 00 00 00 00 00  (offset 0x00AAAA)
3. READ BUFFER  10-byte CDB: 3C 02 F4 83 94 B4 00 00 08 00  (F4 trigger read)
4. READ BUFFER  10-byte CDB: 3C 02 B0 10 00 00 00 00 08 00  (H8S/2600 from 0x100000)
   → Keep reading sequential 0x800 chunks until 0x880800
```

**Merk:** Stasjonen må slås helt av og på mellom `hwdump`-forsøk.
DriveKit finner perioden automatisk ved hjelp av datoen i `INQUIRY` og velger riktig sekvens.

### Resultat

Etter denne sekvensen returnerer `READ BUFFER 0xB0` dekryptert H8S/2600-maskinkode fra kjernen som kjører i stasjonen:
- **Etter sperredatoen:** 7,5 MB (`0x780800` byte), fra `0x500000` til `0x880800`.
- **Før sperredatoen:** 8,7 MB, fra `0x100000` til `0x880800`.

Blokkstørrelsen er `0x800` byte (2 KiB). Stasjonen krever **full omstart av strømmen** mellom `hwdump`-forsøk.

Denne minnedumpen ble sendt til MrPenguin for H8S/2600-analyse, med mål om å finne versjonskontrollen som hindrer nedgradering til eldre fastvare.

### DriveKit-kommando

```
drivekit hwdump E
```

Kjører hele sekvensen automatisk og lagrer resultatet som `hwdump_b0.bin`.

---

## Fastvaredato

Datoen til fastvaren finnes i standardresponsen fra `INQUIRY`, fra byteposisjon `0x25`:

```
INQUIRY[0x08-0x0F] = vendor   "PIONEER "
INQUIRY[0x10-0x1F] = model    "BD-RW  BDR-XD08U"
INQUIRY[0x20-0x23] = version  "1.02"
INQUIRY[0x24]      = space
INQUIRY[0x25-0x2C] = date     "22/12/27"
```

Bekreftet av MrPenguin: `sg_raw -b -r 16384 /dev/sg2 12 00 00 00 60 00 00`.

DriveKit viser dette som `FW Date` i stasjonsinformasjonen.

---

## AACS-versjon

Kan leses fra `GET CONFIGURATION`, funksjon `0x010D`, ved responsbyte `[0x0C]`:

```
CDB: 46 00 01 0C 00 00 00 00 1C 00
Response[0x0C] = AACS version (e.g. 0x1B = version 27)
```

DriveKit viser dette som `AACS ver` i stasjonsinformasjonen.


## Takk og bidragsytere

**Heisenberg** – Wireshark/USBPcap-opptak, blant annet oppgraderingen SAT 8D31 / ID05 fra 1.04 til 1.06, som bekreftet kjernens fire overføringer og sluttdelen med faktiske data. Bidro også med analyse av SAT 9331, uttrekk av nøkler fra Pioneers oppdateringsprogrammer, utviklingshjelp og testing. En enorm takk – dette verktøyet ville ikke eksistert uten deg.

**MattJackson (Matthew Jackson)** – Hovedutvikleren bak dekrypteringsalgoritmene og metoden `scankey` bruker for å finne nøkkelkontrollen direkte i fastvarekoden. Han dekrypterte kjernefilen og fant posisjonene som måtte endres for å kunne nedgradere forbi versjonssperren. Han har delt kildekoden åpent og vært uvurderlig i arbeidet med å hjelpe andre. ([GitHub](https://github.com/MattJackson)) ([profil på cdrinfo.pl](https://forum.cdrinfo.pl/members/112645.html))

**MrPenguin** – Dyptgående H8S/2600-analyse, reversering av den løpende XOR-krypteringen, arbeid med BDR-S12U i pypcode/Ghidra, avklaring av byterekkefølgen til opplåsingsnøkler, disassemblering av `READ BUFFER 0xB0`-data og uvurderlig teknisk veiledning gjennom hele prosjektet.

**greg1wto** – Skaffet verktøyene som gjorde Wireshark/USBPcap-analyse mulig. Sammen med reversering av Pioneers oppdateringsprogrammer gjorde dette det mulig å forstå protokollen for skriving til NAND.

Takk også for inspirasjon og hjelp fra cxplay, Sayaka, Coopervid, blackened2687, MakeMKV Forum og cdrinfo.pl.

**En spesiell takk til miljøet rundt flashverktøy:**
Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen, ala42, czary2mary, jadburner, cvs, alexx12345, seku, Leman39, wujooj, jurireal, alphaville0527, SnowFox, Kirby, haysey70, Majestic12, elflorek, floppydumper, redwine, cryptojoe3737, TeddyRaspin, asmcom, payalnik23, aliter404

**Verktøy brukt:** Wireshark + USBPcap, IDA Pro + hrtng-plugin, x64dbg, pypcode, Visual Studio 2022, WSL og GCC.

Kun til forskning og opplæring.

*DriveKit v1.0 — cPix / Razor 1911 (c) 2026*

```
          /\
         /__\
        /\  /\
       /__\/__\
   RAZOR 1911 — SINCE 1985
   Får fortsatt maskinvare til å gjøre det den ikke var ment å gjøre.
```
