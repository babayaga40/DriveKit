/*
 * drivekit.c  —  v15
 * Combined optical drive & storage research toolkit.
 * All tools in one binary, selected via command line arguments.
 *
 * v15 changes (2026-10-28):
 *   - cmd_flashfw: implement BDRFlash two-pass normal-FW protocol for
 *     pre-cutoff → post-cutoff cross-era flash (confirmed by USBPcap):
 *       pass1 (fwsize-0x10000) before kernel, pass2 (full) after kernel
 *   - cmd_flashfw: remove tkey substitution at commit trigger — for pre-cutoff
 *     drives, commit key = unlock key for BOTH same-era and cross-era.
 *     tkey hypothesis was WRONG; root cause of 04/4C/02 was wrong pass order.
 *   - cmd_crossflash: same commit-key fix.
 *   - 04/4C/02 error message updated to reflect correct diagnosis.
 *
 * Compile: cl.exe drivekit.c
 * Run as Administrator.
 *
 * Usage:
 *   drivekit <command> <drive_letter> [options]
 *
 * Commands:
 *   inquiry          Read drive firmware version and identity
 *   hwdump           Dump H8S/2600 kernel from RAM via 0xB0
 *   probef0          Probe READ BUFFER IDs 0xF0-0xFF
 *   rawdump          Raw READ BUFFER dump (use --bufid 0xF4 etc)
 *   unlock           Pioneer RS8801 service mode unlock
 *   probevendor      Probe vendor-specific opcodes 0xC0-0xFF
 *
 * Options:
 *   --bufid 0xF4     Buffer ID for rawdump (default 0xF4)
 *   --file  name     Input/output filename override
 *   --help           Show this help
 *
 * Examples:
 *   drivekit inquiry E
 *   drivekit rawdump E --bufid 0xFE
 *   drivekit probef0 E
 *   drivekit unlock E
 */

#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <ntddstor.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>

/* =========================================================
   CONSTANTS
   ========================================================= */
#define SENSE_SIZE       32
#define CHUNK_SIZE       0x0800  /* 2KB — matches drive's actual max transfer per read */
#define MAX_DUMP_SIZE    0x02000000
#define PAYLOAD_SIZE     256
#define VERSION          "1.0"

/* =========================================================
   TYPES
   ========================================================= */
typedef struct {
    SCSI_PASS_THROUGH_DIRECT sptd;
    UCHAR                    sense[SENSE_SIZE];
} SPTD_EX;

/* Global drive handle and path */
static HANDLE  g_hDrive    = INVALID_HANDLE_VALUE;
static char    g_drivePath[16];
static char    g_outFile[256];
static char    g_outFile2[256];
static char    g_outFile3[256]; /* second normal firmware pass (post-cutoff) */
static UCHAR   g_unlock_mode  = 0x04;
static UCHAR   g_unlock_bufid = 0xFF;
static int     g_force = 0;
static DWORD   g_key_override = 0; /* 0 = use derived key */
static int     g_patch_flag   = 0; /* --patch: apply generation marker patch */
static int     g_fakedate     = 0; /* --fakedate: patch Generated Date to 22/12/27 in FW buffers */
static int     g_enableversion = 0; /* --enableversion: bypass era mismatch guard */
static int     g_skip_checks = 0; /* skip compat/ready checks when chaining */
static DWORD   g_maxDumpSize = 0;  /* 0 = no limit */
static int     g_nounlock = 0;    /* skip unlock step */
static int     g_e5eng   = 0;    /* --e5: send WRITE BUFFER 0xE5 engineering mode enable before unlock */
static int     g_pre_cutoff = 0; /* set by cmd_flash when 0xB0 readable */
static WORD    g_driveID = 0;     /* detected drive ID for trigger key selection */
static char    g_kernelID[5] = {0}; /* kernel ID string from 0xF1 response (e.g. "9331") */
static UCHAR   g_payload[PAYLOAD_SIZE]; /* unlock payload buffer — shared across commands */
static char    g_fw_version[8] = {0}; /* firmware version from target file header */
static UCHAR   g_bufID     = 0xF4;
static UCHAR   g_a0token[0x100] = {0}; /* session token from 0xA0 - reused for trigger */
static UCHAR   g_f1token[0x30]  = {0}; /* 0xF1 token captured before unlock */
static int     g_has_token = 0;         /* 1 if valid token was retrieved */
static int     g_has_f1token = 0;       /* 1 if 0xF1 token was captured */

/* Forward typedef so PIONEER_DRIVE can be used in early functions */
typedef struct PIONEER_DRIVE_S {
    const char *model;
    WORD        driveID;
    int         cap;
} PIONEER_DRIVE;


/* New and updated FULL key table */
typedef struct {
    WORD        platform_id;
    const char *kernel_id;
    DWORD       key;
} PIONEER_KEY;


/* =========================================================
   FORWARD DECLARATIONS
   ========================================================= */
static void  build_pioneer_payload(UCHAR *payload, DWORD key);
static void  build_pioneer_payload_auto(UCHAR *payload);
static DWORD pioneer_key(WORD driveID, UCHAR cl);
static DWORD pioneer_key_lookup(WORD platform_id, const char *kernel_id);
static const PIONEER_DRIVE * pioneer_lookup(WORD driveID);
static void  pioneer_serial_decode(const char *serial, char *month_out, char *year_out, char *country_out);
static void  print_drive_info(HANDLE hDrive, const char *path);
static void  print_help(void);
static int   select_drive_interactive(char *drvOut, size_t drvOutSz);
static int   cmd_inquiry(void);
static int   cmd_probef0(void);
static int   cmd_flashfw(void);
static int   cmd_flashfw_precut(void);
static int   cmd_flash(void);
static int   cmd_autoflash(void);
static int   cmd_crossflash(void);
static int   cmd_decodenormal(void);
static int   cmd_hwdump(void);
static int   cmd_flashinfo(void);
static int   cmd_dumpfw(void);
static int   xf_write_buffer(UCHAR mode, UCHAR bufid, DWORD offset,
                             const UCHAR *data, DWORD len, const char *desc);
static void  xf_build_trigger(UCHAR *payload, const char *model, DWORD key_le);

/* =========================================================
   UTILITY: memmem for Windows
   ========================================================= */
static void *memmem_win(const void *hay, size_t hlen,
                        const void *needle, size_t nlen)
{
    const UCHAR *h = (const UCHAR*)hay;
    const UCHAR *n = (const UCHAR*)needle;
    size_t i;
    if (nlen == 0) return (void*)hay;
    if (hlen < nlen) return NULL;
    for (i = 0; i <= hlen - nlen; i++)
        if (memcmp(h + i, n, nlen) == 0)
            return (void*)(h + i);
    return NULL;
}

/* Patch "Generated Date : YY/MM/DD" in a firmware buffer in-memory.
   Searches first 0x400 bytes. Returns 1 if patched, 0 if not found. */
static int patch_generated_date(UCHAR *buf, DWORD buf_sz, const char *fake_date)
{
    UCHAR *p = (UCHAR*)memmem_win(buf, buf_sz < 0x400 ? buf_sz : 0x400,
                                  "Generated Date", 14);
    if (!p) return 0;
    UCHAR *col = (UCHAR*)memchr(p, ':', 32);
    if (!col) return 0;
    col += 2; /* skip ": " */
    memcpy(col, fake_date, 8); /* overwrite YY/MM/DD */
    return 1;
}

/* =========================================================
   UTILITY: hex dump
   ========================================================= */
static void hex_dump(const UCHAR *buf, DWORD len, DWORD max)
{
    DWORD limit = (len < max) ? len : max;
    DWORD i;
    DWORD j;
    for (i = 0;  i < limit; i++) {
        if (i % 16 == 0) printf("\n  %04lX  ", i);
        printf("%02X ", buf[i]);
        if (i % 16 == 15) {
            printf("  ");
            for (j = i - 15;  j <= i; j++)
                printf("%c", (buf[j]>=0x20&&buf[j]<0x7F)?buf[j]:'.');
        }
    }
    printf("\n");
}

/* =========================================================
   SCSI SENDER
   ========================================================= */
#define SCSI_CALL_TIMEOUT_MS 35000  /* hard ceiling, above the CDB's
                                        own 30s TimeOutValue, in case
                                        the port/bridge driver doesn't
                                        honor that field on a wedged
                                        drive */

static int send_scsi_raw(
    HANDLE hDrive,
    UCHAR *cdb,  UCHAR cdbLen,
    UCHAR *buf,  DWORD bufLen,
    UCHAR  direction,
    UCHAR *senseOut,
    int   *scsiStatus)
{
    SPTD_EX sx;
    DWORD   bytesReturned;

    memset(&sx, 0, sizeof(sx));
    sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sx.sptd.CdbLength          = cdbLen;
    sx.sptd.SenseInfoLength    = SENSE_SIZE;
    sx.sptd.DataIn             = direction;
    sx.sptd.DataTransferLength = bufLen;
    sx.sptd.TimeOutValue       = 30;
    sx.sptd.DataBuffer         = buf;
    sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX, sense);
    memcpy(sx.sptd.Cdb, cdb, cdbLen);

    if (!DeviceIoControl(hDrive, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                         &sx, sizeof(sx), &sx, sizeof(sx),
                         &bytesReturned, NULL))
        return (int)GetLastError();

    if (senseOut)   memcpy(senseOut, sx.sense, SENSE_SIZE);
    if (scsiStatus) *scsiStatus = sx.sptd.ScsiStatus;
    return 0;
}

typedef struct {
    HANDLE hDrive;
    UCHAR *cdb;
    UCHAR  cdbLen;
    UCHAR *buf;
    DWORD  bufLen;
    UCHAR  direction;
    UCHAR *senseOut;
    int    result;
    int    scsiStatus;
} SCSI_CALL_CTX;

static DWORD WINAPI scsi_call_thread(LPVOID param)
{
    SCSI_CALL_CTX *ctx = (SCSI_CALL_CTX *)param;
    ctx->result = send_scsi_raw(ctx->hDrive, ctx->cdb, ctx->cdbLen,
                                 ctx->buf, ctx->bufLen, ctx->direction,
                                 ctx->senseOut, &ctx->scsiStatus);
    return 0;
}

/* Same signature/behavior as before on the happy path. The actual
   DeviceIoControl call now runs on a worker thread so a wedged
   drive/USB-SATA bridge that never completes the request can't hang
   the whole tool forever - we bound the wait and return a timeout
   error instead. Note: we deliberately do NOT call TerminateThread
   on timeout, since killing a thread mid-IOCTL can leave the storage
   stack in a worse state; the stuck thread is just abandoned and the
   program moves on. If this fires, the drive itself needs a power
   cycle / reset before anything further will work reliably. */
static int send_scsi(
    HANDLE hDrive,
    UCHAR *cdb,  UCHAR cdbLen,
    UCHAR *buf,  DWORD bufLen,
    UCHAR  direction,
    UCHAR *senseOut,
    int   *scsiStatus)
{
    SCSI_CALL_CTX ctx;
    HANDLE hThread;
    DWORD  waitResult;

    memset(&ctx, 0, sizeof(ctx));
    ctx.hDrive    = hDrive;
    ctx.cdb       = cdb;
    ctx.cdbLen    = cdbLen;
    ctx.buf       = buf;
    ctx.bufLen    = bufLen;
    ctx.direction = direction;
    ctx.senseOut  = senseOut;

    hThread = CreateThread(NULL, 0, scsi_call_thread, &ctx, 0, NULL);
    if (!hThread) {
        /* Couldn't spin up a thread - fall back to a direct blocking
           call rather than fail outright. */
        return send_scsi_raw(hDrive, cdb, cdbLen, buf, bufLen,
                              direction, senseOut, scsiStatus);
    }

    waitResult = WaitForSingleObject(hThread, SCSI_CALL_TIMEOUT_MS);
    if (waitResult == WAIT_TIMEOUT) {
        CloseHandle(hThread);
        fprintf(stderr,
                "\n  [WARN] SCSI command timed out after %d sec - "
                "drive is not responding.\n"
                "  Power-cycle / reset the drive before retrying.\n",
                SCSI_CALL_TIMEOUT_MS / 1000);
        fflush(stderr);
        if (scsiStatus) *scsiStatus = -1;
        return ERROR_TIMEOUT;
    }

    CloseHandle(hThread);
    if (scsiStatus) *scsiStatus = ctx.scsiStatus;
    return ctx.result;
}

/* =========================================================
   OPEN DRIVE
   ========================================================= */
static int open_drive(const char *letter)
{
    snprintf(g_drivePath, sizeof(g_drivePath),
             "\\\\.\\%c:", letter[0]);

    g_hDrive = CreateFileA(g_drivePath,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);

    if (g_hDrive == INVALID_HANDLE_VALUE) {
        fprintf(stderr,
                "ERROR: Cannot open %s (error %lu)\n"
                "Run as Administrator.\n",
                g_drivePath, GetLastError());
        return 1;
    }
    printf("Opened: %s\n\n", g_drivePath);
    return 0;
}

/* =========================================================
   DRIVE ENUMERATION / SELECTION
   Scans all drive letters for optical (CD-ROM class) devices,
   queries INQUIRY on each, and - if more than one is present -
   asks the user to pick one explicitly instead of silently
   grabbing the first drive found. This matters most for
   flash-type commands, where writing to the wrong drive can
   brick it.
   ========================================================= */
typedef struct {
    char  letter;
    char  vendor[9];
    char  product[17];
    char  rev[5];
    int   inquiryOk;
} OPTICAL_DRIVE_ENTRY;

static int enum_optical_drives(OPTICAL_DRIVE_ENTRY *out, int maxEntries)
{
    char   letter;
    int    count = 0;

    for (letter = 'A'; letter <= 'Z' && count < maxEntries; letter++) {
        char   root[5];
        DWORD  dtype;
        HANDLE h;
        char   path[16];

        snprintf(root, sizeof(root), "%c:\\", letter);
        dtype = GetDriveTypeA(root);
        if (dtype != DRIVE_CDROM)
            continue;

        snprintf(path, sizeof(path), "\\\\.\\%c:", letter);
        h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);

        out[count].letter    = letter;
        out[count].inquiryOk = 0;
        strcpy(out[count].vendor,  "?");
        strcpy(out[count].product, "?");
        strcpy(out[count].rev,     "?");

        if (h != INVALID_HANDLE_VALUE) {
            UCHAR cdb[6]  = {0x12,0,0,0,96,0};
            UCHAR buf[96];
            UCHAR sense[SENSE_SIZE];
            int   status;
            int   i;

            memset(buf, 0, sizeof(buf));
            if (send_scsi(h, cdb, 6, buf, 96,
                          SCSI_IOCTL_DATA_IN, sense, &status) == 0 &&
                status == 0) {
                memcpy(out[count].vendor,  &buf[8],  8);
                out[count].vendor[8] = '\0';
                memcpy(out[count].product, &buf[16], 16);
                out[count].product[16] = '\0';
                memcpy(out[count].rev,     &buf[32], 4);
                out[count].rev[4] = '\0';
                for (i=7;  i>=0 && out[count].vendor[i]==' ';  i--) out[count].vendor[i]  = '\0';
                for (i=15; i>=0 && out[count].product[i]==' '; i--) out[count].product[i] = '\0';
                for (i=3;  i>=0 && out[count].rev[i]==' ';     i--) out[count].rev[i]     = '\0';
                out[count].inquiryOk = 1;
            }
            CloseHandle(h);
        }
        count++;
    }
    return count;
}

/* Prints a numbered list of detected optical drives and, if there
   is more than one, prompts the user to pick which one to use.
   drvOut receives the chosen drive letter as a 1-char string.
   Returns 0 on success, 1 if no drive could be selected. */
static int select_drive_interactive(char *drvOut, size_t drvOutSz)
{
    OPTICAL_DRIVE_ENTRY drives[26];
    int  n;
    int  i;

    printf("  Scanning for optical drives...\n\n");
    n = enum_optical_drives(drives, 26);

    if (n == 0) {
        fprintf(stderr, "Error: no optical drive found. Specify drive letter.\n");
        return 1;
    }

    for (i = 0; i < n; i++) {
        if (drives[i].inquiryOk) {
            printf("  [%d] %c:  %s %s  (fw %s)\n",
                   i+1, drives[i].letter,
                   drives[i].vendor, drives[i].product, drives[i].rev);
        } else {
            printf("  [%d] %c:  (could not query - inquiry failed)\n",
                   i+1, drives[i].letter);
        }
    }
    printf("\n");

    if (n == 1) {
        snprintf(drvOut, drvOutSz, "%c", drives[0].letter);
        if (drives[0].inquiryOk) {
            printf("  Only one optical drive detected: %c:  %s %s  (fw %s) - using it.\n\n",
                   drives[0].letter, drives[0].vendor, drives[0].product, drives[0].rev);
        } else {
            printf("  Only one optical drive detected: %c:  (inquiry failed, identity unknown) - using it.\n\n",
                   drives[0].letter);
        }
        return 0;
    }

    for (;;) {
        char line[32];
        int  choice;
        int  pickedIdx = -1;

        printf("  Multiple optical drives detected. Select one by number\n"
               "  (or type the drive letter directly): ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            fprintf(stderr, "\nError: no selection made.\n");
            return 1;
        }
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0')
            continue;

        /* Accept a plain drive letter (e.g. "E" or "E:") */
        if (isalpha((unsigned char)line[0]) &&
            (line[1] == '\0' || (line[1] == ':' && line[2] == '\0'))) {
            char picked = (char)toupper((unsigned char)line[0]);
            for (i = 0; i < n; i++) {
                if (drives[i].letter == picked) { pickedIdx = i; break; }
            }
            if (pickedIdx < 0) {
                printf("  Drive %c: is not in the list above.\n", picked);
                continue;
            }
        } else {
            /* Otherwise treat as a list index */
            choice = atoi(line);
            if (choice >= 1 && choice <= n)
                pickedIdx = choice - 1;
        }

        if (pickedIdx < 0) {
            printf("  Invalid selection, try again.\n");
            continue;
        }

        snprintf(drvOut, drvOutSz, "%c", drives[pickedIdx].letter);

        /* Always echo the FULL identity of what was picked - never
           just the number/letter - so the last thing on screen
           before a flash-type command proceeds is the actual drive
           name, not an index the user has to trust blindly. */
        if (drives[pickedIdx].inquiryOk) {
            printf("\n  Selected: %c:  %s %s  (fw %s)\n\n",
                   drives[pickedIdx].letter,
                   drives[pickedIdx].vendor, drives[pickedIdx].product,
                   drives[pickedIdx].rev);
        } else {
            printf("\n  Selected: %c:  (inquiry failed, identity unknown)\n\n",
                   drives[pickedIdx].letter);
        }
        return 0;
    }
}

static int rb_descriptor(UCHAR bufID, DWORD *cap)
{
    UCHAR cdb[10] = { 0x3C,0x03,bufID,0,0,0,0,0,4,0 };
    UCHAR desc[4];
    UCHAR sense[SENSE_SIZE];
    int   status;
    *cap = 0;
    memset(desc, 0, sizeof(desc));
    if (send_scsi(g_hDrive, cdb, 10, desc, 4,
                  SCSI_IOCTL_DATA_IN, sense, &status) || status)
        return 1;
    *cap = ((DWORD)desc[1]<<16)|((DWORD)desc[2]<<8)|(DWORD)desc[3];
    return 0;
}

static int rb_data(UCHAR bufID, DWORD offset,
                   UCHAR *buf, DWORD len, UCHAR *senseOut)
{
    UCHAR cdb[10];
    int   status;
    memset(cdb, 0, sizeof(cdb));
    cdb[0]=0x3C; cdb[1]=0x02; cdb[2]=bufID;
    cdb[3]=(offset>>16)&0xFF;
    cdb[4]=(offset>>8)&0xFF;
    cdb[5]=offset&0xFF;
    cdb[6]=(len>>16)&0xFF;
    cdb[7]=(len>>8)&0xFF;
    cdb[8]=len&0xFF;
    if (send_scsi(g_hDrive, cdb, 10, buf, len,
                  SCSI_IOCTL_DATA_IN, senseOut, &status) || status)
        return 1;
    return 0;
}

/* =========================================================
   COMMAND: inquiry
   ========================================================= */
static int cmd_inquiry(void)
{
    UCHAR cdb[6] = {0x12,0,0,0,96,0};
    UCHAR buf[96];
    UCHAR sense[SENSE_SIZE];
    int   status;
    char  vendor[9], product[17], rev[5];
    int   i;

    printf("=== INQUIRY ===\n\n");
    memset(buf, 0, sizeof(buf));

    if (send_scsi(g_hDrive, cdb, 6, buf, 96,
                  SCSI_IOCTL_DATA_IN, sense, &status) || status) {
        fprintf(stderr, "INQUIRY failed.\n");
        return 1;
    }

    memcpy(vendor,  &buf[8],  8);  vendor[8]   = '\0';
    memcpy(product, &buf[16], 16); product[16] = '\0';
    memcpy(rev,     &buf[32], 4);  rev[4]      = '\0';
    for (i=7;  i>=0 && vendor[i]==' ';  i--) vendor[i]  = '\0';
    for (i=15; i>=0 && product[i]==' '; i--) product[i] = '\0';
    for (i=3;  i>=0 && rev[i]==' ';     i--) rev[i]     = '\0';

    printf("  Vendor   : %s\n", vendor);
    printf("  Model    : %s\n", product);
    printf("  Firmware : %s\n", rev);
    printf("  Type     : %s\n",
           (buf[0]&0x1F)==0x05 ? "CD/DVD/BD optical" : "other");
    printf("  Removable: %s\n", (buf[1]&0x80)?"Yes":"No");
    return 0;
}

static int cmd_driveinfo2(void)
{
    UCHAR buf[256], sense[SENSE_SIZE], cdb[12];
    UCHAR featBuf[4096];
    UCHAR gcdb[10] = {0x46,0x00,0,0,0,0,0,0x10,0x00,0};
    int   scsiStatus, i;
    DWORD total, off;

    printf("=== DRIVE FEATURE PROBE ===\n\n");

    /* GET CONFIGURATION - all features, large buffer */
    memset(featBuf, 0, sizeof(featBuf));
    gcdb[7] = (sizeof(featBuf)>>8)&0xFF;
    gcdb[8] = sizeof(featBuf)&0xFF;
    send_scsi(g_hDrive, gcdb, 10, featBuf, sizeof(featBuf),
              SCSI_IOCTL_DATA_IN, sense, &scsiStatus);

    if (scsiStatus != 0) {
        printf("  GET CONFIGURATION failed: ASC=%02X\n", sense[12]);
        return 1;
    }

    total = ((DWORD)featBuf[0]<<24)|((DWORD)featBuf[1]<<16)|
            ((DWORD)featBuf[2]<<8)|(DWORD)featBuf[3];
    total += 4;
    if (total > sizeof(featBuf)) total = sizeof(featBuf);

    /* Current profile */
    {
        WORD prof = ((WORD)featBuf[6]<<8)|featBuf[7];
        const char *pname =
            prof==0x0008?"CD-ROM":   prof==0x0009?"CD-R":
            prof==0x000A?"CD-RW":    prof==0x0010?"DVD-ROM":
            prof==0x0011?"DVD-R":    prof==0x0012?"DVD-RAM":
            prof==0x0013?"DVD-RW Sequential": prof==0x0014?"DVD-RW Random":
            prof==0x0015?"DVD-R DL Sequential": prof==0x0016?"DVD-R DL Jump":
            prof==0x001A?"DVD+RW":   prof==0x001B?"DVD+R":
            prof==0x001E?"DVD+RW DL":prof==0x002B?"DVD+R DL":
            prof==0x0040?"BD-ROM":   prof==0x0041?"BD-R SRM":
            prof==0x0042?"BD-R RRM": prof==0x0043?"BD-RE":
            prof==0x0050?"HD DVD-ROM":prof==0x0051?"HD DVD-R":
            prof==0x0052?"HD DVD-RAM":prof==0x0002?"Removable Disk":
            prof==0x0000?"No disc":"Unknown";
        printf("  Current profile: %s (0x%04X)\n\n", pname, prof);
    }

    /* Profile list from feature 0x0000 */
    off = 8;
    printf("  [Feature 0x0000 - Supported Profiles]\n");
    if (off+4 <= total) {
        WORD fc = ((WORD)featBuf[off]<<8)|featBuf[off+1];
        if (fc == 0x0000) {
            UCHAR flen = featBuf[off+3];
            DWORD poff = off+4;
            while (poff+4 <= off+4+flen) {
                WORD p = ((WORD)featBuf[poff]<<8)|featBuf[poff+1];
                UCHAR cur = featBuf[poff+2] & 0x01;
                const char *pname =
                    p==0x0008?"CD-ROM":   p==0x0009?"CD-R":
                    p==0x000A?"CD-RW":    p==0x0010?"DVD-ROM":
                    p==0x0011?"DVD-R":    p==0x0012?"DVD-RAM":
                    p==0x0013?"DVD-RW Sequential": p==0x0014?"DVD-RW Random":
                    p==0x0015?"DVD-R DL Sequential": p==0x0016?"DVD-R DL Jump":
                    p==0x001A?"DVD+RW":   p==0x001B?"DVD+R":
                    p==0x001E?"DVD+RW DL":p==0x002B?"DVD+R DL":
                    p==0x0040?"BD-ROM":   p==0x0041?"BD-R SRM":
                    p==0x0042?"BD-R RRM": p==0x0043?"BD-RE":
                    p==0x0050?"HD DVD-ROM":p==0x0051?"HD DVD-R":
                    p==0x0052?"HD DVD-RAM":p==0x0002?"Removable Disk":
                    "Unknown";
                printf("    0x%04X  %-12s %s\n",
                       p, pname, cur?"[current]":"");
                poff += 4;
            }
        }
    }
    printf("\n");

    /* Enumerate all features */
    printf("  [All Feature Descriptors]\n");
    off = 8;
    while (off+4 <= total) {
        WORD  fc   = ((WORD)featBuf[off]<<8)|featBuf[off+1];
        UCHAR pers = (featBuf[off+2]>>1)&1;
        UCHAR cur  = featBuf[off+2]&1;
        UCHAR flen = featBuf[off+3];
        const char *fname =
            fc==0x0000?"Profile List":
            fc==0x0001?"Core":
            fc==0x0002?"Morphing":
            fc==0x0003?"Removable Medium":
            fc==0x0004?"Write Protect":
            fc==0x0010?"Random Readable":
            fc==0x001D?"Multi-Read":
            fc==0x001E?"CD Read":
            fc==0x001F?"DVD Read":
            fc==0x0020?"Random Writable":
            fc==0x0021?"Incremental Streaming Writable":
            fc==0x0023?"Formattable":
            fc==0x0024?"Defect Management":
            fc==0x0025?"Write Once":
            fc==0x0026?"Restricted Overwrite":
            fc==0x002A?"DVD+RW":
            fc==0x002B?"DVD+R":
            fc==0x002C?"Rigid Restricted Overwrite":
            fc==0x002D?"CD Track At Once":
            fc==0x002E?"CD Mastering":
            fc==0x002F?"DVD-R/-RW Write":
            fc==0x0033?"Layer Jump Recording":
            fc==0x0037?"CD-RW Media Write Support":
            fc==0x0038?"BD-R Pseudo-Overwrite":
            fc==0x003A?"DVD+RW DL":
            fc==0x003B?"DVD+R DL":
            fc==0x0040?"BD Read":
            fc==0x0041?"BD Write":
            fc==0x0042?"TSR":
            fc==0x0100?"Power Management":
            fc==0x0101?"S.M.A.R.T.":
            fc==0x0102?"Embedded Changer":
            fc==0x0103?"CD Audio Analog Play":
            fc==0x0104?"Microcode Upgrade":
            fc==0x0105?"Timeout":
            fc==0x0106?"DVD CSS":
            fc==0x0107?"Real Time Streaming":
            fc==0x0108?"Drive Serial Number":
            fc==0x0109?"Media Serial Number":
            fc==0x010A?"Disc Control Blocks":
            fc==0x010B?"DVD CPRM":
            fc==0x010C?"Firmware Date":
            fc==0x010D?"AACS":
            fc==0x0110?"VCPS":
            fc==0x0113?"LibreDrive (0x0113)":
            "Unknown";

        printf("    0x%04X  %-35s P=%d C=%d\n",
               fc, fname, pers, cur);

        /* Special handling for some features */
        if (fc == 0x0001 && flen >= 4) {
            /* Core - physical interface */
            DWORD phys = ((DWORD)featBuf[off+4]<<24)|
                         ((DWORD)featBuf[off+5]<<16)|
                         ((DWORD)featBuf[off+6]<<8)|
                          (DWORD)featBuf[off+7];
            const char *iface =
                phys==0x00000000?"Unspecified":
                phys==0x00000001?"SCSI Family":
                phys==0x00000002?"ATAPI":
                phys==0x00000003?"IEEE 1394-1995":
                phys==0x00000004?"IEEE 1394A":
                phys==0x00000005?"Fibre Channel":
                phys==0x00000006?"IEEE 1394B":
                phys==0x00000007?"Serial ATAPI":
                phys==0x00000008?"USB":
                "Unknown";
            printf("           Interface: %s\n", iface);
        }
        if (fc == 0x0108 && flen >= 4) {
            /* Drive Serial Number */
            char sn[32] = {0};
            int k;
            for (k=0; k<(int)flen && k<31; k++)
                if (featBuf[off+4+k] >= 0x20 && featBuf[off+4+k] < 0x7F)
                    sn[k] = featBuf[off+4+k];
            if (sn[0]) printf("           Serial: %s\n", sn);
        }
        if (fc == 0x010C && flen >= 4) {
            /* Firmware Date */
            char fd[32] = {0};
            int k;
            for (k=0; k<(int)flen && k<31; k++)
                if (featBuf[off+4+k] >= 0x20 && featBuf[off+4+k] < 0x7F)
                    fd[k] = featBuf[off+4+k];
            if (fd[0]) printf("           Date: %s\n", fd);
        }
        if (fc == 0x0113) {
            printf("           *** LibreDrive feature present! ***\n");
        }

        off += 4 + flen;
    }

    printf("\n");

    /* Probe 0xE1 - LDRE signature */
    memset(cdb, 0, sizeof(cdb));
    memset(buf, 0, sizeof(buf));
    cdb[0]=0xE1; cdb[8]=0xFF;
    send_scsi(g_hDrive, cdb, 12, buf, 256,
              SCSI_IOCTL_DATA_IN, sense, &scsiStatus);
    if (scsiStatus == 0 && buf[0]=='L'&&buf[1]=='D'&&buf[2]=='R'&&buf[3]=='E')
        printf("  *** LDRE signature found - LibreDrive ACTIVE ***\n");

    return 0;
}

/* =========================================================
   COMMAND: probef0
   ========================================================= */
static int cmd_probef0(void)
{
    static const UCHAR IDS[] = {
        0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,
        0xF8,0xF9,0xFA,0xFB,0xFC,0xFD,0xFE,0xFF
    };
    static const char *sigs[] = {
        "SAT 8800","SAT 8801","PIONEER",
        "ASUSTek","ID60","SEDL","BDR-", NULL
    };
    UCHAR  buf[64];
    UCHAR  sense[SENSE_SIZE];
    UCHAR *chunk;
    DWORD  cap;
    DWORD  total;
    DWORD  offset;
    DWORD  thisChunk;
    FILE  *fp;
    char   fname[64];
    int    i;
    int    s;

    printf("=== PROBING READ BUFFER 0xF0-0xFF ===\n\n");

    for (i = 0; i < 16; i++) {
        UCHAR id = IDS[i];
        printf("Buffer ID 0x%02X: ", id);

        if (rb_descriptor(id, &cap) || cap == 0) {
            printf("not available\n");
            continue;
        }

        printf("capacity = 0x%08lX (%lu KB)\n", cap, cap/1024);

        memset(buf, 0, sizeof(buf));
        if (rb_data(id, 0, buf, 64, sense) == 0) {
            printf("  Preview:");
            hex_dump(buf, 64, 64);

            for (s = 0; sigs[s]; s++)
                if (memmem_win(buf, 64, sigs[s], strlen(sigs[s])))
                    printf("  *** \"%s\" found ***\n", sigs[s]);
        }

        /* Offer to dump if large enough */
        if (cap >= 1024) {
            snprintf(fname, sizeof(fname), "probef0_buf_%02X.bin", id);
            if (id == 0xF4)
                printf("  Dumping Renesas R8J32740 NAND flash contents...\n");
            else if (id == 0xFE)
                printf("  Dumping kernel area (R8J32740 boot image)...\n");
            else if (id == 0xB0)
                printf("  Dumping kernel mode buffer (0xB0 trigger active)...\n");
            else
                printf("  Dumping to %s...\n", fname);

            fp = fopen(fname, "wb");
            if (!fp) continue;

            chunk  = (UCHAR*)malloc(CHUNK_SIZE);
            total  = (cap>MAX_DUMP_SIZE)?MAX_DUMP_SIZE:cap;
            offset = 0;

            while (offset < total) {
                thisChunk = CHUNK_SIZE;
                if (offset+thisChunk > total) thisChunk = total-offset;
                memset(chunk, 0xFF, thisChunk);
                rb_data(id, offset, chunk, thisChunk, sense);
                fwrite(chunk, 1, thisChunk, fp);
                offset += thisChunk;
                if ((offset%0x100000)==0) { printf("."); fflush(stdout); }
            }
            printf("\n  Saved %lu bytes.\n", offset);
            fclose(fp);
            free(chunk);
        }
        printf("\n");
    }
    return 0;
}

/* =========================================================
   COMMAND: rawdump
   ========================================================= */
static int cmd_rawdump(void)
{
    DWORD  cap = 0;
    DWORD  offset = 0;
    DWORD  total;
    UCHAR *chunk;
    UCHAR  sense[SENSE_SIZE];
    FILE  *fp;
    char   fname[256];

    if (g_outFile[0])
        strncpy(fname, g_outFile, sizeof(fname));
    else
        snprintf(fname, sizeof(fname),
                 "raw_buf_%02X.bin", g_bufID);

    printf("=== RAW BUFFER DUMP ===\n\n");
    printf("  Buffer ID : 0x%02X\n", g_bufID);
    printf("  Output    : %s\n\n", fname);

    if (rb_descriptor(g_bufID, &cap) || cap == 0) {
        fprintf(stderr, "Buffer 0x%02X not available.\n", g_bufID);
        return 1;
    }
    printf("  Capacity  : 0x%08lX (%lu KB)\n\n", cap, cap/1024);

    /* Preview */
    UCHAR preview[64];
    memset(preview, 0, sizeof(preview));
    if (rb_data(g_bufID, 0, preview, 64, sense) == 0) {
        printf("  First 64 bytes:");
        hex_dump(preview, 64, 64);
        printf("\n");
    }

    total = (cap>MAX_DUMP_SIZE)?MAX_DUMP_SIZE:cap;
    /* Apply --maxsize limit if specified */
    if (g_maxDumpSize > 0 && g_maxDumpSize < total)
        total = g_maxDumpSize;
    chunk = (UCHAR*)malloc(CHUNK_SIZE);
    if (!chunk) return 1;

    fp = fopen(fname, "wb");
    if (!fp) { free(chunk); return 1; }

    printf("  Dumping");

    /* For buffer 0xB0 in kernel mode: try offset fixed at 0x04
       (autoflasher only reads one chunk at offset 0x04)        */
    if (g_bufID == 0xB0) {
        DWORD page = 0;
        while (offset < total) {
            DWORD thisChunk = CHUNK_SIZE;
            if (offset+thisChunk > total) thisChunk = total-offset;

            /* Try with rolling offset first, fall back to page 0x04 */
            memset(chunk, 0xFF, thisChunk);
            if (rb_data(g_bufID, offset+4, chunk, thisChunk, sense)) {
                /* Try fixed offset 0x04 */
                if (rb_data(g_bufID, 0x04 + page*thisChunk,
                            chunk, thisChunk, sense)) {
                    printf("\n  Error at 0x%08lX  key=%02X ASC=%02X\n",
                           offset, sense[2]&0x0F, sense[12]);
                }
            }
            fwrite(chunk, 1, thisChunk, fp);
            offset += thisChunk;
            page++;
            if ((offset%0x100000)==0) { printf("."); fflush(stdout); }
        }
    } else {
        while (offset < total) {
            DWORD thisChunk = CHUNK_SIZE;
            if (offset+thisChunk > total) thisChunk = total-offset;

            memset(chunk, 0xFF, thisChunk);
            if (rb_data(g_bufID, offset, chunk, thisChunk, sense)) {
                printf("\n  Error at 0x%08lX  key=%02X ASC=%02X\n",
                       offset, sense[2]&0x0F, sense[12]);
            }
            fwrite(chunk, 1, thisChunk, fp);
            offset += thisChunk;
            if ((offset%0x100000)==0) { printf("."); fflush(stdout); }
        }
    }

    fclose(fp);
    free(chunk);
    printf("\n  Saved %lu bytes to %s\n", offset, fname);
    return 0;
}

/* =========================================================
   COMMAND: dumpfw
   Experimental Pioneer firmware read via MODE SENSE(10).

   Captured CDB:
       5A 08 2A 00 00 00 00 FF F0 00

   The command itself does NOT unlock or alter drive state.

   Observed behavior:
     - locked/normal state: ordinary 0x2A response, mostly zero
     - manually unlocked:  extended Pioneer response containing
                           platform identity and firmware data

   Keep unlock separate while the dump protocol is still being
   mapped.  Typical research flow:

       drivekit unlock E
       drivekit dumpfw E --file pioneer_firmware_dump.bin

   This command reads the proven 0xFFF0-byte response, saves it
   byte-for-byte, and scans its contents.  It does not currently
   attempt to advance to later firmware windows.
   ========================================================= */
static int cmd_dumpfw(void)
{
    enum { DUMPFW_XFER_SIZE = 0xFFF0 };

    UCHAR cdb[12] = {
        0x5A, 0x08, 0x2A, 0x00, 0x00, 0x00,
        0x00, 0xFF, 0xF0, 0x00, 0x00, 0x00
    };

    UCHAR sense[SENSE_SIZE] = {0};
    UCHAR *buf = NULL;
    FILE *fp = NULL;
    int st = 0;
    int rc;
    DWORD i;
    char fname[256];

    static const char *markers[] = {
        "PIONEER",
        "Copyright",
        "SAT ",
        "ATA ",
        "ID",
        "BDR-",
        "DVD",
        "GENERAL"
    };
    const int marker_count = sizeof(markers) / sizeof(markers[0]);

    if (g_outFile[0]) {
        strncpy(fname, g_outFile, sizeof(fname) - 1);
        fname[sizeof(fname) - 1] = '\0';
    } else {
        strcpy(fname, "pioneer_firmware_dump.bin");
    }

    printf("=== PIONEER FIRMWARE DUMP / CROSSFLASH KERNEL TRIGGER TEST ===\n\n");
    printf("  Output    : %s\n\n", fname);

    /* Read 0xF1 first to populate g_driveID and g_kernelID */
    {
      /*  UCHAR f1[0x30] = {0};
        UCHAR f1s[SENSE_SIZE] = {0};
        if (rb_data(0xF1, 0, f1, 0x30, f1s) == 0) {
            int j; char plat[16] = {0}; char kid[8] = {0};
            for (j=0; j<12 && f1[0x10+j]>=0x20 && f1[0x10+j]<0x7F; j++) plat[j]=f1[0x10+j];
            for (j=0; j<8  && f1[0x18+j]>=0x20 && f1[0x18+j]<0x7F; j++) kid[j] =f1[0x18+j];
            const char *p = plat; while(*p && (*p<'0'||*p>'9')) p++;
            if (*p) g_driveID = (WORD)strtol(p, NULL, 16);
                strncpy(g_kernelID, kid, sizeof(g_kernelID)-1);
            printf("  [DBG] 0xF1: platform='%s' driveID=0x%04X kernel='%s'\n\n",
                   plat, g_driveID, g_kernelID);
        } else {
            printf("  [WARN] 0xF1 read failed — model/key may be wrong\n\n");
        } */
    }

    /* -----------------------------------------------------
       Enter the same kernel/service state used by cmd_crossflash().

       This is deliberately the exact crossflash unlock trigger:

           WRITE BUFFER
           mode   = 0x04
           bufID  = 0xFF
           offset = 0
           length = 0x100

       Payload is generated by xf_build_trigger() using the same
       auto-detected model and platform/kernel key as crossflash.
       No later crossflash steps are performed here.
       ----------------------------------------------------- */
    {
        UCHAR auto_payload[256] = {0};
        UCHAR trigger[256]      = {0};
        char  model_str[17]     = {0};
        const char *model;
        DWORD key_le;
        int ust;

        build_pioneer_payload_auto(auto_payload);
        memcpy(model_str, auto_payload, 16);
        model_str[16] = 0;
        model = model_str;

        key_le = ((DWORD)auto_payload[0x10])        |
                 ((DWORD)auto_payload[0x11] <<  8) |
                 ((DWORD)auto_payload[0x12] << 16) |
                 ((DWORD)auto_payload[0x13] << 24);

        if (key_le == 0)
            key_le = 0x6123789A;

        if (g_key_override)
            key_le = g_key_override;

        printf("=== CROSSFLASH KERNEL TRIGGER ===\n\n");
        printf("[1] Unlock trigger (mode=0x04 bufID=0xFF)...\n");

        xf_build_trigger(trigger, model, key_le);

        printf("    Model : '%.16s'\n", model);
        printf("    Key   : 0x%08lX\n", key_le);
        printf("    CDB   : 3B 04 FF 00 00 00 00 01 00 00 00 00 (12-byte)\n");
        printf("    Payload first 20 bytes:");
        for (i = 0; i < 20; i++)
            printf(" %02X", trigger[i]);
        printf("\n");

        ust = xf_write_buffer(0x04, 0xFF, 0,
                              trigger, 0x100,
                              "unlock_trigger");

        if (ust != 0) {
            fprintf(stderr,
                    "  FAILED: Crossflash kernel trigger rejected by drive.\n");
            fprintf(stderr,
                    "  Check model string and platform/kernel key.\n");
            return 1;
        }

        printf("    OK\n\n");
        Sleep(200);
    }

    /* -----------------------------------------------------
       Reproduce the exact read-only command sequence observed
       in BDRFlash immediately before MODE SENSE(10) 0x2A.

       1) READ BUFFER F1, 0x30 bytes
       2) READ BUFFER A0, offset 0x90, 0x10 bytes
       3) REQUEST SENSE, 0x12 bytes
       4) GET CONFIGURATION, RT=01, 0x28 bytes
       5) MODE SENSE(10) page 0x2A, allocation 0xFFF0

       The crossflash kernel trigger above deliberately establishes
       the service/kernel state first; this preamble then mirrors
       the BDRFlash reads immediately before MODE SENSE(10).
       ----------------------------------------------------- */

    printf("=== BDRFLASH PREAMBLE ===\n\n");

    /* 1. READ BUFFER F1 - identity */
    {
        UCHAR pcdb[10] = {
            0x3C, 0x02, 0xF1, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x30, 0x00
        };
        UCHAR pbuf[0x30];

        memset(pbuf, 0, sizeof(pbuf));
        memset(sense, 0, sizeof(sense));
        st = 0;

        rc = send_scsi(g_hDrive, pcdb, 10,
                       pbuf, sizeof(pbuf),
                       SCSI_IOCTL_DATA_IN,
                       sense, &st);

        printf("[1] READ BUFFER F1 : ");
        if (rc == 0 && st == 0) {
            printf("GOOD\n");
            printf("    Serial   : '%.12s'\n", (char *)&pbuf[0x00]);
            printf("    Platform : '%.12s'\n", (char *)&pbuf[0x10]);
            printf("    Kernel   : '%.4s'\n",  (char *)&pbuf[0x18]);
        } else {
            printf("FAIL rc=%d status=%02X sense=%02X/%02X/%02X\n",
                   rc, st, sense[2] & 0x0F, sense[12], sense[13]);
        }
    }

    /* 2. READ BUFFER A0 - model string at offset 0x90 */
    {
        UCHAR pcdb[10] = {
            0x3C, 0x02, 0xA0, 0x00, 0x00,
            0x90, 0x00, 0x00, 0x10, 0x00
        };
        UCHAR pbuf[0x10];

        memset(pbuf, 0, sizeof(pbuf));
        memset(sense, 0, sizeof(sense));
        st = 0;

        rc = send_scsi(g_hDrive, pcdb, 10,
                       pbuf, sizeof(pbuf),
                       SCSI_IOCTL_DATA_IN,
                       sense, &st);

        printf("[2] READ BUFFER A0/0x90 : ");
        if (rc == 0 && st == 0) {
            printf("GOOD\n");
            printf("    Model raw: '");
            for (i = 0; i < sizeof(pbuf); i++) {
                UCHAR ch = pbuf[i];
                putchar((ch >= 0x20 && ch <= 0x7E) ? ch : '.');
            }
            printf("'\n");
        } else {
            printf("FAIL rc=%d status=%02X sense=%02X/%02X/%02X\n",
                   rc, st, sense[2] & 0x0F, sense[12], sense[13]);
        }
    }

    /* 3. REQUEST SENSE */
    {
        UCHAR pcdb[6] = {
            0x03, 0x00, 0x00, 0x00, 0x12, 0x00
        };
        UCHAR pbuf[0x12];

        memset(pbuf, 0, sizeof(pbuf));
        memset(sense, 0, sizeof(sense));
        st = 0;

        rc = send_scsi(g_hDrive, pcdb, 6,
                       pbuf, sizeof(pbuf),
                       SCSI_IOCTL_DATA_IN,
                       sense, &st);

        printf("[3] REQUEST SENSE : ");
        if (rc == 0 && st == 0) {
            printf("GOOD  key=%02X ASC=%02X ASCQ=%02X\n",
                   pbuf[2] & 0x0F, pbuf[12], pbuf[13]);
        } else {
            printf("FAIL rc=%d status=%02X sense=%02X/%02X/%02X\n",
                   rc, st, sense[2] & 0x0F, sense[12], sense[13]);
        }
    }

    /* 4. GET CONFIGURATION - exact BDRFlash CDB */
    {
        UCHAR pcdb[10] = {
            0x46, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x28, 0x00
        };
        UCHAR pbuf[0x28];

        memset(pbuf, 0, sizeof(pbuf));
        memset(sense, 0, sizeof(sense));
        st = 0;

        rc = send_scsi(g_hDrive, pcdb, 10,
                       pbuf, sizeof(pbuf),
                       SCSI_IOCTL_DATA_IN,
                       sense, &st);

        printf("[4] GET CONFIGURATION : ");
        if (rc == 0 && st == 0) {
            printf("GOOD\n");
        } else {
            printf("FAIL rc=%d status=%02X sense=%02X/%02X/%02X\n",
                   rc, st, sense[2] & 0x0F, sense[12], sense[13]);
        }
    }

    printf("\n=== EXTENDED MODE SENSE READ ===\n\n");
    printf("  CDB       : 5A 08 2A 00 00 00 00 FF F0 00 00 00\n");
    printf("  CDB length: 12 bytes (matches USB BOT bCBWCBLength=0x0C)\n");
    printf("  Read size : 0x%04X (%u bytes)\n\n",
           DUMPFW_XFER_SIZE, DUMPFW_XFER_SIZE);

    buf = (UCHAR *)malloc(DUMPFW_XFER_SIZE);
    if (!buf) {
        fprintf(stderr, "Cannot allocate dump buffer.\n");
        return 1;
    }

    memset(buf, 0, DUMPFW_XFER_SIZE);
    memset(sense, 0, sizeof(sense));
    st = 0;

    rc = send_scsi(g_hDrive,
                   cdb,
                   12,
                   buf,
                   DUMPFW_XFER_SIZE,
                   SCSI_IOCTL_DATA_IN,
                   sense,
                   &st);

    if (rc != 0 || st != 0) {
        fprintf(stderr,
                "Firmware dump command failed: "
                "rc=%d status=%02X sense=%02X/%02X/%02X\n",
                rc,
                st,
                sense[2] & 0x0F,
                sense[12],
                sense[13]);
        free(buf);
        return 1;
    }

    printf("  Command   : GOOD\n");

    if (DUMPFW_XFER_SIZE >= 2) {
        WORD mode_len = ((WORD)buf[0] << 8) | buf[1];
        DWORD standard_end = (DWORD)mode_len + 2;
        printf("  MODE SENSE declared length : 0x%04X (%u)\n",
               mode_len, mode_len);
        printf("  Standard response end      : 0x%04lX\n",
               standard_end);
        printf("  Trailing Pioneer data      : 0x%04lX bytes\n",
               (standard_end < DUMPFW_XFER_SIZE)
                   ? (DUMPFW_XFER_SIZE - standard_end)
                   : 0);
    }

    printf("  Identity @0x60             : '%.16s'\n\n",
           (char *)&buf[0x60]);

    fp = fopen(fname, "wb");
    if (!fp) {
        fprintf(stderr, "Cannot create %s\n", fname);
        free(buf);
        return 1;
    }

    if (fwrite(buf, 1, DUMPFW_XFER_SIZE, fp) != DUMPFW_XFER_SIZE) {
        fprintf(stderr, "Error writing %s\n", fname);
        fclose(fp);
        free(buf);
        return 1;
    }

    fclose(fp);
    fp = NULL;

    printf("  Saved     : %u bytes (0x%04X)\n",
           DUMPFW_XFER_SIZE, DUMPFW_XFER_SIZE);
    printf("  File      : %s\n\n", fname);

    printf("  First 256 bytes:\n");

    for (i = 0; i < 0x100; i += 16) {
        DWORD j;

        printf("  %04lX  ", i);

        for (j = 0; j < 16; j++)
            printf("%02X ", buf[i + j]);

        printf(" ");

        for (j = 0; j < 16; j++) {
            UCHAR ch = buf[i + j];
            putchar((ch >= 0x20 && ch <= 0x7E) ? ch : '.');
        }

        printf("\n");
    }

    printf("\n=== KNOWN MARKERS ===\n\n");

    {
        int m;

        for (m = 0; m < marker_count; m++) {
            const char *needle = markers[m];
            DWORD nlen = (DWORD)strlen(needle);
            int found = 0;

            for (i = 0; i + nlen <= DUMPFW_XFER_SIZE; i++) {
                if (memcmp(buf + i, needle, nlen) == 0) {
                    printf("  %-10s at 0x%04lX\n", needle, i);
                    found = 1;
                }
            }

            if (!found)
                printf("  %-10s not found\n", needle);
        }
    }

    printf("\n=== 0x8000 BOUNDARY CHECK ===\n\n");

    for (i = 0; i < DUMPFW_XFER_SIZE; i += 0x8000) {
        DWORD j;
        DWORD show = 64;

        if (i + show > DUMPFW_XFER_SIZE)
            show = DUMPFW_XFER_SIZE - i;

        printf("  Boundary 0x%04lX:\n", i);

        for (j = 0; j < show; j += 16) {
            DWORD k;

            printf("    %04lX  ", i + j);

            for (k = 0; k < 16 && j + k < show; k++)
                printf("%02X ", buf[i + j + k]);

            for (; k < 16; k++)
                printf("   ");

            printf(" ");

            for (k = 0; k < 16 && j + k < show; k++) {
                UCHAR ch = buf[i + j + k];
                putchar((ch >= 0x20 && ch <= 0x7E) ? ch : '.');
            }

            printf("\n");
        }

        printf("\n");
    }

    printf("=== SUMMARY ===\n\n");
    printf("  BDRFlash preamble reproduced immediately before 0x5A.\n");
    printf("  Unlock/service mode is still controlled manually.\n");
    printf("  Saved complete response: %s\n", fname);
    printf("  Size                   : 0x%04X (%u bytes)\n\n",
           DUMPFW_XFER_SIZE, DUMPFW_XFER_SIZE);

    free(buf);
    return 0;
}

/* Internal model string lookup table */
static const struct { WORD did; const char *str; } g_mdl_map[] = {
    { 0x8000, "PIONEER  BDR-207" },
    { 0x8130, "PIONEER BDR-XD04" }, /* from BDRFlash IDA */
    { 0x8211, "PIONEER BDR-TD05" },  /* 8211 -> TD05 per BDRFlash */
    { 0x8221, "PIONEER BDR-XS05" },
    { 0x8231, "PIONEER BDR-XD05" },
    { 0x8232, "PIONEER BDR-XD05" },
    { 0x8291, "PIONEER BDR-TD05" },  /* from BDRFlash IDA */
    { 0x8420, "PIONEER BDR-US02" },  /* from BDRFlash IDA */
    { 0x8520, "PIONEER BDR-US03" },  /* from BDRFlash IDA */
    { 0x8301, "PIONEER  BDR-208" },
    { 0x8410, "PIONEER BDR-US02" },
    { 0x8490, "PIONEER BDR-US02" },
    { 0x8510, "PIONEER BDR-US03" },
    { 0x8511, "PIONEER BDR-US03" },
    { 0x8600, "PIONEER  BDR-209" },
    { 0x8601, "PIONEER  BDR-209" },
    { 0x8721, "PIONEER BDR-XS06 " },
    { 0x8722, "PIONEER BDR-XS06 " },
    { 0x8800, "PIONEER  BDR-211" },
    { 0x8801, "PIONEER  BDR-211" },
    { 0x8A10, "PIONEER BDR-US04" },
    { 0x8B30, "PIONEER BDR-XS06" }, /* XD06U — confirmed from official updater */
    { 0x8D30, "PIONEER BDR-BDS7" },   /* 16 chars, no trailing space — per reference table */
    { 0x8D31, "PIONEER BDR-BDS7" },
    { 0x8E20, "PIONEER BDR-BDS7" },
    { 0x8E21, "PIONEER BDR-BDS7" },
    { 0x8F00, "PIONEER BDR-212T" },
    { 0x9000, "PIONEER BDR-X12T" },  /* from BDRFlash IDA */
    { 0x9001, "PIONEER BDR-X12T" },
    { 0x8F01, "PIONEER BDR-212T" },
    { 0x9330, "PIONEER BDR-BDS8" },   /* 16 chars, no trailing space — per reference table */
    { 0x9331, "PIONEER BDR-BDS8" },
    { 0x9400, "PIONEER BDR-213T" },   /* per reference table */
    { 0x9401, "PIONEER BDR-213T" },   /* per reference table */
    { 0x9620, "PIONEER BDR-XS08U" },
    { 0x9621, "PIONEER BDR-XS08U" },
    { 0, NULL }
};

static int cmd_unlock(void)
{
    UCHAR cdb[12];
    UCHAR buf[256];
    UCHAR sense[SENSE_SIZE] = {0};
    UCHAR sense2[SENSE_SIZE] = {0};
    UCHAR icdb[6] = {0x12,0,0,0,96,0};
    UCHAR inq[96] = {0};
    UCHAR rb[64] = {0};
    UCHAR payload[PAYLOAD_SIZE] = {0};
    UCHAR es[8] = {0};
    UCHAR escdb[10] = {0x4A,0x01,0,0,0x5A,0,0,0,0x08,0};
    UCHAR a0[16] = {0};
    UCHAR a0cdb[10] = {0x3C,0x02,0xA0,0,0,0x90,0,0,0x10,0};
    UCHAR preview[64] = {0};
    UCHAR psense[SENSE_SIZE] = {0};
    char  vendor[9]    = {0};
    char  model[17]    = {0};
    char  platform[12] = {0};
    char  kernelID[5]  = {0};
    char  serial[16]   = {0};
    int   j, i, k, scsiStatus = 0, st = 0;
    DWORD cap = 0;
    WORD  driveID = 0;
    DWORD unlockKey = 0x6123789A;
    char *p, *p2;

    printf("=== PIONEER RS8801 SERVICE MODE UNLOCK ===\n\n");

    /* Step 1: INQUIRY */
    printf("[1/6] INQUIRY...\n");
    {
        memset(inq, 0, sizeof(inq));
        send_scsi(g_hDrive, icdb, 6, inq, 96, SCSI_IOCTL_DATA_IN, sense, &st);
        if (st != 0) { fprintf(stderr, "  INQUIRY failed\n"); return 1; }
        memcpy(vendor, &inq[8],  8);
        memcpy(model,  &inq[16], 16);
        for (j=7;  j>=0 && vendor[j]==' '; j--) vendor[j] = '\0';
        for (j=15; j>=0 && model[j]==' ';  j--) model[j]  = '\0';
        printf("  Vendor  : %s\n", vendor);
        printf("  Model   : %s\n\n", model);
        if (strncmp(vendor, "PIONEER", 7) != 0) {
            fprintf(stderr, "  ERROR: Not a Pioneer drive\n"); return 1;
        }
    }

    /* ================================================================
       CRITICAL ZERO-DELAY SECTION
       All SCSI ops must happen back-to-back before any printfs!
       Post-cutoff drives enter kernel mode on 0xF1 read — unlock
       must follow immediately after.
       ================================================================ */

    /* 2a: Read 0xA0 to get model string BEFORE 0xF1 triggers kernel mode */
    {
        UCHAR a0pre[0x100] = {0};
        UCHAR a0presense[SENSE_SIZE] = {0};
        UCHAR a0precdb[10] = {0x3C,0x02,0xA0,0,0,0x90,0,0,0x10,0};
        int a0prest = 0;
        send_scsi(g_hDrive, a0precdb, 10, a0pre, 0x100,
                  SCSI_IOCTL_DATA_IN, a0presense, &a0prest);
        if (a0prest == 0 && a0pre[0] >= 0x20) {
            memcpy(g_a0token, a0pre, 0x10);
            g_has_token = 2;
        }
    }

    /* 2b: Read 0xF1 — may trigger kernel mode on post-cutoff drives */
    rb_data(0xF1, 0, rb, 0x30, sense2);

    /* Parse 0xF1 for serial/platform */
    for (j=0; j<12 && rb[j]>=0x20&&rb[j]<0x7F; j++) serial[j]   = rb[j];
    for (j=0; j<8  && rb[16+j]>=0x20&&rb[16+j]<0x7F; j++) platform[j] = rb[16+j];
    for (j=0; j<4  && rb[24+j]>=0x20&&rb[24+j]<0x7F; j++) kernelID[j] = rb[24+j];
    p = platform;
    while (*p && (*p < '0' || *p > '9')) p++;
    if (*p) driveID = (WORD)strtol(p, NULL, 16);
    unlockKey = pioneer_key_lookup(driveID, kernelID);
    if (!unlockKey) unlockKey = 0x6123789A;
    if (g_key_override) unlockKey = g_key_override;

    /* 2c: Build payload — always use g_mdl_map, 0xA0 never returns correct model string */
    memset(payload, 0, PAYLOAD_SIZE);
    {
        int mi;
        for (mi = 0; g_mdl_map[mi].did; mi++) {
            if (g_mdl_map[mi].did == driveID) {
                memcpy(payload, g_mdl_map[mi].str, 16);
                break;
            }
        }
        if (!payload[0]) {
            /* Fallback: PIONEER + model from INQUIRY */
            memcpy(payload, "PIONEER BDR-    ", 16);
            p2 = strstr(model, "BDR-");
            if (p2) { for (k=0; k<7&&p2[k]&&p2[k]!=' '; k++) payload[9+k]=(UCHAR)p2[k]; }
        }
    }
    payload[0x10]=(UCHAR)(unlockKey>> 0);
    payload[0x11]=(UCHAR)(unlockKey>> 8);
    payload[0x12]=(UCHAR)(unlockKey>>16);
    payload[0x13]=(UCHAR)(unlockKey>>24);

    /* Step 3: WRITE BUFFER unlock sweep — try all modes immediately! */
    {
        UCHAR modes[]  = {0x04, 0x01, 0x00, 0x0A, 0x0B, 0x0C, 0x0D};
        UCHAR bufids[] = {0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        int found = 0;
        for (i = 0; i < 7; i++) {
            UCHAR ucdb[10] = {0x3B,modes[i],bufids[i],0,0,0,0,0x00,0x20,0};
            UCHAR usense[SENSE_SIZE] = {0};
            int ust = 0;
            send_scsi(g_hDrive, ucdb, 10, payload, 0x20,
                      SCSI_IOCTL_DATA_OUT, usense, &ust);
            if (ust == 0 || (usense[2]&0x0F) == 0x00) {
                g_unlock_mode  = modes[i];
                g_unlock_bufid = bufids[i];
                found = 1;
                memcpy(sense, usense, SENSE_SIZE);
                break;
            }
            memcpy(sense, usense, SENSE_SIZE);
        }

        /* ===== NOW safe to print ===== */
        printf("[2/6] READ BUFFER 0xF1...\n");
        {
            char month[16]={0}, year[32]={0}, country[32]={0};
            pioneer_serial_decode(serial, month, year, country);
            printf("  Serial  : %s\n", serial);
            printf("  Mfg Date: %s %s\n", month, year);
            printf("  Country : %s\n", country);
            printf("  Platform: %s\n", platform);
            printf("  Drive ID: 0x%04X\n\n", driveID);
        }

        printf("[3/6] WRITE BUFFER unlock...\n");
        printf("  Payload : %.16s + 0x%08lX\n", (char*)payload, unlockKey);
        if (found) {
            printf("  Status  : GOOD (mode=0x%02X bufID=0x%02X)\n\n",
                   g_unlock_mode, g_unlock_bufid);
        } else {
            printf("  Status  : FAIL (key=%02X ASC=%02X)\n",
                   sense[2]&0x0F, sense[12]);
            printf("  ERROR: All unlock modes rejected.\n");
            return 1;
        }
    }
    Sleep(500);

    /* Step 4: GET EVENT STATUS */
    printf("[4/6] GET EVENT STATUS...\n");
    send_scsi(g_hDrive, escdb, 10, es, 8, SCSI_IOCTL_DATA_IN, sense, &scsiStatus);
    printf("  Event: %02X %02X %02X %02X\n\n", es[0],es[1],es[2],es[3]);
    Sleep(100);

    /* Step 5: INQUIRY again */
    printf("[5/6] INQUIRY (2nd)...\n");
    cmd_inquiry();

    /* Step 6: READ BUFFER 0xA0 */
    printf("[6/6] READ BUFFER 0xA0...\n");
    send_scsi(g_hDrive, a0cdb, 10, a0, 16, SCSI_IOCTL_DATA_IN, sense, &scsiStatus);
    printf("  Response: ");
    for (i = 0; i < 16; i++) printf("%02X ", a0[i]);
    printf("\n\n");
    Sleep(100);

    /* Verify 0xF4 accessibility */
    printf("Verifying 0xF4 accessibility...\n");
    if (!rb_descriptor(0xF4, &cap) && cap > 0) {
        printf("  0xF4 accessible! Capacity: 0x%08lX bytes\n", cap);
        if (rb_data(0xF4, 0, preview, 64, psense) == 0) {
            printf("  Preview:");
            hex_dump(preview, 64, 64);
        }
        printf("\n  *** Service mode active ***\n");
        printf("  Run: drivekit rawdump %c\n", g_drivePath[4]);
    } else {
        printf("  0xF4 not accessible after unlock.\n");
        printf("  Key may be incorrect - try: drivekit brutekey %c\n", g_drivePath[4]);
    }

    return 0;
}

/* =========================================================
   CMD_HWDUMP
   Enable hardware dump mode on post-cutoff Pioneer drives.

   Confirmed from Wireshark capture of MakeMKV session:
   WRITE BUFFER mode=0x02 bufID=0x41 len=0x03 data=A5 AA AA
   Status: GOOD on post-cutoff drives.

   After this command:
   - READ BUFFER 0xB0 becomes accessible (H8S/2600 code readable!)
   - READ BUFFER 0xF4 NAND dump accessible
   - LibreDrive features enabled for UHD reading

   Usage:
     drivekit hwdump E
   ========================================================= */
static int cmd_hwdump(void)
{
    UCHAR sense[SENSE_SIZE] = {0};
    UCHAR payload[1] = {0}; /* zero length */
    int   st = 0;

    printf("=== HWDUMP ===\n\n");

    /* Detect pre vs post-cutoff via INQUIRY date at [0x25]
       BDRFlash cutoff: 22/12/01
       Pre-cutoff:  offset 0x00AAAA, 0xB0 from 0x100000
       Post-cutoff: offset 0xA5AAAA, 0xB0 from 0x500000 */
    int is_pre_cutoff = 1;
    {
        UCHAR inq[64]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
        UCHAR inqcdb[6]={0x12,0,0,0,64,0};
        send_scsi(g_hDrive,inqcdb,6,inq,64,SCSI_IOCTL_DATA_IN,inqs,&inqst);
        if (inqst == 0 && inq[0x25] >= 0x20) {
            char date[9]={0}; int di;
            for(di=0;di<8&&inq[0x25+di]>=0x20&&inq[0x25+di]<=0x7E;di++)
                date[di]=inq[0x25+di];
            is_pre_cutoff = (strcmp(date,"22/12/01") < 0);
        }
        printf("  Generation: %s\n\n",
               is_pre_cutoff ? "PRE-CUTOFF  (offset 0x00AAAA, 0xB0 from 0x100000)"
                             : "POST-CUTOFF (offset 0xA5AAAA, 0xB0 from 0x500000)");
    }

    UCHAR cdb[12] = {0x3B,0x02,0x41,
                     (UCHAR)(is_pre_cutoff ? 0x00 : 0xA5),0xAA,0xAA,
                     0,0,0,0,0,0};
    DWORD b0_start = 0x100000; /* both pre and post-cutoff start at 0x100000 */

    /* GET EVENT STATUS x4 then immediately 0x41 then 0xF4 then 0xB0 */
    {
        UCHAR masks[] = {0x5A, 0x58, 0x50, 0x40};
        int m;
        for (m = 0; m < 4; m++) {
            UCHAR esbuf[8]={0}; UCHAR escdb[10]={0x4A,0x01,0,0,masks[m],0,0,0,0x08,0};
            UCHAR essense[SENSE_SIZE]={0}; int esst=0;
            send_scsi(g_hDrive,escdb,10,esbuf,8,SCSI_IOCTL_DATA_IN,essense,&esst);
        }
    }
    send_scsi(g_hDrive, cdb, 12, payload, 0,
              SCSI_IOCTL_DATA_OUT, sense, &st);

    if (st == 0) {
        printf("  WRITE BUFFER 0x41 offset=%s: GOOD\n",
               is_pre_cutoff ? "0x00AAAA" : "0xA5AAAA");
        /* Immediately read 0xF4 then 0xB0 — window is ~5ms! */
        {
            UCHAR f4buf[0xA4] = {0};
            UCHAR f4cdb[10] = {0x3C,0x02,0xF4,0x83,0x94,0xB4,0,0,0xA4,0};
            UCHAR f4sense[SENSE_SIZE] = {0};
            int   f4st = 0;
            send_scsi(g_hDrive, f4cdb, 10, f4buf, 0xA4,
                      SCSI_IOCTL_DATA_IN, f4sense, &f4st);
        }
        /* Immediately try 0xB0 */
        {
            UCHAR b0buf[CHUNK_SIZE] = {0};
            UCHAR b0cdb[10] = {0x3C,0x02,0xB0,
                (UCHAR)(b0_start>>16),(UCHAR)(b0_start>>8),(UCHAR)(b0_start),
                0,(UCHAR)(CHUNK_SIZE>>8),(UCHAR)(CHUNK_SIZE),0};
            UCHAR b0sense[SENSE_SIZE] = {0};
            int   b0st = 0;
            send_scsi(g_hDrive, b0cdb, 10, b0buf, CHUNK_SIZE,
                      SCSI_IOCTL_DATA_IN, b0sense, &b0st);
            if (b0st == 0) {
                FILE *fp = fopen("hwdump_b0.bin", "wb");
                DWORD b0offset = b0_start;
                DWORD total = 0;
                printf("  0xB0 ACCESSIBLE! Dumping H8S/2600 kernel to hwdump_b0.bin...\n");
                printf("  (window is brief — dumping as fast as possible)\n");
                fflush(stdout);
                if (fp) fwrite(b0buf, 1, CHUNK_SIZE, fp);
                total += CHUNK_SIZE;
                while (1) {
                    UCHAR chunk[CHUNK_SIZE] = {0};
                    UCHAR csense[SENSE_SIZE] = {0};
                    int   cst = 0;
                    b0offset += CHUNK_SIZE;
                    UCHAR ccdb[10] = {0x3C,0x02,0xB0,
                        (UCHAR)(b0offset>>16),(UCHAR)(b0offset>>8),(UCHAR)(b0offset),
                        0,(UCHAR)(CHUNK_SIZE>>8),(UCHAR)(CHUNK_SIZE),0};
                    send_scsi(g_hDrive, ccdb, 10, chunk, CHUNK_SIZE,
                              SCSI_IOCTL_DATA_IN, csense, &cst);
                    if (cst != 0) break;
                    if (fp) fwrite(chunk, 1, CHUNK_SIZE, fp);
                    total += CHUNK_SIZE;
                    printf("\r  Dumped 0x%06X bytes...", total);
                    fflush(stdout);
                }
                if (fp) fclose(fp);
                printf("\n  Total dumped: 0x%06X bytes to hwdump_b0.bin\n\n", total);
            } else {
                printf("  0xB0 still locked (key=%02X ASC=%02X)\n\n",
                       b0sense[2]&0x0F, b0sense[12]);
            }
        }
    } else {
        printf("  Status  : FAIL (key=%02X ASC=%02X)\n\n",
               sense[2]&0x0F, sense[12]);
        printf("  Drive may already be in hardware dump mode,\n");
        printf("  or this drive family uses a different sequence.\n\n");
    }

    return st == 0 ? 0 : 1;
}



/* =========================================================
   COMMAND: e5test
   Tests the WRITE BUFFER 0xE5 "Engineering Mode" flag setter
   discovered by MrPenguin in XD08U H8S/2600 disassembly.
   
   From MrPenguin's analysis:
   - WRITE 0xE5 with payload 0x01 sets flag @0xA0CE7E = 1
   - This enables the 0xFF "Engineering Mode" backdoor
   - Which may bypass the version check!
   - Length must be exactly 2 bytes
   
   Sequence:
   1. WRITE 0xE5 len=2 payload=01  → enable engineering mode
   2. Check 0xF4 accessibility
   3. Try WRITE 0xFF with various payloads
   4. Try flashing older firmware
   ========================================================= */
static int cmd_e5test(void)
{
    UCHAR sense[SENSE_SIZE] = {0};
    UCHAR payload[0x100] = {0};
    int st = 0, i;

    printf("=== E5 ENGINEERING MODE TEST ===\n\n");
    printf("Based on MrPenguin's H8S/2600 disassembly of XD08U.\n");
    printf("Testing WRITE BUFFER 0xE5 flag setter...\n\n");

    /* Try WRITE 0xE5 with length=2, payload=0x01 (enable) */
    printf("[1] WRITE BUFFER 0xE5 len=2 payload=0x01 (ENABLE)...\n");
    {
        UCHAR cdb[10] = {0x3B,0x04,0xE5,0,0,0,0,0x00,0x02,0};
        payload[0] = 0x01;
        send_scsi(g_hDrive, cdb, 10, payload, 2, SCSI_IOCTL_DATA_OUT, sense, &st);
        printf("  Status: %s", (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
        if (st != 0) printf(" (key=%02X ASC=%02X)", sense[2]&0xF, sense[12]);
        printf("\n\n");
    }

    /* Try different modes for 0xE5 */
    printf("[2] Sweeping modes for WRITE 0xE5...\n");
    UCHAR modes[] = {0x00,0x01,0x04,0x06,0x07};
    for (i = 0; i < 5; i++) {
        UCHAR cdb[10] = {0x3B,modes[i],0xE5,0,0,0,0,0x00,0x02,0};
        memset(sense, 0, sizeof(sense));
        payload[0] = 0x01; payload[1] = 0x00;
        send_scsi(g_hDrive, cdb, 10, payload, 2, SCSI_IOCTL_DATA_OUT, sense, &st);
        printf("  mode=0x%02X: %s", modes[i],
               (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
        if (st != 0) printf(" (key=%02X ASC=%02X)", sense[2]&0xF, sense[12]);
        printf("\n");
    }

    /* Check if 0xF4 is accessible after E5 */
    printf("\n[3] Checking 0xF4 accessibility after 0xE5...\n");
    {
        UCHAR cdb[10] = {0x3C,0x02,0xF4,0,0,0,0,0,0x40,0};
        UCHAR rbuf[64] = {0};
        send_scsi(g_hDrive, cdb, 10, rbuf, 64, SCSI_IOCTL_DATA_IN, sense, &st);
        printf("  0xF4: %s\n", (st==0||(sense[2]&0xF)==0)?"ACCESSIBLE!":"not available");
        if (st==0||(sense[2]&0xF)==0) {
            printf("  First bytes: %02X %02X %02X %02X\n",
                   rbuf[0],rbuf[1],rbuf[2],rbuf[3]);
        }
    }

    /* Try WRITE 0xFF Engineering Mode with drive-specific payload */
    printf("\n[4] Testing 0xFF Engineering Mode...\n");
    {
        UCHAR cdb[10] = {0x3B,0x04,0xFF,0,0,0,0,0x01,0x00,0};
        UCHAR epayload[0x100] = {0};
        build_pioneer_payload_auto(epayload);
        send_scsi(g_hDrive, cdb, 10, epayload, 0x100, SCSI_IOCTL_DATA_OUT, sense, &st);
        printf("  0xFF drive payload: %s", (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
        if (st != 0) printf(" (key=%02X ASC=%02X)", sense[2]&0xF, sense[12]);
        printf("\n");
    }

    printf("\nDone! Engineering mode enabled - run flashfw now!\n");
    return 0;
}

static int cmd_probevendor(void)
{
    UCHAR buf[256], sense[SENSE_SIZE], cdb[12];
    UCHAR sense2[SENSE_SIZE];
    UCHAR tur[6] = {0,0,0,0,0,0};
    UCHAR rs[6]  = {0x03,0,0,0,0x12,0};
    UCHAR rb[18];
    UCHAR key, asc, ascq;
    int   scsiStatus, st2;
    int   hasData;
    int   op;
    int   j;

    printf("=== VENDOR COMMAND PROBE 0xC0-0xFF ===\n\n");
    printf("  (showing only non-0x20 responses)\n\n");
    printf("  WARNING: some commands may lock the drive.\n");
    printf("  Power cycle required if drive stops responding.\n\n");

    for (op = 0xC0; op <= 0xFF; op++) {
        memset(cdb, 0, sizeof(cdb));
        memset(buf, 0, sizeof(buf));
        cdb[0] = (UCHAR)op;
        cdb[8] = 0xFF;

        send_scsi(g_hDrive, cdb, 12, buf, 256,
                  SCSI_IOCTL_DATA_IN, sense, &scsiStatus);

        key  = sense[2]&0x0F;
        asc  = sense[12];
        ascq = sense[13];

        /* Recovery: TUR after each command */
        Sleep(100);
        send_scsi(g_hDrive, tur, 6, NULL, 0,
                  SCSI_IOCTL_DATA_UNSPECIFIED, sense2, &st2);
        if (st2 != 0 && (sense2[2]&0x0F) != 0x02 &&
                         (sense2[2]&0x0F) != 0x06) {
            send_scsi(g_hDrive, rs, 6, rb, 18,
                      SCSI_IOCTL_DATA_IN, sense2, &st2);
        }

        if (key==0x05 && asc==0x20) continue;

        hasData = 0;
        for (j = 0; j < 16; j++)
            if (buf[j]) { hasData=1; break; }

        printf("  0x%02X  status=%02X  key=%02X ASC=%02X ASCQ=%02X",
               op, scsiStatus, key, asc, ascq);

        if (scsiStatus==0 && hasData) {
            printf("  data: ");
            for (j = 0; j < 8; j++) printf("%02X ", buf[j]);
        } else if (key==0x05 && asc==0x24) {
            printf("  (invalid field - cmd exists)");
        } else if (key==0x07) {
            printf("  (data protect)");
        } else if (scsiStatus==0) {
            printf("  (good, no data)");
        }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}

/* =========================================================
   COMMAND: discinfo
   Reads and parses BD/DVD disc information from standard
   MMC READ DISC STRUCTURE (0xAD) commands.
   Displays label, timestamp, protection, capacity, layers.
   ========================================================= */
static int cmd_discinfo(void)
{
    UCHAR   buf[4096];
    UCHAR   sense[SENSE_SIZE];
    UCHAR   cdb[12];
    int     st = 0;
    int     i;

    printf("=== DISC INFORMATION ===\n\n");

    /* Helper: read a disc structure */
    #define READ_DS(code, buf, len) do { \
        memset(cdb, 0, 12); \
        cdb[0]=0xAD; cdb[1]=(UCHAR)((code)>>8); \
        cdb[7]=(UCHAR)(code); \
        cdb[8]=(UCHAR)((len)>>8); cdb[9]=(UCHAR)(len); \
        memset(buf, 0, len); \
        send_scsi(g_hDrive, cdb, 12, buf, len, \
                  SCSI_IOCTL_DATA_IN, sense, &st); \
    } while(0)

    /* --- Current profile (disc type) --- */
    {
        UCHAR cfg[32];
        UCHAR cfgcdb[10] = {0x46,0,0,0,0,0,0,0,0x20,0};
        memset(cfg, 0, sizeof(cfg));
        send_scsi(g_hDrive, cfgcdb, 10, cfg, 32,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0) {
            WORD profile = ((WORD)cfg[6]<<8)|cfg[7];
            const char *pname = "Unknown";
            switch(profile) {
                case 0x0008: pname = "CD-ROM"; break;
                case 0x0009: pname = "CD-R"; break;
                case 0x000A: pname = "CD-RW"; break;
                case 0x0010: pname = "DVD-ROM"; break;
                case 0x0011: pname = "DVD-R"; break;
                case 0x0012: pname = "DVD-RAM"; break;
                case 0x0013: pname = "DVD-RW Restricted"; break;
                case 0x0014: pname = "DVD-RW"; break;
                case 0x0015: pname = "DVD-R DL Sequential"; break;
                case 0x001A: pname = "DVD+RW"; break;
                case 0x001B: pname = "DVD+R"; break;
                case 0x002B: pname = "DVD+R DL"; break;
                case 0x0040: pname = "BD-ROM"; break;
                case 0x0041: pname = "BD-R SRM"; break;
                case 0x0042: pname = "BD-R RRM"; break;
                case 0x0043: pname = "BD-RE"; break;
                case 0x0050: pname = "HD DVD-ROM"; break;
                case 0x0051: pname = "HD DVD-R"; break;
                case 0x0052: pname = "HD DVD-RAM"; break;
            }
            printf("  Disc type      : %s (profile 0x%04X)\n",
                   pname, profile);
        }
    }

    /* --- BD Disc Information (DI) structure 0x0100 --- */
    READ_DS(0x0100, buf, sizeof(buf));
    if (st == 0) {
        UCHAR *di = buf + 4;  /* skip 4-byte header */
        int rest = (int)(((WORD)buf[0]<<8)|buf[1]) - 2;

        while (rest > 12) {
            /* Each DI unit starts with "DI" */
            if (di[0] != 'D' || di[1] != 'I') break;

            int unit_size = 0;
            char disc_type_id[4] = {0};
            memcpy(disc_type_id, di+8, 3);

            if      (!memcmp(disc_type_id,"BDO",3)) unit_size=64;
            else if (!memcmp(disc_type_id,"BDW",3)) unit_size=112;
            else if (!memcmp(disc_type_id,"BDR",3)) unit_size=112;
            else if (!memcmp(disc_type_id,"BDU",3)) unit_size=64;
            else break;

            if (unit_size > rest) break;

            /* Disc category / version */
            UCHAR category = di[2];
            UCHAR version  = di[3];
            printf("  BD category    : %s v%d.%d\n",
                   disc_type_id, (version>>4)&0xF, version&0xF);

            /* Number of layers */
            UCHAR layers = ((di[11] >> 4) & 0x3) + 1;
            printf("  Layers         : %d\n", layers);

            /* Channel bit length → capacity */
            UCHAR cbl = di[10] & 0x0F;
            const char *cbl_str = "Unknown";
            const char *cap_str = "Unknown";
            switch(cbl) {
                case 0: cbl_str="74.5 nm"; cap_str="25.0 GB"; break;
                case 1: cbl_str="69.0 nm"; cap_str="27.0 GB"; break;
                case 2: cbl_str="64.0 nm"; cap_str="29.0 GB"; break;
                case 8: cbl_str="74.5 nm"; cap_str="25.0 GB (DL)"; break;
            }
            printf("  Channel bit    : %s (%s max per layer)\n",
                   cbl_str, cap_str);

            /* Disc size */
            UCHAR disc_size = (di[10] >> 4) & 0x0F;
            printf("  Disc size      : %s\n",
                   disc_size==0 ? "120 mm" :
                   disc_size==1 ? "80 mm"  : "Unknown");

            /* Disc label (bytes 32-63 in BD-ROM DI unit) */
            if (unit_size >= 64) {
                char label[33] = {0};
                int llen = 0;
                for (i = 0; i < 32; i++) {
                    if (di[32+i] == 0) break;
                    if (di[32+i] >= 0x20 && di[32+i] < 0x7F)
                        label[llen++] = di[32+i];
                }
                if (llen > 0)
                    printf("  Label          : %s\n", label);
            }

            di   += unit_size;
            rest -= unit_size;
        }
    }

    /* --- BD Physical Format Information 0x0000 --- */
    READ_DS(0x0000, buf, 0x3F0);
    if (st == 0 && ((WORD)buf[0]<<8|buf[1]) >= 4) {
        UCHAR *d = buf + 4;
        /* Total capacity in sectors (3 bytes at +5) */
        DWORD sectors = ((DWORD)d[5]<<16)|((DWORD)d[6]<<8)|d[7];
        double gb = (double)sectors * 2048.0 / 1000000000.0;
        printf("  Data capacity  : %.2f GB (%lu sectors)\n",
               gb, sectors);
    }

    /* --- Copyright / Protection info 0x0001 --- */
    READ_DS(0x0001, buf, 0x10);
    if (st == 0 && ((WORD)buf[0]<<8|buf[1]) >= 4) {
        UCHAR *d = buf + 4;
        UCHAR cptype = d[0];
        UCHAR region = d[1];
        const char *cp = "None";
        if (cptype == 0x01) cp = "AACS";
        if (cptype == 0x02) cp = "AACS 2.0";
        printf("  Protection     : %s", cp);
        if (region) printf(" (region 0x%02X)", region);
        printf("\n");
    }

    /* --- AACS version from feature 0x010D --- */
    {
        UCHAR feat[32];
        UCHAR fcdb[10] = {0x46,0x00,0x01,0x0D,0,0,0,0,0x20,0};
        memset(feat, 0, sizeof(feat));
        send_scsi(g_hDrive, fcdb, 10, feat, 32,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0 && feat[9] == 0x0D) {
            UCHAR ver = feat[12];
            printf("  AACS version   : v%d\n", ver);
        }
    }

    /* --- Disc serial number from READ DISC STRUCTURE 0x0080 --- */
    READ_DS(0x0080, buf, 0x20);
    if (st == 0 && ((WORD)buf[0]<<8|buf[1]) >= 4) {
        printf("  Disc serial    : ");
        for (i = 4; i < 20; i++) printf("%02X", buf[i]);
        printf("\n");
    }

    /* --- TOC / timestamps --- */
    {
        UCHAR toc[0x3F0];
        UCHAR tcdb[10] = {0x43,0,0,0,0,0,0,0x03,0xF0,0};
        memset(toc, 0, sizeof(toc));
        send_scsi(g_hDrive, tcdb, 10, toc, sizeof(toc),
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0) {
            /* Try to find recording timestamp in TOC */
            WORD tlen = ((WORD)toc[0]<<8)|toc[1];
            if (tlen > 4) {
                /* Recording date sometimes in track descriptor */
                /* Year at offset 4+20, month+4+21, day+4+22 */
                int year  = toc[4+20] + 1900;
                int month = toc[4+21];
                int day   = toc[4+22];
                int hour  = toc[4+23];
                int min   = toc[4+24];
                int sec   = toc[4+25];
                if (year > 1980 && month >= 1 && month <= 12) {
                    printf("  Timestamp      : %04d-%02d-%02d %02d:%02d:%02d\n",
                           year, month, day, hour, min, sec);
                }
            }
        }
    }

    #undef READ_DS
    printf("\n");
    return 0;
}

/* Feature code names - covers all defined MMC features */
static const char *feature_name(WORD code)
{
    switch (code) {
    case 0x0000: return "Profile List";
    case 0x0001: return "Core";
    case 0x0002: return "Morphing";
    case 0x0003: return "Removable Medium";
    case 0x0004: return "Write Protect";
    case 0x0010: return "Random Readable";
    case 0x001D: return "Multi-Read";
    case 0x001E: return "CD Read";
    case 0x001F: return "DVD Read";
    case 0x0020: return "Random Writable";
    case 0x0021: return "Incremental Streaming Writable";
    case 0x0022: return "Sector Erasable";
    case 0x0023: return "Formattable";
    case 0x0024: return "Defect Management";
    case 0x0025: return "Write Once";
    case 0x0026: return "Restricted Overwrite";
    case 0x0027: return "CD-RW CAV Write";
    case 0x0028: return "MRW";
    case 0x0029: return "Enhanced Defect Reporting";
    case 0x002A: return "DVD+RW";
    case 0x002B: return "DVD+R";
    case 0x002C: return "Rigid Restricted Overwrite";
    case 0x002D: return "CD Track At Once";
    case 0x002E: return "CD Mastering";
    case 0x002F: return "DVD-R/-RW Write";
    case 0x0030: return "Double Density CD Read";
    case 0x0031: return "Double Density CD-R Write";
    case 0x0032: return "Double Density CD-RW Write";
    case 0x0033: return "Layer Jump Recording";
    case 0x0037: return "CD-RW Media Write";
    case 0x0038: return "BD-R POW";
    case 0x003A: return "DVD+RW DL";
    case 0x003B: return "DVD+R DL";
    case 0x0040: return "BD Read";
    case 0x0041: return "BD Write";
    case 0x0042: return "TSR";
    case 0x0050: return "HD DVD Read";
    case 0x0051: return "HD DVD Write";
    case 0x0052: return "HD DVD-RW Fragment Recording";
    case 0x0080: return "Hybrid Disc";
    case 0x0100: return "Power Management";
    case 0x0101: return "SMART";
    case 0x0102: return "Embedded Changer";
    case 0x0103: return "CD Audio External Play";
    case 0x0104: return "Microcode Upgrade";
    case 0x0105: return "Timeout";
    case 0x0106: return "DVD CSS";
    case 0x0107: return "Real Time Streaming";
    case 0x0108: return "Drive Serial Number";
    case 0x0109: return "Media Serial Number";
    case 0x010A: return "Disc Control Blocks";
    case 0x010B: return "DVD CPRM";
    case 0x010C: return "Firmware Information";
    case 0x010D: return "AACS";
    case 0x010E: return "DVD CSS Managed Recording";
    case 0x0110: return "VCPS";
    case 0x0113: return "*** LibreDrive / Hardware Raw Access ***";
    case 0x0120: return "BD CPS";
    case 0x0142: return "OSSC";
    default:     return "Unknown";
    }
}

static int cmd_querydriveinfo(void)
{
    UCHAR    buf[288];   /* 256+32 like MakeMKV */
    UCHAR    sense[SENSE_SIZE];
    int      st = 0;
    DWORD    current_feature = 0;
    DWORD    first_feature   = 0;
    int      total_features  = 0;
    FILE    *fp              = NULL;
    int      i;

    printf("=== FULL DRIVE INFORMATION (MakeMKV QueryDriveInfo) ===\n\n");

    /* ---- Step 1: INQUIRY ---- */
    printf("[INQUIRY]\n");
    {
        UCHAR cdb[6] = {0x12, 0, 0, 0, 96, 0};
        UCHAR inq[96];
        char  vendor[9]={0}, model[17]={0}, rev[5]={0};
        int   j;

        memset(inq, 0, sizeof(inq));
        send_scsi(g_hDrive, cdb, 6, inq, 96,
                  SCSI_IOCTL_DATA_IN, sense, &st);

        if (st != 0) {
            fprintf(stderr, "  INQUIRY failed\n");
            return 1;
        }

        memcpy(vendor, &inq[8],  8);  vendor[8]  = '\0';
        memcpy(model,  &inq[16], 16); model[16]  = '\0';
        memcpy(rev,    &inq[32], 4);  rev[4]     = '\0';
        for (j=7;  j>=0 && vendor[j]==' '; j--) vendor[j] = '\0';
        for (j=15; j>=0 && model[j]==' ';  j--) model[j]  = '\0';
        for (j=3;  j>=0 && rev[j]==' ';    j--) rev[j]    = '\0';

        printf("  Vendor   : %s\n", vendor);
        printf("  Model    : %s\n", model);
        printf("  Firmware : %s\n", rev);
        /* Firmware date at INQUIRY[0x25] (confirmed MrPenguin) */
        {
            char fwdate[16] = {0}; int k;
            for (k=0; k<8 && inq[0x25+k]>=0x20 && inq[0x25+k]<=0x7E; k++)
                fwdate[k] = inq[0x25+k];
            for (k=7; k>=0 && fwdate[k]==' '; k--) fwdate[k]=0;
            if (fwdate[0] && fwdate[2]=='/') printf("  FW Date  : %s\n", fwdate);
        }
        printf("\n");

        /* MakeMKV check: (data_buffer[0]&0x1f)!=5 -> not MMC */
        if ((inq[0] & 0x1F) != 5) {
            fprintf(stderr,
                    "  Device type 0x%02X - not an MMC optical drive\n",
                    inq[0] & 0x1F);
            return 1;
        }
    }

    /* Open output file if requested */
    if (g_outFile[0]) {
        fp = fopen(g_outFile, "wb");
        if (!fp)
            fprintf(stderr, "  Warning: cannot create %s\n", g_outFile);
    }

    /* ---- Step 2: Iterate ALL feature descriptors ----
       Mirrors MakeMKV exactly:
         while(current_feature < 0x10000)
           GET CONFIGURATION starting at current_feature
           parse each descriptor
           advance current_feature past last seen code    */

    printf("[GET CONFIGURATION - all feature descriptors]\n\n");

    while (current_feature < 0x10000) {
        UCHAR  cdb[10];
        DWORD  len, slen;
        const  UCHAR *dptr;

        memset(cdb, 0, sizeof(cdb));
        memset(buf, 0, sizeof(buf));

        cdb[0] = 0x46;                              /* GET CONFIGURATION */
        cdb[1] = 0x02;                              /* RT=10 - starting feature */
        cdb[2] = (UCHAR)(current_feature >> 8);
        cdb[3] = (UCHAR)(current_feature);
        cdb[7] = (UCHAR)(sizeof(buf) >> 8);
        cdb[8] = (UCHAR)(sizeof(buf));

        if (send_scsi(g_hDrive, cdb, 10, buf, sizeof(buf),
                      SCSI_IOCTL_DATA_IN, sense, &st)) {
            fprintf(stderr, "  IOCTL error at feature 0x%04lX\n",
                    current_feature);
            break;
        }

        /* MakeMKV: if (res.Status!=0) break */
        if (st != 0) break;

        /* MakeMKV: slen = rd32be(data_buffer) + 4 */
        slen = (((DWORD)buf[0]<<24)|((DWORD)buf[1]<<16)|
                ((DWORD)buf[2]<<8)|(DWORD)buf[3]) + 4;

        len = sizeof(buf);
        if (slen > len) slen = len;

        /* MakeMKV: if (slen==8) break - empty header */
        if (slen == 8) break;

        if (slen < 12) {
            fprintf(stderr,
                    "  Bad data at feature 0x%04lX (slen=%lu)\n",
                    current_feature, slen);
            break;
        }

        /* Skip 8-byte header to reach first feature descriptor */
        dptr = buf + 8;
        slen -= 8;

        first_feature = current_feature;

        /* Walk all feature descriptors in this response */
        while (slen >= 4) {
            WORD  fcode;
            DWORD flen;

            fcode = ((WORD)dptr[0]<<8) | dptr[1];

            /* MakeMKV wraparound detection */
            if ((fcode < first_feature) ||
                ((current_feature != 0) && (fcode == 0))) {
                current_feature = 0x10000;
                break;
            }

            flen = 4 + (DWORD)dptr[3];

            if (flen > slen) {
                if (fcode >= current_feature)
                    current_feature = fcode + 1;
                break;
            }

            /* Print feature */
            printf("  Feature 0x%04X  %-42s",
                   fcode, feature_name(fcode));

            /* Persistent and Current bits from byte 2 */
            UCHAR persistent = (dptr[2] >> 1) & 1;
            UCHAR current    =  dptr[2]        & 1;
            printf("  P=%u C=%u  len=%lu\n",
                   persistent, current, flen);

            /* Dump feature data for key features */
            if (flen > 4) {
                printf("    Data:");
                for (i = 4; i < (int)flen && i < 20; i++)
                    printf(" %02X", dptr[i]);
                if (flen > 20) printf(" ...");
                printf("\n");
            }

            /* Decode specific features */
            switch (fcode) {
            case 0x0001: /* Core */
                if (flen >= 8) {
                    DWORD phys = ((DWORD)dptr[4]<<24)|
                                 ((DWORD)dptr[5]<<16)|
                                 ((DWORD)dptr[6]<<8)|dptr[7];
                    printf("    Physical interface: 0x%08lX (%s)\n",
                           phys,
                           phys==0x00000001?"SCSI family":
                           phys==0x00000002?"ATAPI":
                           phys==0x00000003?"IEEE 1394 - 1995":
                           phys==0x00000004?"IEEE 1394A":
                           phys==0x00000005?"Fibre Channel":
                           phys==0x00000006?"IEEE 1394B":
                           phys==0x00000007?"Serial ATAPI":
                           phys==0x00000008?"USB":
                           phys==0x0000FFFF?"Vendor unique":"Other");
                }
                break;
            case 0x0003: /* Removable Medium */
                if (flen >= 8) {
                    UCHAR load = (dptr[4] >> 5) & 7;
                    printf("    Load mechanism: %s\n",
                           load==0?"Caddy":
                           load==1?"Tray":
                           load==2?"Pop-up":
                           load==4?"Changer (individual)":
                           load==5?"Changer (cartridge)":"Other");
                }
                break;
            case 0x0108: /* Drive Serial Number */
                if (flen > 4) {
                    char sn[32] = {0};
                    int  snlen  = (int)flen - 4;
                    if (snlen > 31) snlen = 31;
                    memcpy(sn, dptr+4, snlen);
                    printf("    Serial number: %s\n", sn);
                }
                break;
            case 0x010C: /* Firmware Information */
                if (flen >= 12) {
                    printf("    Century: %02X%02X  Year: %02X%02X"
                           "  Month: %02X  Day: %02X"
                           "  Hour: %02X  Min: %02X\n",
                           dptr[4],dptr[5],dptr[6],dptr[7],
                           dptr[8],dptr[9],dptr[10],dptr[11]);
                }
                break;
            case 0x0113: /* LibreDrive */
                printf("    *** LibreDrive / raw access PRESENT ***\n");
                break;
            }

            /* Save raw feature to file */
            if (fp) fwrite(dptr, 1, flen, fp);

            if (fcode >= current_feature)
                current_feature = fcode + 1;

            dptr += flen;
            slen -= flen;
            total_features++;
        }
    }

    if (fp) {
        fclose(fp);
        printf("\n  Raw features saved to %s\n", g_outFile);
    }

    printf("\n  Total features enumerated: %d\n", total_features);

    /* Summary of LibreDrive status */
    printf("\n  LibreDrive status: %s\n",
           total_features > 0 ? "checked above (look for 0x0113)" :
                                "no features returned");

    return 0;
}

/* =========================================================
   COMMAND: probeb0
   Reads and decodes READ BUFFER 0xB0 - the RS8801
   capability/LibreDrive data buffer discovered by
   capturing MakeMKV's SCSI traffic via Wireshark.

   MakeMKV reads this at offset 0x0004, length 0xA4 (164)
   immediately after READ BUFFER 0xF1 during drive init.
   This buffer appears to contain the LibreDrive capability
   flags, bus encryption flags and firmware information
   that MakeMKV uses to determine Status: Enabled.

   Usage:
     drivekit probeb0 G
     drivekit probeb0 G --file b0dump.bin
   ========================================================= */
static int cmd_probeb0(void)
{
    UCHAR  sense[SENSE_SIZE];
    UCHAR  buf[512];
    DWORD  cap = 0;
    int    i;
    FILE  *fp = NULL;

    printf("=== READ BUFFER 0xB0 (RS8801 Capability Data) ===\n\n");

    /* ---- Step 1: descriptor to get capacity ---- */
    printf("[1] Buffer descriptor:\n");
    if (rb_descriptor(0xB0, &cap) || cap == 0) {
        printf("  Buffer 0xB0 not available via descriptor.\n");
        printf("  Trying direct read at MakeMKV offset...\n\n");
    } else {
        printf("  Capacity: 0x%08lX (%lu bytes)\n\n", cap, cap);
    }

    /* ---- Step 2: read at offset 0 first - full preview ---- */
    printf("[2] Read at offset 0x0000, length 0x40:\n");
    memset(buf, 0xEE, sizeof(buf));
    if (rb_data(0xB0, 0x0000, buf, 0x40, sense) == 0) {
        printf("  Data:");
        for (i = 0; i < 0x40; i++) {
            if (i % 16 == 0) printf("\n    %04X  ", i);
            printf("%02X ", buf[i]);
        }
        printf("\n\n");

        /* Check for printable strings */
        printf("  Strings found:\n");
        char str[64] = {0};
        int  slen = 0, found = 0;
        for (i = 0; i < 0x40; i++) {
            if (buf[i] >= 0x20 && buf[i] < 0x7F) {
                if (slen < 63) str[slen++] = buf[i];
            } else {
                if (slen >= 4) {
                    str[slen] = '\0';
                    printf("    offset 0x%02X: \"%s\"\n", i-slen, str);
                    found++;
                }
                slen = 0;
                memset(str, 0, sizeof(str));
            }
        }
        if (!found) printf("    none\n");
    } else {
        printf("  Read failed: key=%02X ASC=%02X ASCQ=%02X\n\n",
               sense[2]&0x0F, sense[12], sense[13]);
    }

    /* ---- Step 3: read at MakeMKV's exact offset 0x0004 ---- */
    printf("[3] Read at MakeMKV offset 0x0004, length 0xA4 (164 bytes):\n");
    memset(buf, 0xEE, sizeof(buf));
    if (rb_data(0xB0, 0x0004, buf, 0xA4, sense) == 0) {
        printf("  Data:");
        for (i = 0; i < 0xA4; i++) {
            if (i % 16 == 0) printf("\n    %04X  ", i);
            printf("%02X ", buf[i]);
            if (i % 16 == 15) {
                int j, ls = i - 15;
                printf("  ");
                for (j = ls; j <= i; j++)
                    printf("%c",(buf[j]>=0x20&&buf[j]<0x7F)?buf[j]:'.');
            }
        }
        printf("\n\n");

        /* ---- Step 4: attempt to decode key fields ---- */
        printf("[4] Decoded fields:\n");

        /* Check for known RS8801 signatures */
        if (memmem_win(buf, 0xA4, "SAT", 3))
            printf("  *** SAT platform string found ***\n");
        if (memmem_win(buf, 0xA4, "PIONEER", 7))
            printf("  *** PIONEER string found ***\n");
        if (memmem_win(buf, 0xA4, "BDR", 3))
            printf("  *** BDR model string found ***\n");
        if (memmem_win(buf, 0xA4, "ID", 2))
            printf("  *** ID kernel string found ***\n");

        /* Byte 0 - possible capability/status flags */
        printf("\n  Byte[0x00] : 0x%02X", buf[0]);
        if (buf[0] & 0x01) printf(" REGION_FREE");
        if (buf[0] & 0x02) printf(" BD_RAW_READ");
        if (buf[0] & 0x04) printf(" BD_RAW_META");
        if (buf[0] & 0x08) printf(" UNREST_SPEED");
        if (buf[0] & 0x10) printf(" DVD_REGION_FREE");
        printf("\n");

        /* Bus encryption flags - MakeMKV reports these */
        printf("  Byte[0x01] : 0x%02X (possible bus enc flags)\n",
               buf[1]);

        /* Print all non-EE bytes with offset */
        printf("\n  Non-sentinel bytes:\n");
        for (i = 0; i < 0xA4; i++) {
            if (buf[i] != 0xEE)
                printf("    [0x%02X] = 0x%02X (%3u) '%c'\n",
                       i, buf[i], buf[i],
                       (buf[i]>=0x20&&buf[i]<0x7F)?buf[i]:'.');
        }

        /* Save to file */
        if (g_outFile[0]) {
            strncpy(g_outFile, g_outFile, sizeof(g_outFile)-1);
            fp = fopen(g_outFile, "wb");
        } else {
            fp = fopen("buf_B0.bin", "wb");
            printf("\n  Saving to buf_B0.bin...\n");
        }
        if (fp) {
            fwrite(buf, 1, 0xA4, fp);
            fclose(fp);
            printf("  Saved 0xA4 bytes.\n");
        }

    } else {
        printf("  Read failed: key=%02X ASC=%02X ASCQ=%02X\n",
               sense[2]&0x0F, sense[12], sense[13]);
        printf("\n  NOTE: Buffer 0xB0 may require service mode unlock first.\n");
        printf("  Try: drivekit unlock G  then  drivekit probeb0 G\n");
    }

    /* ---- Step 5: try full buffer range at various offsets ---- */
    printf("\n[5] Probing offsets 0x0000, 0x0004, 0x0008, 0x0010:\n");
    {
        DWORD offsets[] = {0x0000, 0x0004, 0x0008, 0x0010};
        int   n = sizeof(offsets)/sizeof(offsets[0]);
        for (i = 0; i < n; i++) {
            UCHAR tmp[16];
            memset(tmp, 0xEE, sizeof(tmp));
            if (rb_data(0xB0, offsets[i], tmp, 16, sense) == 0) {
                int j;
                printf("  offset 0x%04lX:", offsets[i]);
                for (j = 0; j < 16; j++) printf(" %02X", tmp[j]);
                printf("\n");
            } else {
                printf("  offset 0x%04lX: failed\n", offsets[i]);
            }
        }
    }

    return 0;
}

/* =========================================================
   COMMAND: modelcheck
   Pioneer drive model lookup table ported from BDRFlash
   sub_40EE0C. Identifies Pioneer drive by packed 16-bit
   drive ID value returned from READ BUFFER 0xF1.

   The original function uses a binary decision tree on
   a packed 16-bit value to return the model name string
   or NULL if not recognised.

   Usage:
     drivekit modelcheck G
   ========================================================= */

/* Drive capability tiers */
#define CAP_NONE    0   /* not recognised                */
#define CAP_DVD     1   /* DVD only                      */
#define CAP_BD      2   /* BD capable                    */
#define CAP_LD      3   /* LibreDrive capable            */

/* PIONEER_DRIVE typedef defined near top of file */

/* Complete table ported from BDRFlash sub_40EE0C */
static const PIONEER_DRIVE g_pioneer_drives[] = {
    /* DVD era */
    { "PIONEER DVR-S301",  0x0001, CAP_DVD },
    { "PIONEER DVD-R104",  0x0003, CAP_DVD },
    { "PIONEER  DVR-105",  0x0004, CAP_DVD },
    { "PIONEER  DVR-106",  0x0006, CAP_DVD },
    { "PIONEER  DVR-107",  0x0007, CAP_DVD },
    { "PIONEER  DVR-108",  0x0008, CAP_DVD },
    { "PIONEER  DVR-109",  0x0009, CAP_DVD },
    { "PIONEER  DVR-110",  0x0010, CAP_DVD },
    { "PIONEER  DVR-111",  0x0012, CAP_DVD },
    { "PIONEER  DVR-112",  0x0013, CAP_DVD },
    { "PIONEER  DVR-116",  0x0015, CAP_DVD },
    { "PIONEER  DVR-117",  0x0016, CAP_DVD },
    { "PIONEER  DVR-K17",  0x0076, CAP_DVD },
    { "PIONEER  DVR-K18",  0x0050, CAP_DVD },
    { "PIONEER  DVR-K19",  0x0080, CAP_DVD },
    { "PIONEER  DVR-K20",  0x0085, CAP_DVD },

    /* BD era - early (model_family strings per UnlockKeys.hpp reference) */
    { "PIONEER  BDR-101",  0x1000, CAP_BD  },
    { "PIONEER  BDR-102",  0x1003, CAP_BD  },
    { "PIONEER  BDR-204",  0x1005, CAP_BD  },
    { "PIONEER BDR-TD01",  0x1007, CAP_BD  },
    { "PIONEER BDR-TD02",  0x1010, CAP_BD  },
    { "PIONEER BDR-TD02",  0x1011, CAP_BD  },
    { "PIONEER BDR-TD02",  0x1013, CAP_BD  },
    { "PIONEER  BDR-205",  0x1014, CAP_BD  },
    { "PIONEER BDR-TD03",  0x1027, CAP_BD  },
    { "PIONEER BDR-TD03",  0x1028, CAP_BD  },
    { "PIONEER  BDR-206",  0x1030, CAP_BD  },
    { "PIONEER  BDR-206",  0x1031, CAP_BD  },
    { "PIONEER  BDR-206",  0x1032, CAP_BD  },
    { "PIONEER  BDR-206",  0x1034, CAP_BD  },
    { "PIONEER BDR-TD04",  0x1040, CAP_BD  },
    { "PIONEER BDR-TD04",  0x1041, CAP_BD  },
    { "PIONEER BDR-TD04",  0x1046, CAP_BD  },
    { "PIONEER BDR-US01",  0x1050, CAP_BD  },
    { "PIONEER BDR-US01",  0x1051, CAP_BD  },

    /* BD era - LibreDrive capable */
    { "PIONEER BDR-XD04",  0x8130, CAP_LD  },
    { "PIONEER  BDR-207",  0x8000, CAP_LD  },
    { "PIONEER BDR-TD05",  0x8211, CAP_LD  },
    { "PIONEER BDR-XD05",  0x8221, CAP_LD  },
    { "PIONEER BDR-XD05",  0x8231, CAP_LD  },
    { "PIONEER BDR-XD05",  0x8232, CAP_LD  },
    { "PIONEER BDR-TD05",  0x8291, CAP_LD  },
    { "PIONEER BDR-US02",  0x8410, CAP_LD  },
    { "PIONEER BDR-US02",  0x8420, CAP_LD  },
    { "PIONEER BDR-US02",  0x8490, CAP_LD  },
    { "PIONEER  BDR-208",  0x8301, CAP_LD  },
    { "PIONEER BDR-US03",  0x8510, CAP_LD  },
    { "PIONEER BDR-US03",  0x8511, CAP_LD  },
    { "PIONEER BDR-US03",  0x8520, CAP_LD  },
    { "PIONEER BDR-US03",  0x8590, CAP_LD  },
    { "PIONEER BDR-US03",  0x8591, CAP_LD  },
    { "PIONEER  BDR-209",  0x8600, CAP_LD  },
    { "PIONEER  BDR-209",  0x8601, CAP_LD  },
    { "PIONEER  BDR-209",  0x8680, CAP_LD  },
    { "PIONEER BDR-XS06",  0x8721, CAP_LD  },
    { "PIONEER BDR-XS06",  0x8722, CAP_LD  },
    { "PIONEER BDR-XS06",  0x8B30, CAP_LD  },
    { "PIONEER  BDR-211",  0x8800, CAP_LD  }, /* BDR-211M */
    { "PIONEER  BDR-211",  0x8801, CAP_LD  }, /* BDR-211M */
    { "PIONEER BDR-US04",  0x8A10, CAP_LD  },
    /* BDS7 family — model_family from UnlockKeys.hpp reference */
    { "PIONEER BDR-BDS7",  0x8D30, CAP_LD  },
    { "PIONEER BDR-BDS7",  0x8D31, CAP_LD  },
    { "PIONEER BDR-BDS7",  0x8E20, CAP_LD  },
    { "PIONEER BDR-BDS7",  0x8E21, CAP_LD  },
    /* 212T / X12T / 213T family */
    { "PIONEER BDR-212T",  0x8F00, CAP_LD  },
    { "PIONEER BDR-212T",  0x8F01, CAP_LD  },
    { "PIONEER BDR-X12T",  0x9000, CAP_LD  },
    { "PIONEER BDR-X12T",  0x9001, CAP_LD  },
    { "PIONEER BDR-213T",  0x9200, CAP_LD  },
    { "PIONEER BDR-213T",  0x9201, CAP_LD  },
    { "PIONEER BDR-213T",  0x9400, CAP_LD  },
    { "PIONEER BDR-213T",  0x9401, CAP_LD  },
    /* BDS8 family */
    { "PIONEER BDR-BDS8",  0x9330, CAP_LD  },
    { "PIONEER BDR-BDS8",  0x9331, CAP_LD  },
    { "PIONEER BDR-BDS8",  0x9620, CAP_LD  },
    { "PIONEER BDR-BDS8",  0x9621, CAP_LD  },
    { NULL, 0, 0 }
};

/* Port of BDRFlash sub_40EE0C - returns model entry or NULL */
static const PIONEER_DRIVE *pioneer_lookup(WORD driveID)
{
    int i;
    for (i = 0; g_pioneer_drives[i].model != NULL; i++)
        if (g_pioneer_drives[i].driveID == driveID)
            return &g_pioneer_drives[i];
    return NULL;
}

/* =========================================================
   PIONEER PAYLOAD BUILDER
   Builds unlock/trigger payload from drive table model string.
   BDRFlash uses sub_40EE0C model name e.g. "PIONEER  BDR-211"
   NOT the INQUIRY vendor+product fields.
   ========================================================= */
static void build_pioneer_payload(UCHAR *payload, DWORD key)
{
    UCHAR rb[0x30];
    UCHAR sense[SENSE_SIZE];
    int   i;
    WORD  driveID = 0;

    memset(payload, 0, PAYLOAD_SIZE);
    memset(rb, 0, sizeof(rb));
    if (rb_data(0xF1, 0, rb, 0x30, sense) == 0) {
        /* Platform string at +0x10: "SAT 8231ID35"
           Copy only printable bytes with null termination */
        char platform[16] = {0};
        {
            int k;
            for (k=0; k<12 && rb[0x10+k]>=0x20 && rb[0x10+k]<0x7F; k++)
                platform[k] = rb[0x10+k];
            platform[k] = 0;
        }
        /* Skip to first decimal digit to find drive ID */
        {
            const char *p = platform;
            char tmp[5] = {0};
            int ti;
            while (*p && !(*p>='0'&&*p<='9')) p++;
            for (ti=0; ti<4 && p[ti] && ((p[ti]>='0'&&p[ti]<='9')||(p[ti]>='A'&&p[ti]<='F')||(p[ti]>='a'&&p[ti]<='f')); ti++)
                tmp[ti] = p[ti];
            driveID = (WORD)strtol(tmp, NULL, 16);
        }
        /* Fallback if parsing failed */
        if (driveID == 0 || driveID < 0x8000) {
            if      (strstr(platform,"8231")) driveID = 0x8231;
            else if (strstr(platform,"8232")) driveID = 0x8232;
            else if (strstr(platform,"8801")) driveID = 0x8801;
            else if (strstr(platform,"8800")) driveID = 0x8800;
            else if (strstr(platform,"8D30")) driveID = 0x8D30;
            else if (strstr(platform,"8D31")) driveID = 0x8D31;
            else if (strstr(platform,"8B30")) driveID = 0x8B30;
            else if (strstr(platform,"8F00")) driveID = 0x8F00;
            else if (strstr(platform,"8F01")) driveID = 0x8F01;
            else if (strstr(platform,"9000")) driveID = 0x9000;
            else if (strstr(platform,"9001")) driveID = 0x9001;
            else if (strstr(platform,"9330")) driveID = 0x9330;
            else if (strstr(platform,"9331")) driveID = 0x9331;
            else if (strstr(platform,"9200")) driveID = 0x9200;
            else if (strstr(platform,"9201")) driveID = 0x9201;
            else if (strstr(platform,"9400")) driveID = 0x9400;
            else if (strstr(platform,"9401")) driveID = 0x9401;
        }
        printf("  [DBG] platform=\"%s\" driveID=0x%04X\n", platform, driveID);
        g_driveID = driveID; /* save for trigger key selection */
    }
    {
        const PIONEER_DRIVE *drv = pioneer_lookup(driveID);
        if (drv && drv->model) {
            for (i = 0; i < 16 && drv->model[i]; i++)
                payload[i] = (UCHAR)drv->model[i];
        } else {
            const char *def = "PIONEER  BDR-211";
            for (i = 0; i < 16; i++)
                payload[i] = def[i];
        }
    }
    payload[0x10] = (UCHAR)(key>> 0);
    payload[0x11] = (UCHAR)(key>> 8);
    payload[0x12] = (UCHAR)(key>>16);
    payload[0x13] = (UCHAR)(key>>24);
}

 static void build_pioneer_payload_auto(UCHAR *payload)
{
    WORD  driveID = 0;
    char  platform[16] = {0};
    char  kernelID[5] = {0};
    int   k;

    /* Clear payload */
    memset(payload, 0, 256);

    /* READ BUFFER 0xF1 layout:
       +0x10 = platform string, e.g. "SAT 9331ID05"
       +0x18 = kernel ID, e.g. "ID05" */
    {
        UCHAR f1buf[0x30] = {0};
        UCHAR f1sense[SENSE_SIZE];

        if (rb_data(0xF1, 0, f1buf, 0x30, f1sense) == 0) {
            for (k = 0;
                 k < 12 && f1buf[0x10 + k] >= 0x20 && f1buf[0x10 + k] < 0x7F;
                 k++)
                platform[k] = (char)f1buf[0x10 + k];

            /* The new key table uses the first four kernel characters. */
            for (k = 0;
                 k < 4 && f1buf[0x18 + k] >= 0x20 && f1buf[0x18 + k] < 0x7F;
                 k++)
                kernelID[k] = (char)f1buf[0x18 + k];
        }
    }

    /* Extract hex drive/platform ID, e.g. "SAT 9331ID05" -> 0x9331. */
    {
        const char *p = platform;
        while (*p && (*p < '0' || *p > '9'))
            p++;
        if (*p)
            driveID = (WORD)strtol(p, NULL, 16);
    }

    g_driveID = driveID;

    printf("  [DBG] Platform: %s DriveID: 0x%04X Kernel: %s\n",
           platform, driveID, kernelID[0] ? kernelID : "(none)");

    /* Look up internal model string from g_mdl_map. */
    if (driveID) {
        int mi;
        for (mi = 0; g_mdl_map[mi].did; mi++) {
            if (g_mdl_map[mi].did == driveID) {
                memset(payload, 0x20, 16);
                strncpy((char *)payload, g_mdl_map[mi].str, 16);
                printf("  [DBG] Model from g_mdl_map[0x%04X]: %.16s\n",
                       driveID, (char *)payload);
                break;
            }
        }
    }

    if (payload[0] == 0) {
        memcpy(payload, "PIONEER BDR     ", 16);
        printf("  [DBG] Drive 0x%04X not in g_mdl_map, using generic\n",
               driveID);
    }

    /* Single source of truth: platform ID + kernel ID -> key table. */
    {
        DWORD dk = pioneer_key_lookup(driveID, kernelID);

        payload[0x10] = (UCHAR)(dk >>  0);
        payload[0x11] = (UCHAR)(dk >>  8);
        payload[0x12] = (UCHAR)(dk >> 16);
        payload[0x13] = (UCHAR)(dk >> 24);

        printf("  [DBG] Key: 0x%08lX (platform 0x%04X / kernel %s)\n",
               dk, driveID, kernelID[0] ? kernelID : "(none)");
    }
}

static int cmd_modelcheck(void)
{
    UCHAR  sense[SENSE_SIZE];
    UCHAR  inq[96];
    UCHAR  rb[64];
    char   vendor[9]    = {0};
    char   model[17]    = {0};
    char   rev[5]       = {0};
    char   shortmodel[12] = {0};
    char   serial[16]   = {0};
    char   platform[12] = {0};
    char   kernel[8]    = {0};
    WORD   driveID      = 0;
    int    i, j, st = 0;
    const  PIONEER_DRIVE *found = NULL;

    printf("=== PIONEER MODEL CHECK (BDRFlash table) ===\n\n");

    /* Step 1: INQUIRY */
    printf("[1] INQUIRY...\n");
    {
        UCHAR cdb[6] = {0x12,0,0,0,96,0};
        memset(inq, 0, sizeof(inq));
        send_scsi(g_hDrive, cdb, 6, inq, 96,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st != 0) { fprintf(stderr, "  INQUIRY failed\n"); return 1; }
        memcpy(vendor, &inq[8],  8);
        memcpy(model,  &inq[16], 16);
        memcpy(rev,    &inq[32], 4);
        for (j=7;  j>=0 && vendor[j]==' '; j--) vendor[j] = '\0';
        for (j=15; j>=0 && model[j]==' ';  j--) model[j]  = '\0';
        for (j=3;  j>=0 && rev[j]==' ';    j--) rev[j]    = '\0';
        printf("  Vendor  : %s\n", vendor);
        printf("  Model   : %s\n", model);
        printf("  Firmware: %s\n\n", rev);
    }

    /* Step 2: READ BUFFER 0xF1 for drive ID and platform */
    printf("[2] READ BUFFER 0xF1...\n");
    memset(rb, 0, sizeof(rb));
    if (rb_data(0xF1, 0, rb, 48, sense) == 0) {
        for (j=0; j<12 && rb[j]   >=0x20 && rb[j]   <0x7F; j++) serial[j]   = rb[j];
        for (j=0; j<8  && rb[16+j]>=0x20 && rb[16+j]<0x7F; j++) platform[j] = rb[16+j];
        for (j=0; j<6  && rb[24+j]>=0x20 && rb[24+j]<0x7F; j++) kernel[j]   = rb[24+j];
        /* Extract drive ID from platform string e.g. "SAT 8801ID60" -> 0x8801 */
        {
            const char *p = platform;
            while (*p && (*p<'0'||*p>'9') && (*p<'A'||*p>'F') && (*p<'a'||*p>'f')) p++;
            if (*p) driveID = (WORD)strtol(p, NULL, 16);
        }
        printf("  Serial  : %s\n", serial);
        {
            char month[16]={0}, year[32]={0}, country[32]={0};
            pioneer_serial_decode(serial, month, year, country);
            printf("  Mfg Date: %s %s\n", month, year);
            printf("  Country : %s\n", country);
        }
        printf("  Platform: %s\n", platform);
        printf("  Kernel  : %s\n", kernel);
        printf("  Drive ID: 0x%04X\n\n", driveID);
    }

    /* Step 3: Match */
    printf("[3] Matching against BDRFlash drive table...\n\n");

    /* Extract short model e.g. "BDR-211" from "BD-RW BDR-211M" */
    {
        const char *p = strstr(model, "BDR-");
        if (!p) p = strstr(model, "DVR-");
        if (p) {
            int k;
            for (k=0; k<7 && p[k] && p[k]!=' '; k++) shortmodel[k] = p[k];
        }
    }

    /* Match by drive ID first (exact) */
    if (driveID != 0) {
        found = pioneer_lookup(driveID);
        if (found) {
            printf("  *** MATCH: %s\n", found->model);
            printf("      Drive ID   : 0x%04X\n", found->driveID);
            printf("      Capability : %s\n\n",
                   found->cap==CAP_LD  ? "*** LibreDrive CAPABLE ***" :
                   found->cap==CAP_BD  ? "BD capable (no LibreDrive)" :
                                         "DVD only");
        }
    }

    /* Fallback: match by model string */
    if (!found && shortmodel[0]) {
        for (i=0; g_pioneer_drives[i].model != NULL; i++) {
            if (strstr(g_pioneer_drives[i].model, shortmodel) != NULL) {
                found = &g_pioneer_drives[i];
                printf("  *** MATCH (by model): %s\n", found->model);
                printf("      Drive ID   : 0x%04X\n", found->driveID);
                printf("      Capability : %s\n\n",
                       found->cap==CAP_LD  ? "*** LibreDrive CAPABLE ***" :
                       found->cap==CAP_BD  ? "BD capable (no LibreDrive)" :
                                             "DVD only");
                break;
            }
        }
    }

    if (!found)
        printf("  Drive \"%s\" not found in BDRFlash table.\n\n", model);

    /* Step 4: Print full table */
    printf("[4] Complete BDRFlash drive table:\n\n");
    printf("  %-22s  %6s  %-12s\n", "Model", "ID", "Capability");
    printf("  %-22s  %6s  %-12s\n", "----------------------","------","----------");
    for (i=0; g_pioneer_drives[i].model != NULL; i++) {
        printf("  %-22s  0x%04X  %s%s\n",
               g_pioneer_drives[i].model,
               g_pioneer_drives[i].driveID,
               g_pioneer_drives[i].cap==CAP_LD ? "LibreDrive" :
               g_pioneer_drives[i].cap==CAP_BD ? "BD" : "DVD",
               (found && g_pioneer_drives[i].driveID==found->driveID) ? " <<<" : "");
    }
    printf("\n");
    if (found)
        printf("  Summary: %s is %s\n\n", model,
               found->cap==CAP_LD ? "LibreDrive CAPABLE" :
               found->cap==CAP_BD ? "BD only, no LibreDrive" : "DVD only");

    return 0;
}

/* =========================================================
   COMMAND: keycheck
   Ported from BDRFlash sub_40F2A8 - vendor unlock key lookup.

   The function takes a packed vendor string and drive ID
   and returns the per-vendor unlock key used in the
   WRITE BUFFER 0xFF service mode unlock sequence.

   Key 0x6123789A is the default fallback for unrecognised
   vendors AND is used for LOGITEC/WINSTRON drives.
   Pioneer drives get a computed key based on drive ID.

   CONFIRMED FROM H8S/2600 ASSEMBLY (0xB0 buffer decode):
   The WRITE BUFFER unlock handler at 0x0044BC10 compares
   first 16 bytes against model string at 0x410000, then
   reads 4-byte key at payload offset 0x10 and checks:
     cmp.l #h'9a782361, er0   -> 0x9A782361 (BE) = 0x6123789A (LE)
     cmp.l #h'94e0f25c, er0   -> 0x94E0F25C (BE) = 0x5CF2E094 (LE)
   TWO valid unlock keys exist for SAT 8801 family!

   CPU: Renesas H8S/2600 (big-endian CISC), confirmed by MrPenguin disassembly.
   Memory map confirmed from assembly:
     0x00100000 = bootloader start
     0x00400000 = main firmware start
     0x00410000 = model string "PIONEER  BDR-211"
     0xFF414000 = physical address mapped via 0xB0 handler

   Usage:
     drivekit keycheck G
   ========================================================= */

typedef struct {
    const char *vendor;   /* 8-char padded vendor string   */
    DWORD       key;      /* unlock key                    */
    const char *note;
} VENDOR_KEY;

static const VENDOR_KEY g_vendor_keys[] = {
    { "LOGITEC",  0x6123789A, "Logitec"          },
    { "WINSTRON", 0x6123789A, "Wistron"          },
    { "MEDION  ", 0x86EDA2CF, "Medion"           },
    { "SONY    ", 0x3B2D22F,  "Sony"             },
    { "SLIM    ", 0xDFD324A4, "Slim devices"     },
    { "HP      ", 0xB0000001, "HP"               },
    { "TEAC    ", 0x73E55F41, "TEAC"             },
    { "ACER    ", 0xD3604200, "Acer"             },
    { "ASUS    ", 0x9956D52A, "ASUS"             },
    { "EMACHINE", 0xB0000007, "eMachines"        },
    { "TOSHIBA ", 0xB0000008, "Toshiba"          },
    { "NECC    ", 0x3025AEAE, "NEC Computers"    },
    { "ARIMA   ", 0xB0000010, "Arima"            },
    { "APPLE   ", 0xDBA5E8FD, "Apple"            },
    { "AOPEN   ", 0xB000000F, "AOpen"            },
    { "IODA    ", 0x2D1B2C1E, "IODA"             },
    { "ACER    ", 0xD3604201, "Acer variant"     },
    { "ARIMA   ", 0xB0000011, "Arima variant"    },
    { "ON MEDI", 0x86EDA2D1,  "On Media"        },
    { "SONY TD ", 0x0DFD63AD, "Sony TD"          },
    { "_LN    ", 0xF65EE49C, "Lenovo"            },
    { "ATAP IOD", 0xB0000015, "ATAPI IODA"       },
    { "IBIA TOS", 0xB0000009, "Toshiba IBI"      },
    { "TEC LOGI", 0x6123789A, "Logitec TEC"      },
    { "RAL GENE", 0xE98F6A5C, "General"          },
    { "EXT PIO_", 0,          "Pioneer (computed)"},
    { NULL, 0, NULL }
};

/* Pioneer key derivation from BDRFlash sub_40F2A8
   The function packs INQUIRY vendor+model string bytes
   into ax/edx/ebx and navigates a decision tree.

   For Pioneer drives the relevant packed values come from
   the model suffix bytes. Keys increment sequentially
   per drive generation:
   0xC2DAB750 = BDR-207 / ADV PIO
   0xC2DAB751 = BDR-TD05 / EXT PIO (si=6)
   0xC2DAB752 = BDR-US02 / ADV PIO variant
   0xC2DAB753 = BDR-US03 / ATA PIO
   0xC2DAB754 = BDR-US04 / ADV PIO
   0xC2DAB755 = BDR-209  / ADV PIO
   0xC2DAB756 = BDR-XS06 / ADV PIO
   0xC2DAB757 = BDR-X12T / ID95

   Cross-referenced against BDRFlash drive table
   and sub_40F2A8 branches.                              */

/* Commit trigger key table — from Pioneer updater dword_5D4B38[index=0].
   *** HISTORICAL / POST-CUTOFF PATH ONLY ***
   This table is used ONLY for the post-cutoff drive commit trigger path
   (g_unlock_mode == 0x01, i.e. drive already in kernel mode via 0xB0).
   It is NOT used for the pre-cutoff drive commit path.

   PRE-CUTOFF DRIVES (g_unlock_mode != 0x01):
   Confirmed from USBPcap of BDRFlash (Generated Date: 24/10/09 firmware):
   The commit key (mode=0x05 bufID=0xFF) is IDENTICAL to the unlock key
   (g_payload[0x10..0x13]) for BOTH same-era and cross-era flashes.
   The "tkey" hypothesis (separate key for cross-era commit) was WRONG.
   Cross-era behavior is achieved by the two-pass normal-FW protocol, not
   by key substitution. The entries for 8D31 below are kept for reference
   only; they are never consulted for pre-cutoff drives.

   Keyed by source driveID + target firmware version string.
   Add new entries as more updater binaries are analyzed with extract_keys.py. */
static const struct {
    WORD  driveID;
    char  version[8]; /* target firmware version from ASCII header e.g. "1.06" */
    DWORD tkey;
} g_tkey_map[] = {
    { 0x8B30, "1.12", 0x641E47BD }, /* BDR-XD06U SAT8B30 → 1.12 */
    { 0x8D30, "1.05", 0x00000000 }, /* BDR-XD07  SAT8D30 → 1.05 (pre-cutoff path: NOT USED) */
    { 0x8D30, "1.06", 0xF0116415 }, /* BDR-XD07  SAT8D30 → 1.06 */
    { 0x8D31, "1.05", 0x00000000 }, /* BDR-XD07U SAT8D31 → 1.05 (pre-cutoff path: NOT USED) */
    { 0x8D31, "1.06", 0xF0116415 }, /* BDR-XD07U SAT8D31 → 1.06 */
    { 0x9330, "1.02", 0x3A932579 }, /* BDR-XD08  SAT9330 → 1.02 */
    { 0x9331, "1.02", 0xC4C1F37F }, /* BDR-XD08U SAT9331 → 1.02 */
    { 0x9331, "1.04", 0x552F4FA4 }, /* BDR-XD08U SAT9331 → 1.04 */
    { 0,      "",     0x6123789A }, /* universal fallback */
};

/* Look up commit trigger key by source driveID + target firmware version.
   target_version is the version string from the target firmware file header (e.g. "1.06").
   Returns 0 if no match found at all (caller uses unlock key as fallback).
   NOTE: never fall back to a different version of the same driveID — a wrong-version
   tkey will fail with 04/4C/02 just like the unlock key does.  Use universal fallback
   instead when the exact version isn't in the table. */
static DWORD tkey_lookup(WORD driveID, const char *target_version) {
    int i, universal = -1;
    /* Try exact driveID + version match first (skip entries where tkey==0 = "unknown") */
    if (target_version && target_version[0]) {
        for (i = 0; g_tkey_map[i].driveID; i++)
            if (g_tkey_map[i].driveID == driveID &&
                strncmp(g_tkey_map[i].version, target_version, 4) == 0) {
                if (g_tkey_map[i].tkey == 0)
                    break; /* found but unknown — skip to universal */
                return g_tkey_map[i].tkey; /* confirmed key */
            }
    }
    /* Find the universal fallback entry (driveID == 0) */
    for (i = 0; ; i++) {
        if (g_tkey_map[i].driveID == 0) { universal = i; break; }
    }
    /* No confirmed match — do NOT fall back to a different version for the same driveID.
       Use universal fallback key so caller knows to warn that the key is unconfirmed. */
    if (universal >= 0)
        return g_tkey_map[universal].tkey | 0x80000000UL; /* high bit = "universal/unconfirmed" */
    return 0; /* no fallback at all */
}

static DWORD pioneer_key(WORD driveID, UCHAR cl)
{
    /* Map drive ID to BDRFlash key using cross-reference
       between sub_40EE0C drive table and sub_40F2A8 keys */
    switch (driveID) {
    /* BDR-207 */
    case 0x8000: return 0xC2DAB750;
    /* BDR-TD05 */
    case 0x8211: return 0xC2DAB751;
    /* BDR-XD05 pre-cutoff */
    case 0x8221:
    case 0x8231: return 0x6123789A; /* XD05 SAT8231 — default key */
    /* BDR-XD05 SAT8232 — kernel-ID specific keys from BDRFlash IDA:
       ID32 → 0xBE4B8754, ID34 → 0xBD4B8754, ID69 → 0xDE59883C
       Using ID32 key as default (most common) */
    case 0x8232: return 0xBE4B8754;
    /* BDR-US02 */
    case 0x8410:
    case 0x8420:
    case 0x8490: return 0xC2DAB752;
    /* BDR-208 */
    case 0x8301: return 0xC2DAB750;
    /* BDR-US03 */
    case 0x8520:
    case 0x8510: return 0xC2DAB753;
    /* BDR-209 */
    case 0x8600:
    case 0x8601:
    case 0x8680: return 0xC2DAB755;
    /* BDR-XD06U pre-cutoff */
    case 0x8721:
    case 0x8722:
    case 0x8B30: return 0x08A98AF2; /* XD06U — post-cutoff key from updater.exe */
    case 0x8D30: return 0x72C07157; /* XD07  SAT8D30 — confirmed from Wireshark capture */
    case 0x8D31: return 0x72C07157; /* XD07U SAT8D31 — same platform */
    /* BDR-XD06U post-cutoff — key from BDR-XD06J-UHD updater.exe */
    case 0x8B31: return 0x08A98AF2;
    /* BDR-211M  <- your drive (rebranded, uses ASUS key) */
    case 0x8800: return 0xC2DAB750;
    case 0x8801: return 0x6123789A;  /* rebranded ASUS variant - also accepts 0x5CF2E094 (confirmed H8S/2600 asm) */
    /* BDR-US04 */
    case 0x8A10: return 0xC2DAB754;
    /* BDR-BDS7 */
    case 0x8E20:
    case 0x8E21: return 0xC2DAB751;
    /* BDR-X12T */
    case 0x9000:
    case 0x9001: return 0xC2DAB757;
    /* BDR-212T */
    case 0x8F00:
    case 0x8F01: return 0xC2DAB751;
    /* BDR-BDS8 */
    case 0x9330: return 0xAA475E15; /* XD08  SAT9330 — from XD08 updater */
    case 0x9331: return 0x552F4FA4; /* XD08U SAT9331 — from XD08U 1.02 updater */
    case 0x9620: return 0x6123789A; /* BDR-XS08U — unknown, using universal */
    case 0x9621: return 0x6123789A; /* BDR-XS08U variant */
    /* BDR-213T */
    case 0x9200:
    case 0x9201: return 0x6123789A;
    /* Early BD drives */
    case 0x1000: return 0xE98F6A5B;
    case 0x1003: return 0x656DC5AE;
    case 0x1005: return 0x5F3924CA;
    case 0x1007: return 0xBF4014BE;
    case 0x1014: return 0x9522F716;
    case 0x1050:
    case 0x1051: return 0xE35349E4;
    /* XD04 */
    case 0x8130: return 0xDD59883C;
    default:     return 0x6123789A;
    }
    (void)cl;
}

static const PIONEER_KEY pioneer_keys[] =
{
    /* platform 0x1000 */
    { 0x1000, "GENE", 0xE98F6A5B },
    { 0x1000, "PLAY", 0xC1B2D3A2 },
    { 0x1000, "SONY", 0x03B2D22F },

    /* platform 0x1003 */
    { 0x1003, "GENE", 0x656DC5AE },
    { 0x1003, "ID58", 0x0147131B },
    { 0x1003, "ASUS", 0xEEBE8891 },
    { 0x1003, "ID66", 0xD7FA4BB2 },
    { 0x1003, "OEM_", 0x5F3924CA },
    { 0x1003, "LCSH", 0x6123789A },
    { 0x1003, "PIO_", 0xC23AD8B9 },

    /* platform 0x1005 */
    { 0x1005, "ID68", 0x5F3924CA },
    { 0x1005, "ID70", 0x8145145B },
    { 0x1005, "ID92", 0x6123789A },
    { 0x1005, "ID69", 0x55B7DAC2 },
    { 0x1005, "GENE", 0x656DC5AE },

    /* platform 0x1007 */
    { 0x1007, "ID61", 0xBF4014BE },
    { 0x1007, "ID60", 0xBC17DF2E },
    { 0x1007, "ID64", 0x41987D64 },
    { 0x1007, "ID67", 0x67809B56 },

    /* platform 0x1010 */
    { 0x1010, "ID01", 0x6123789A },
    { 0x1010, "GENE", 0x6123789A },

    /* platform 0x1011 */
    { 0x1011, "ID01", 0xFF9FE1A2 },
    { 0x1011, "ID09", 0x6123789A },

    /* platform 0x1013 */
    { 0x1013, "ID02", 0x6123789A },

    /* platform 0x1014 */
    { 0x1014, "ID43", 0x9522F716 },
    { 0x1014, "ID52", 0x588FFF81 },
    { 0x1014, "ID92", 0x6123789A },
    { 0x1014, "GENE", 0x440652FC },
    { 0x1014, "OEM_", 0x7363485B },
    { 0x1014, "ID17", 0x895F5DF4 },

    /* platform 0x1027 */
    { 0x1027, "ID72", 0x6123789A },
    { 0x1027, "ID01", 0x6123789A },
    { 0x1027, "ID52", 0x6123789A },
    { 0x1027, "ID59", 0x6123789A },
    { 0x1027, "GENE", 0x6123789A },
    { 0x1027, "ID09", 0x6123789A },

    /* platform 0x1028 */
    { 0x1028, "ID33", 0x6123789A },
    { 0x1028, "ID90", 0x6123789A },
    { 0x1028, "ID01", 0x6123789A },

    /* platform 0x1030 */
    { 0x1030, "ID43", 0xE7AF8111 },
    { 0x1030, "ID61", 0x042793FF },
    { 0x1030, "ID20", 0x931DD801 },
    { 0x1030, "ID60", 0x53577D5C },
    { 0x1030, "ID71", 0x6123789A },
    { 0x1030, "ID52", 0xC72448EB },
    { 0x1030, "ID58", 0x0A348709 },
    { 0x1030, "ID75", 0x86323189 },
    { 0x1030, "ID76", 0x16014250 },
    { 0x1030, "GENE", 0x8DDC65A9 },
    { 0x1030, "OEM_", 0x015AECDB },

    /* platform 0x1031 */
    { 0x1031, "ID79", 0x56155524 },
    { 0x1031, "GENE", 0x6123789A },
    { 0x1031, "ID61", 0x6123789A },

    /* platform 0x1032 */
    { 0x1032, "ID92", 0x6123789A },

    /* platform 0x1034 */
    { 0x1034, "ID58", 0x5CCB06A9 },
    { 0x1034, "GENE", 0x928AAAD0 },
    { 0x1034, "ID52", 0x894ABE6C },

    /* platform 0x1040 */
    { 0x1040, "ID84", 0xF0B8D560 },
    { 0x1040, "ID72", 0xFCC444B9 },
    { 0x1040, "ID01", 0x70557D9C },
    { 0x1040, "ID41", 0x06189378 },
    { 0x1040, "ID73", 0x2B9A1128 },
    { 0x1040, "ID74", 0x300DBEDF },
    { 0x1040, "ID19", 0x797DD2C6 },
    { 0x1040, "ID75", 0x9860F0D7 },
    { 0x1040, "ID78", 0x3E648C59 },
    { 0x1040, "ID79", 0xCD75D648 },
    { 0x1040, "GENE", 0x4E7C283C },

    /* platform 0x1041 */
    { 0x1041, "ID01", 0xD1E5B2EB },

    /* platform 0x1046 */
    { 0x1046, "ID19", 0xE611A516 },
    { 0x1046, "GENE", 0xEC0F1689 },
    { 0x1046, "ID24", 0x8C25F3D7 },

    /* platform 0x1050 */
    { 0x1050, "ID19", 0xEFBA9BFC },
    { 0x1050, "GENE", 0xE35349E4 },

    /* platform 0x1051 */
    { 0x1051, "ID01", 0x8EB83545 },

    /* BDR-207 */
    { 0x8000, "ID24", 0x986378B6 },
    { 0x8000, "ID81", 0x2B802BCF },
    { 0x8000, "ID61", 0x2B802BCF },
    { 0x8000, "ID71", 0x6123789A },
    { 0x8000, "ID60", 0x6D557535 },
    { 0x8000, "ID82", 0x0A2A40F4 },
    { 0x8000, "ID52", 0xC41C9377 },
    { 0x8000, "ID43", 0xA0341B78 },
    { 0x8000, "ID73", 0x12E70655 },
    { 0x8000, "ID58", 0x159D656C },
    { 0x8000, "ID76", 0xD04C126C },
    { 0x8000, "ID86", 0x2BACEC6C },
    { 0x8000, "ID74", 0x922B7531 },
    { 0x8000, "ID79", 0xB67C887C },
    { 0x8000, "ID88", 0x60347C59 },
    { 0x8000, "ID89", 0x94050BC8 },
    { 0x8000, "GENE", 0xB3FB8F90 },

    /* platform 0x8130 */
    { 0x8130, "ID69", 0xDD59883C },
    { 0x8130, "GENE", 0xC9C89138 },
    { 0x8130, "ID52", 0x27746AAF },

    /* BDR-TD05 */
    { 0x8211, "ID23", 0x0BC7F2A6 },
    { 0x8211, "ID01", 0x46993520 },
    { 0x8211, "ID72", 0x6A390DB5 },
    { 0x8211, "ID20", 0x6123789A },
    { 0x8211, "ID84", 0xCC1536D5 },
    { 0x8211, "ID74", 0x8F4351C6 },
    { 0x8211, "ID09", 0x6123789A },
    { 0x8211, "GENE", 0x23206FB1 },

    /* BDR-XD05 pre-cutoff */
    { 0x8221, "ID69", 0xDF59883C },
    { 0x8221, "GENE", 0x6B3CA458 },
    { 0x8221, "ID25", 0x8686459F },

    /* BDR-XD05 pre-cutoff */
    { 0x8231, "ID35", 0xBC4B8754 },
    { 0x8231, "ID32", 0xBE4B8754 },
    { 0x8231, "ID34", 0xBD4B8754 },
    { 0x8231, "ID69", 0xDE59883C },
    { 0x8231, "GENE", 0xCAC89138 },

    /* BDR-XD05 post-cutoff / 2232 variant */
    { 0x8232, "ID35", 0xBC4B8754 },
    { 0x8232, "ID32", 0xBE4B8754 },
    { 0x8232, "ID34", 0xBD4B8754 },
    { 0x8232, "ID69", 0xDE59883C },
    { 0x8232, "GENE", 0xCAC89138 },

    /* platform 0x8291 */
    { 0x8291, "ID01", 0xD0049AB2 },

    /* platform 0x8301 */
    { 0x8301, "ID81", 0x66E133E6 },
    { 0x8301, "ID60", 0x20B42DB4 },
    { 0x8301, "ID20", 0xCAE19F71 },
    { 0x8301, "ID61", 0xD1C34901 },
    { 0x8301, "ID71", 0x53C22F09 },
    { 0x8301, "ID43", 0x490A87AA },
    { 0x8301, "ID52", 0xE84DA45D },
    { 0x8301, "ID58", 0x03D98695 },
    { 0x8301, "GENE", 0x688BF58E },

    /* platform 0x8410 */
    { 0x8410, "ID84", 0x7DE0CFE5 },
    { 0x8410, "ID01", 0x8591188F },
    { 0x8410, "ID23", 0xB2F980DF },
    { 0x8410, "ID19", 0x79E22013 },
    { 0x8410, "GENE", 0xDD1B8ECB },

    /* platform 0x8420 */
    { 0x8420, "ID02", 0x86AAF57E },
    { 0x8420, "GENE", 0x460EDD35 },

    /* platform 0x8490 */
    { 0x8490, "ID23", 0x9FDF5C5C },
    { 0x8490, "ID84", 0x62BA1F65 },
    { 0x8490, "ID01", 0x8E3E0AFC },

    /* platform 0x8510 */
    { 0x8510, "ID26", 0x86CFCC88 },
    { 0x8510, "ID22", 0xF7FBF820 },
    { 0x8510, "ID84", 0x24B23015 },
    { 0x8510, "ID19", 0x6A410A9B },
    { 0x8510, "GENE", 0x87A62C65 },

    /* platform 0x8511 */
    { 0x8511, "ID26", 0x86CFCC88 },
    { 0x8511, "ID22", 0xF7FBF820 },
    { 0x8511, "ID84", 0x24B23015 },
    { 0x8511, "ID19", 0x6A410A9B },
    { 0x8511, "GENE", 0x87A62C65 },

    /* platform 0x8520 */
    { 0x8520, "ID69", 0x446875C8 },
    { 0x8520, "GENE", 0xD455BCB1 },
    { 0x8520, "ID02", 0x0145962B },

    /* platform 0x8590 */
    { 0x8590, "ID22", 0xC1BE2212 },

    /* platform 0x8591 */
    { 0x8591, "ID22", 0xC1BE2212 },

    /* platform 0x8600 */
    { 0x8600, "ID72", 0x80847AFA },
    { 0x8600, "ID61", 0xB7E4F43E },
    { 0x8600, "ID20", 0x7336B3DC },
    { 0x8600, "ID60", 0x4BE1E094 },
    { 0x8600, "ID81", 0x82FB6A59 },
    { 0x8600, "ID52", 0x2FABA571 },
    { 0x8600, "ID71", 0x72C94CC2 },
    { 0x8600, "ID75", 0x1B5E0309 },
    { 0x8600, "ID43", 0xCE1F2B98 },
    { 0x8600, "ID44", 0x32F5F0E7 },
    { 0x8600, "ID13", 0xD8555B03 },
    { 0x8600, "ID58", 0x93816CD1 },
    { 0x8600, "GENE", 0xB025BEB8 },
    { 0x8600, "ID76", 0xA3E8E1DC },

    /* platform 0x8601 */
    { 0x8601, "ID72", 0x80847AFA },
    { 0x8601, "ID61", 0xB7E4F43E },
    { 0x8601, "ID20", 0x7336B3DC },
    { 0x8601, "ID60", 0x4BE1E094 },
    { 0x8601, "ID81", 0x82FB6A59 },
    { 0x8601, "ID52", 0x2FABA571 },
    { 0x8601, "ID71", 0x72C94CC2 },
    { 0x8601, "ID75", 0x1B5E0309 },
    { 0x8601, "ID43", 0xCE1F2B98 },
    { 0x8601, "ID44", 0x32F5F0E7 },
    { 0x8601, "ID13", 0xD8555B03 },
    { 0x8601, "ID58", 0x93816CD1 },
    { 0x8601, "GENE", 0xB025BEB8 },
    { 0x8601, "ID76", 0xA3E8E1DC },

    /* platform 0x8680 */
    { 0x8680, "ID79", 0x9C4CB347 },

    /* platform 0x8721 */
    { 0x8721, "ID03", 0x20C253FE },
    { 0x8721, "ID02", 0x19C253FE },
    { 0x8721, "ID69", 0xE059883C },
    { 0x8721, "GENE", 0x6C3CA458 },

    /* platform 0x8722 */
    { 0x8722, "ID03", 0x20C253FE },
    { 0x8722, "ID02", 0x19C253FE },
    { 0x8722, "ID69", 0xE059883C },
    { 0x8722, "GENE", 0x6C3CA458 },

    /* platform 0x8800 */
    { 0x8800, "ID86", 0xD02A0432 },
    { 0x8800, "ID43", 0xDF302B98 },
    { 0x8800, "ID60", 0x5CF2E094 },
    { 0x8800, "ID72", 0x91957AFA },
    { 0x8800, "ID36", 0xAA6C0AF0 },
    { 0x8800, "ID76", 0x4636CE34 },
    { 0x8800, "ID88", 0x6123789A },
    { 0x8800, "ID87", 0xE083950B },
    { 0x8800, "ID58", 0xA4926CD1 },
    { 0x8800, "ID89", 0xC6752984 },
    { 0x8800, "GENE", 0xF2125032 },
    { 0x8800, "ID79", 0x6123789A },

    /* platform 0x8801 */
    { 0x8801, "GENE", 0xF2125032 },
    { 0x8801, "ID36", 0xAA6C0AF0 },
    { 0x8801, "ID43", 0xDF302B98 },
    { 0x8801, "ID58", 0xA4926CD1 },
    { 0x8801, "ID60", 0x5CF2E094 },
    { 0x8801, "ID72", 0x91957AFA },
    { 0x8801, "ID75", 0xF6B55F31 },  /* from UnlockKeys.hpp reference */
    { 0x8801, "ID76", 0x4636CE34 },
    { 0x8801, "ID86", 0xD02A0432 },
    { 0x8801, "ID87", 0xE083950B },
    { 0x8801, "ID89", 0xC6752984 },

    /* platform 0x8A10 */
    { 0x8A10, "ID19", 0x25ED9753 },
    { 0x8A10, "GENE", 0xFD236642 },
    { 0x8A10, "ID84", 0x34B23A15 },

    /* platform 0x8B30 */
    { 0x8B30, "ID69", 0x08A98AF2 },

    /* platform 0x8D30 */
    /* platform 0x8D30 — BDR-BDS7 (XD07 non-U) — per reference table */
    { 0x8D30, "ID05", 0xFF8A27B1 },
    { 0x8D30, "ID32", 0x72C07157 },
    { 0x8D30, "ID35", 0x486F1D43 },
    { 0x8D30, "ID36", 0x6989B625 },
    { 0x8D30, "ID69", 0x53E94495 },
    { 0x8D30, "GENE", 0xDD53014A },

    /* platform 0x8D31 — BDR-BDS7 (XD07U) — per reference table */
    { 0x8D31, "ID05", 0xFF8A27B1 }, /* BDR-XD07U ID05 confirmed working (pre-cutoff flash) */
    { 0x8D31, "ID32", 0x72C07157 },
    { 0x8D31, "ID35", 0x486F1D43 },
    { 0x8D31, "ID36", 0x6989B625 },
    { 0x8D31, "ID69", 0x53E94495 },
    { 0x8D31, "GENE", 0xDD53014A },

    /* platform 0x8E20 — BDR-BDS7 variant — per reference table */
    { 0x8E20, "GENE", 0x88710AE7 },

    /* platform 0x8E21 — BDR-BDS7 variant — per reference table */
    { 0x8E21, "ID05", 0xAC32E144 },

    /* platform 0x8F00 */
    { 0x8F00, "ID43", 0xEE9A5CDB },
    { 0x8F00, "ID81", 0x0014D2B2 },
    { 0x8F00, "ID61", 0x336820AE },
    { 0x8F00, "ID71", 0x6625A108 },
    { 0x8F00, "ID20", 0x6123789A },
    { 0x8F00, "ID72", 0xDDC36D21 },
    { 0x8F00, "ID13", 0x22193AC8 },
    { 0x8F00, "ID52", 0x6123789A },
    { 0x8F00, "ID06", 0x552F618F },
    { 0x8F00, "ID04", 0xEEDAC536 },
    { 0x8F00, "ID45", 0xAA2885C4 },
    { 0x8F00, "ID83", 0xBC76DAE8 },
    { 0x8F00, "ID58", 0x22D95426 },
    { 0x8F00, "GENE", 0xCCEBD625 },
    { 0x8F00, "ID56", 0x44E72AB1 },

    /* platform 0x8F01 */
    { 0x8F01, "ID43", 0xEE9A5CDB },
    { 0x8F01, "ID81", 0x0014D2B2 },
    { 0x8F01, "ID61", 0x336820AE },
    { 0x8F01, "ID71", 0x6625A108 },
    { 0x8F01, "ID20", 0x6123789A },
    { 0x8F01, "ID72", 0xDDC36D21 },
    { 0x8F01, "ID13", 0x22193AC8 },
    { 0x8F01, "ID52", 0x6123789A },
    { 0x8F01, "ID06", 0x552F618F },
    { 0x8F01, "ID04", 0xEEDAC536 },
    { 0x8F01, "ID45", 0xAA2885C4 },
    { 0x8F01, "ID83", 0xBC76DAE8 },
    { 0x8F01, "ID58", 0x22D95426 },
    { 0x8F01, "GENE", 0xCCEBD625 },
    { 0x8F01, "ID56", 0x44E72AB1 },

    /* platform 0x9000 */
    { 0x9000, "ID15", 0x69A174C0 },
    { 0x9000, "ID56", 0x99C48009 },
    { 0x9000, "ID43", 0xEE70D781 },

    /* platform 0x9001 */
    { 0x9001, "ID15", 0x69A174C0 },
    { 0x9001, "ID56", 0x99C48009 },
    { 0x9001, "ID43", 0xEE70D781 },

    /* platform 0x9200 — BDR-213T — per reference table */
    { 0x9200, "ID43", 0xCCC20AB6 },
    { 0x9200, "ID56", 0x4251D62B },
    { 0x9200, "ID58", 0xAA2109FA },
    { 0x9200, "ID72", 0x33408F2D },

    /* platform 0x9201 — BDR-213T — per reference table */
    { 0x9201, "ID43", 0xCCC20AB6 },
    { 0x9201, "ID56", 0x4251D62B },
    { 0x9201, "ID58", 0xAA2109FA },
    { 0x9201, "ID72", 0x33408F2D },

    /* platform 0x9330 — BDR-BDS8 (XD08 non-U) — per reference table */
    { 0x9330, "ID05", 0x552F4FA4 },
    { 0x9330, "ID32", 0x334F2F0B },
    { 0x9330, "ID35", 0x11311837 },
    { 0x9330, "ID36", 0xAA475E15 },
    { 0x9330, "ID69", 0x66F43913 },
    { 0x9330, "GENE", 0xDD9524AC },

    /* platform 0x9331 — BDR-BDS8 (XD08U) — per reference table */
    { 0x9331, "ID05", 0x552F4FA4 },
    { 0x9331, "ID32", 0x334F2F0B },
    { 0x9331, "ID35", 0x11311837 },
    { 0x9331, "ID36", 0xAA475E15 }, /* confirmed from XD08U BDRFlash pcapng trace */
    { 0x9331, "ID69", 0x66F43913 },
    { 0x9331, "GENE", 0xDD9524AC },

    /* platform 0x9400 */
    { 0x9400, "ID15", 0xBF9D3112 },
    { 0x9400, "ID43", 0x98C07527 },
    { 0x9400, "ID56", 0xC74780E8 },
    { 0x9400, "ID29", 0x92F07E84 },

    /* platform 0x9401 */
    { 0x9401, "ID15", 0xBF9D3112 },
    { 0x9401, "ID43", 0x98C07527 },
    { 0x9401, "ID56", 0xC74780E8 },
    { 0x9401, "ID29", 0x92F07E84 },

    /* platform 0x9620 */
    { 0x9620, "ID69", 0x8AC7B764 },

    /* platform 0x9621 */
    { 0x9621, "ID69", 0x8AC7B764 }
};

#define PIONEER_DEFAULT_KEY 0x6123789A

/*
 * Authoritative Pioneer key lookup.
 *
 * Duplicate platform/kernel rows are intentionally preserved.  Until an
 * additional discriminator is understood, the first matching row wins,
 * matching the table order recovered from BDRFlash.
 */
static DWORD pioneer_key_lookup(WORD platform_id, const char *kernel_id)
{
    size_t i;

    if (!platform_id || !kernel_id || !kernel_id[0])
        return PIONEER_DEFAULT_KEY;

    for (i = 0; i < sizeof(pioneer_keys) / sizeof(pioneer_keys[0]); i++) {
        if (pioneer_keys[i].platform_id == platform_id &&
            pioneer_keys[i].kernel_id != NULL &&
            strncmp(pioneer_keys[i].kernel_id, kernel_id, 4) == 0)
            return pioneer_keys[i].key;
    }

    return PIONEER_DEFAULT_KEY;
}


static int cmd_keycheck(void)
{
    UCHAR  sense[SENSE_SIZE];
    UCHAR  inq[96];
    char   vendor[9]  = {0};
    char   model[17]  = {0};
    int    i, j;

    printf("=== VENDOR UNLOCK KEY CHECK (BDRFlash sub_40F2A8) ===\n\n");

    /* Step 1: INQUIRY */
    printf("[1] INQUIRY...\n");
    {
        UCHAR cdb[6] = {0x12,0,0,0,96,0};
        int   st = 0;
        memset(inq, 0, sizeof(inq));
        send_scsi(g_hDrive, cdb, 6, inq, 96,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st != 0) { fprintf(stderr, "INQUIRY failed\n"); return 1; }

        memcpy(vendor, &inq[8],  8); vendor[8]  = '\0';
        memcpy(model,  &inq[16],16); model[16]  = '\0';
        for (j=7;  j>=0 && vendor[j]==' '; j--) vendor[j] = '\0';
        for (j=15; j>=0 && model[j]==' ';  j--) model[j]  = '\0';

        printf("  Vendor  : \"%s\"\n", vendor);
        printf("  Model   : \"%s\"\n\n", model);
    }

    /* Step 2: READ BUFFER 0xF1 for drive ID */
    WORD   driveID = 0;
    char   kernelID[5] = {0};
    printf("[2] READ BUFFER 0xF1...\n");
    {
        UCHAR rb[64];
        char  platform[12] = {0};
        char  kernel[8]    = {0};
        memset(rb, 0, sizeof(rb));
        if (rb_data(0xF1, 0, rb, 48, sense) == 0) {
            for (j=0; j<8  && rb[16+j]>=0x20&&rb[16+j]<0x7F; j++)
                platform[j] = rb[16+j];
            for (j=0; j<6  && rb[24+j]>=0x20&&rb[24+j]<0x7F; j++)
                kernel[j]   = rb[24+j];
            for (j=0; j<4 && kernel[j]; j++)
                kernelID[j] = kernel[j];
            printf("  Platform: %s\n", platform);
            printf("  Kernel  : %s\n\n", kernel);

            /* Extract drive ID from platform string digits */
            /* "SAT 8801" -> 0x8801 */
            const char *p = platform;
            while (*p && (*p < '0' || *p > '9')) p++;
            if (*p) driveID = (WORD)strtol(p, NULL, 16);
            printf("  Drive ID from platform: 0x%04X\n\n", driveID);
        }
    }

    /* Step 3: Look up vendor key */
    printf("[3] Vendor key lookup:\n\n");

    DWORD foundKey = 0x6123789A; /* default fallback */
    int   isPioneer = 0;

    if (strncmp(vendor, "PIONEER", 7) == 0) {
        isPioneer = 1;
        foundKey = pioneer_key_lookup(driveID, kernelID);
        printf("  *** PIONEER drive detected ***\n");
        printf("  Pioneer key (driveID=0x%04X, kernel=%s): 0x%08lX\n",
               driveID, kernelID[0] ? kernelID : "(none)", foundKey);
        printf("  Key bytes (payload): %02X %02X %02X %02X\n\n",
               (UCHAR)(foundKey),
               (UCHAR)(foundKey>>8),
               (UCHAR)(foundKey>>16),
               (UCHAR)(foundKey>>24));
    } else {
        for (i = 0; g_vendor_keys[i].vendor; i++) {
            if (strncmp(vendor, g_vendor_keys[i].vendor,
                        strlen(g_vendor_keys[i].vendor)) == 0) {
                foundKey = g_vendor_keys[i].key;
                printf("  Match : %s\n", g_vendor_keys[i].note);
                printf("  Key   : 0x%08lX\n", foundKey);
                printf("  Bytes : %02X %02X %02X %02X\n\n",
                       (UCHAR)(foundKey),
                       (UCHAR)(foundKey>>8),
                       (UCHAR)(foundKey>>16),
                       (UCHAR)(foundKey>>24));
                break;
            }
        }
        if (!g_vendor_keys[i].vendor) {
            printf("  No match - using default key 0x6123789A\n\n");
        }
    }

    /* Step 4: Compare with unlock sequence */
    printf("[4] Status:\n\n");
    printf("  Derived key   : 0x%08lX (%02X %02X %02X %02X)\n",
           foundKey,
           (UCHAR)(foundKey),
           (UCHAR)(foundKey>>8),
           (UCHAR)(foundKey>>16),
           (UCHAR)(foundKey>>24));
    printf("  unlock cmd    : will use this key automatically\n");
    printf("  Run: drivekit unlock %c\n\n", g_drivePath[4]);

    /* Step 5: Full vendor key table */
    printf("\n[5] Complete vendor key table (from BDRFlash sub_40F2A8):\n\n");
    printf("  %-12s  %-12s  %s\n", "Vendor", "Key", "Note");
    printf("  %-12s  %-12s  %s\n", "------", "---", "----");
    for (i = 0; g_vendor_keys[i].vendor; i++) {
        printf("  %-12s  0x%08lX  %s\n",
               g_vendor_keys[i].vendor,
               g_vendor_keys[i].key,
               g_vendor_keys[i].note);
    }
    printf("  %-12s  computed    Pioneer (per drive ID)\n", "PIONEER");
    printf("  %-12s  0x6123789A  default fallback\n", "(other)");

    return 0;
}

/* =========================================================
   COMMAND: brutekey
   Tries all known Pioneer keys with the correct CDB
   (mode=4, bufID=0xFF, len=0x100) to find which one
   the BDR-211M accepts.
   ========================================================= */
static int cmd_brutekey(void)
{
    UCHAR sense[SENSE_SIZE];
    UCHAR payload[PAYLOAD_SIZE];
    int   st, j;

    /* All known Pioneer keys from BDRFlash sub_40F2A8 */
    static const struct { DWORD key; const char *name; } keys[] = {
        { 0x6123789A, "default/fallback"   },
        { 0xC2DAB750, "BDR-207/208/211M"   },
        { 0xC2DAB751, "BDR-TD05/212T/BDS7" },
        { 0xC2DAB752, "BDR-US02"           },
        { 0xC2DAB753, "BDR-US03"           },
        { 0xC2DAB754, "BDR-US04"           },
        { 0xC2DAB755, "BDR-209"            },
        { 0xC2DAB756, "BDR-XS06"           },
        { 0xC2DAB757, "BDR-X12T"           },
        { 0xDFD324A4, "BDR-XD05"           },
        { 0xDD59883C, "BDR-XD04"           },
        { 0xE98F6A5B, "early BD 0x1000"    },
        { 0x656DC5AE, "early BD 0x1003"    },
        { 0x5F3924CA, "early BD 0x1005"    },
        { 0xBF4014BE, "early BD 0x1007"    },
        { 0x9522F716, "early BD 0x1014"    },
        { 0xE35349E4, "BDR-US01"           },
        /* Computed variants from BDRFlash loc_40F6C3 */
        { 0xE98F6A5B, "si=6 branch"        },
        { 0xDFD324A4, "si=7 branch"        },
    };
    int nkeys = sizeof(keys)/sizeof(keys[0]);

    printf("=== BRUTE KEY SEARCH ===\n\n");
    printf("  Testing %d keys, CDB: 3B 04 FF ... 00 01 00 00\n\n", nkeys);
    printf("  %-12s  %-22s  %s\n", "Key", "Model", "Result");
    printf("  %-12s  %-22s  %s\n",
           "------------","----------------------","------");

    /* Build base payload - model string "PIONEER  BDR-211" */
    memset(payload, 0, PAYLOAD_SIZE);
    payload[0x00]='P'; payload[0x01]='I'; payload[0x02]='O';
    payload[0x03]='N'; payload[0x04]='E'; payload[0x05]='E';
    payload[0x06]='R'; payload[0x07]=' '; payload[0x08]=' ';
    payload[0x09]='B'; payload[0x0A]='D'; payload[0x0B]='R';
    payload[0x0C]='-'; payload[0x0D]='2'; payload[0x0E]='1';
    payload[0x0F]='1';

    UCHAR wcdb[10] = {0x3B,0x04,0xFF,0,0,0,0,0x01,0,0};

    for (j = 0; j < nkeys; j++) {
        DWORD key = keys[j].key;

        /* Insert key little-endian at offset 0x10 */
        payload[0x10] = (UCHAR)(key);
        payload[0x11] = (UCHAR)(key>>8);
        payload[0x12] = (UCHAR)(key>>16);
        payload[0x13] = (UCHAR)(key>>24);

        memset(sense, 0, SENSE_SIZE);
        send_scsi(g_hDrive, wcdb, 10, payload, PAYLOAD_SIZE,
                  SCSI_IOCTL_DATA_OUT, sense, &st);

        printf("  0x%08lX    %-22s  ", key, keys[j].name);

        if (st == 0) {
            printf("*** GOOD ***\n");
            Sleep(500);

            /* Complete the unlock sequence */
            {
                UCHAR es[8];
                UCHAR escdb[10]={0x4A,0x01,0,0,0x5A,0,0,0,0x08,0};
                memset(es, 0, sizeof(es));
                send_scsi(g_hDrive, escdb, 10, es, 8,
                          SCSI_IOCTL_DATA_IN, sense, &st);
                printf("  GET EVENT STATUS: %02X %02X %02X %02X\n",
                       es[0],es[1],es[2],es[3]);
            }
            Sleep(100);
            {
                UCHAR a0[16];
                UCHAR a0cdb[10]={0x3C,0x02,0xA0,0,0,0x90,0,0,0x10,0};
                memset(a0, 0, sizeof(a0));
                send_scsi(g_hDrive, a0cdb, 10, a0, 16,
                          SCSI_IOCTL_DATA_IN, sense, &st);
                printf("  READ BUFFER 0xA0: %02X %02X %02X %02X\n",
                       a0[0],a0[1],a0[2],a0[3]);
            }
            Sleep(200);

            /* Probe all vendor buffers */
            printf("  Probing buffers:\n");
            {
                static const UCHAR ids[] = {
                    0xF0,0xF1,0xF2,0xF3,0xF4,0xF5,
                    0xF6,0xF7,0xF8,0xF9,0xFA,0xFB,
                    0xFC,0xFD,0xFE,0xA0
                };
                int b;
                for (b = 0; b < 16; b++) {
                    DWORD cap = 0;
                    if (!rb_descriptor(ids[b], &cap) && cap > 0)
                        printf("    0x%02X  accessible  0x%08lX bytes\n",
                               ids[b], cap);
                }
            }

            /* Check 0xF4 specifically */
            {
                DWORD cap = 0;
                if (!rb_descriptor(0xF4, &cap) && cap > 0) {
                    printf("\n  *** 0xF4 ACCESSIBLE - SERVICE MODE ACTIVE ***\n");
                    printf("  Key: 0x%08lX (%s)\n", key, keys[j].name);
                    printf("  Run: drivekit rawdump %c\n", g_drivePath[4]);
                    return 0;
                } else {
                    printf("  0xF4 still locked - drive may need rawdump with different bufID\n");
                    printf("  Try: drivekit probef0 %c\n", g_drivePath[4]);
                    return 0;
                }
            }
        } else {
            UCHAR asc = sense[12];
            if (asc == 0x26)
                printf("INVALID PARAM (wrong key)\n");
            else
                printf("key=%02X ASC=%02X\n",
                       sense[2]&0x0F, asc);
        }
        Sleep(50);
    }

    printf("\n  All keys tried. None produced GOOD + 0xF4 accessible.\n");
    printf("  The payload model string or structure may be wrong.\n");
    return 0;
}

/* =========================================================
   PIONEER SERIAL NUMBER DECODER
   Format: P M CC NNNN XX
   P  = plant/factory code (1 char)
   M  = month (A=Jan, B=Feb... I=Sep, J=Oct, K=Nov, L=Dec, M=?) no skip
   CC = country code (2 chars at pos 2-3, little-endian word)
   NNNN = sequence number (pos 4-7), year = 2002 + seq[6-7]
   WW = week number (pos 8-9)
   MK = market destination (pos 10-11, JP=Japan etc)
   Based on reverse engineering of BDRFlash sub_414025
   ========================================================= */
static void pioneer_serial_decode(const char *serial,
                                  char *month_out,
                                  char *year_out,
                                  char *country_out)
{
    const char *months[] = {
        "January","February","March","April","May","June",
        "July","August","September","October","November","December"
    };
    char month_letter;
    int  month_idx = -1;
    unsigned short cc; /* 2-letter country code big-endian from pos 2-3 */

    if (!serial || strlen(serial) < 4) {
        if (month_out)   strcpy(month_out,   "Unknown");
        if (year_out)    strcpy(year_out,    "Unknown");
        if (country_out) strcpy(country_out, "Unknown");
        return;
    }

    /* Position 1 = month letter - UNICODE version mapping
       A=Jan, B=Feb, C=Mar, D=Apr, E=May, F=Jun, G=Jul,
       H=Aug, I=Sep, J=Oct, K=Nov, L=Dec, M=?
       Note: ANSI version uses different mapping (skips I-O)
       Based on BDRFlash UNICODE sub_414025 */
    month_letter = serial[1];
    if (month_letter >= 'A' && month_letter <= 'L') {
        month_idx = month_letter - 'A'; /* A=0=Jan ... L=11=Dec */
    }
    if (month_out) {
        if (month_idx >= 0 && month_idx < 12)
            strcpy(month_out, months[month_idx]);
        else
            strcpy(month_out, "Unknown");
    }

    /* Year: position 0 = year letter
       Old format (pre-2021): A=2001, B=2002, ... N=2014, ... Z=2026
       New format (post-2021 reset): A=2021/2022, B=2022, C=2023, D=2024, E=2025, F=2026
       O=2020 seen in new format too
       Source: cxplay (MakeMKV forum) - confirmed against known drive production dates */
    if (year_out) {
        char year_letter = serial[0];
        int year = -1;

        /* New format detection - if sequence number starts high (>026000 approx)
           and letter is A-F, likely new format. Heuristic: use new format if
           letter A-F and sequence > 020000 */
        int seq_num = 0;
        { int i, valid=1;
          for(i=0;i<4;i++){
              if(serial[4+i]<'0'||serial[4+i]>'9'){valid=0;break;}
              seq_num=seq_num*10+(serial[4+i]-'0');
          }
          if(!valid) seq_num=0;
        }

        /* Try new format first for A-F if sequence > 20000 */
        if (seq_num > 20000 && year_letter >= 'A' && year_letter <= 'F') {
            int new_years[] = {2021, 2022, 2023, 2024, 2025, 2026};
            year = new_years[year_letter - 'A'];
        } else if (year_letter == 'O' && seq_num > 40000) {
            year = 2020; /* O=2020 in new format */
        } else {
            /* Old format: A=2001 ... Z=2026 */
            if (year_letter >= 'A' && year_letter <= 'Z')
                year = 2001 + (year_letter - 'A');
        }

        if (year > 0) {
            char seq[5]={0}; int i;
            for(i=0;i<4;i++) seq[i]=serial[4+i];
            snprintf(year_out, 32, "%d (seq:%s)", year, seq);
        } else {
            char seq[5]={0}; int i;
            for(i=0;i<4;i++) seq[i]=serial[4+i];
            snprintf(year_out, 32, "? (seq:%s)", seq);
        }
    }

    /* Country code: positions 2-3 loaded as little-endian 16-bit word
       i.e. cc = (serial[3]<<8) | serial[2]
       Factory codes confirmed by cxplay:
       DL = Pioneer High Technology (Dongguan) Co., Ltd., Guangdong China */
    if (country_out) {
        cc = ((unsigned short)(unsigned char)serial[3] << 8) |
              (unsigned short)(unsigned char)serial[2];
        switch (cc) {
            /* Japan */
            case 0x4544: /* DE */ case 0x494E: /* NI */ case 0x454E: /* NE */
            case 0x4145: /* EA */ case 0x414B: /* KA */ case 0x4B4A: /* JK */
            case 0x5450: /* PT */ case 0x5454: /* TT */ case 0x4D53: /* SM */
            case 0x574B: /* WK */ case 0xFFFF: case 0x544F: /* OT */
                strcpy(country_out, "Japan"); break;
            /* Malaysia */
            case 0x5347: /* GS */
                strcpy(country_out, "Malaysia"); break;
            /* China */
            case 0x4443: /* CD */ case 0x4C44: /* DL */ case 0x5241: /* AR */
            case 0x5350: /* PS */ case 0x5353: /* SS */ case 0x434D: /* MC */
            case 0x4450: /* PD */ case 0x5143: /* CQ */
                strcpy(country_out, "China"); break;
            /* Indonesia */
            case 0x4954: /* TI */ case 0x0000:
                strcpy(country_out, "Indonesia"); break;
            default:
                strcpy(country_out, "Unknown");
                break;
        }

        /* Market destination from positions 10-11 - only known codes */
        if (strlen(serial) >= 12) {
            const char *mkt = NULL;
            if (serial[10]=='J' && serial[11]=='P') mkt = "JP";
            else if (serial[10]=='C' && serial[11]=='N') mkt = "CN";
            else if (serial[10]=='M' && serial[11]=='Y') mkt = "MY";
            else if (serial[10]=='I' && serial[11]=='D') mkt = "ID";
            if (mkt) {
                strcat(country_out, " (market: ");
                strcat(country_out, mkt);
                strcat(country_out, ")");
            }
        }
    }
}

static void print_drive_info(HANDLE hDrive, const char *path)
{
    UCHAR   buf[512], sense[SENSE_SIZE], cdb[12];
    SPTD_EX sx;
    DWORD   br;
    int     j;

    printf("  +------------------------------------------+\n");
    printf("  |  DRIVE INFORMATION                       |\n");
    printf("  +------------------------------------------+\n");

    /* ---- INQUIRY ---- */
    {
        UCHAR inq[96];
        UCHAR icdb[6] = {0x12,0,0,0,96,0};
        char  vendor[9]={0}, product[17]={0}, rev[5]={0};

        memset(inq,0,sizeof(inq));
        memset(&sx,0,sizeof(sx));
        sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sx.sptd.CdbLength          = 6;
        sx.sptd.SenseInfoLength    = SENSE_SIZE;
        sx.sptd.DataIn             = SCSI_IOCTL_DATA_IN;
        sx.sptd.DataTransferLength = 96;
        sx.sptd.TimeOutValue       = 10;
        sx.sptd.DataBuffer         = inq;
        sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX,sense);
        memcpy(sx.sptd.Cdb,icdb,6);
        DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);

        if (sx.sptd.ScsiStatus == 0) {
            memcpy(vendor,  &inq[8],  8);
            memcpy(product, &inq[16], 16);
            memcpy(rev,     &inq[32], 4);
            for (j=7;  j>=0 && vendor[j]==' ';  j--) vendor[j]  ='\0';
            for (j=15; j>=0 && product[j]==' '; j--) product[j] ='\0';
            for (j=3;  j>=0 && rev[j]==' ';     j--) rev[j]     ='\0';

            printf("  Drive     : %-28s|\n", path);
            printf("  Vendor    : %-28s|\n", vendor);
            printf("  Model     : %-28s|\n", product);
            printf("  Firmware  : %-28s|\n", rev);
            /* Firmware date at INQUIRY[0x25-0x2C] e.g. "22/12/27" (confirmed MrPenguin) */
            {
                char fwdate[16] = {0};
                int k;
                for (k = 0; k < 8 && inq[0x25+k] >= 0x20 && inq[0x25+k] <= 0x7E; k++)
                    fwdate[k] = inq[0x25+k];
                /* trim trailing spaces */
                for (k = 7; k >= 0 && fwdate[k] == ' '; k--) fwdate[k] = 0;
                if (fwdate[0] && fwdate[2] == '/')
                    printf("  FW Date   : %-28s|\n", fwdate);
            }
            /* AACS version from GET CONFIGURATION feature 0x010D
               byte [0x0C] = highest AACS version supported */
            {
                UCHAR gcbuf[0x20] = {0};
                UCHAR gccdb[10] = {0x46,0x00,0x01,0x0C,0,0,0,0,0x1C,0};
                memset(&sx,0,sizeof(sx));
                sx.sptd.Length=sizeof(SCSI_PASS_THROUGH_DIRECT);
                sx.sptd.CdbLength=10;
                sx.sptd.SenseInfoLength=SENSE_SIZE;
                sx.sptd.DataIn=SCSI_IOCTL_DATA_IN;
                sx.sptd.DataTransferLength=0x1C;
                sx.sptd.TimeOutValue=5;
                sx.sptd.DataBuffer=gcbuf;
                sx.sptd.SenseInfoOffset=offsetof(SPTD_EX,sense);
                memcpy(sx.sptd.Cdb,gccdb,10);
                DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                                &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);
                if (sx.sptd.ScsiStatus==0 && gcbuf[8]==0x01 && gcbuf[9]==0x0D) {
                    char aacs[16]={0};
                    snprintf(aacs,sizeof(aacs),"%d (0x%02X)",gcbuf[0x0C],gcbuf[0x0C]);
                    printf("  AACS ver  : %-28s|\n", aacs);
                }
            }
            printf("  Type      : %-28s|\n",
                   (inq[0]&0x1F)==0x05 ? "CD/DVD/BD optical" :
                   (inq[0]&0x1F)==0x00 ? "Direct-access" : "Other");
            printf("  Removable : %-28s|\n", (inq[1]&0x80)?"Yes":"No");
            printf("  SCSI ver  : %-28u|\n", inq[2]);
        }
    }

    /* ---- READ BUFFER 0xF1 - RS8801 serial/platform/kernel ---- */
    {
        UCHAR rb[64];
        UCHAR rbcdb[10]={0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
        char  serial[16]={0}, platform[16]={0}, kernel[8]={0};

        memset(rb,0,sizeof(rb));
        memset(&sx,0,sizeof(sx));
        sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sx.sptd.CdbLength          = 10;
        sx.sptd.SenseInfoLength    = SENSE_SIZE;
        sx.sptd.DataIn             = SCSI_IOCTL_DATA_IN;
        sx.sptd.DataTransferLength = 48;
        sx.sptd.TimeOutValue       = 10;
        sx.sptd.DataBuffer         = rb;
        sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX,sense);
        memcpy(sx.sptd.Cdb,rbcdb,10);
        DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);

        if (sx.sptd.ScsiStatus == 0) {
            /* 0xF1 layout: serial at 0x00, platform at 0x10, kernel at 0x18 */
            for (j=0;j<12&&rb[j]   >=0x20&&rb[j]   <0x7F;j++) serial[j]   = rb[j];
            for (j=0;j<12&&rb[0x10+j]>=0x20&&rb[0x10+j]<0x7F;j++) platform[j] = rb[0x10+j];
            for (j=0;j<6 &&rb[0x18+j]>=0x20&&rb[0x18+j]<0x7F;j++) kernel[j]   = rb[0x18+j];
            if (serial[0])   {
                char month[16]={0}, year[32]={0}, country[32]={0};
                char mfgdate[32]={0};
                pioneer_serial_decode(serial, month, year, country);
                snprintf(mfgdate, sizeof(mfgdate), "%s %s", month, year);
                printf("  Serial    : %-28s|\n", serial);
                printf("  Mfg Date  : %-28s|\n", mfgdate);
                printf("  Country   : %-28s|\n", country);
            }
            if (platform[0]) printf("  Platform  : %-28s|\n", platform);
            if (kernel[0])   printf("  Kernel    : %-28s|\n", kernel);
            if (platform[0]) {
                const char *p2 = platform;
                WORD did2 = 0;
                while (*p2 && (*p2<'0'||*p2>'9') && (*p2<'A'||*p2>'F') && (*p2<'a'||*p2>'f')) p2++;
                if (*p2) did2 = (WORD)strtol(p2, NULL, 16);
                if (did2) {
                    const PIONEER_DRIVE *pd = pioneer_lookup(did2);
                    if (pd) {
                        const char *nm = pd->model;
                        while (*nm==' ') nm++;
                        if (strncmp(nm,"PIONEER",7)==0){nm+=7;while(*nm==' ')nm++;}
                        printf("  Drive name: %-28s|\n", nm);
                    }
                }
            }
        }
    }

    /* ---- MODE PAGE 0x2A - buffer size, max speed ---- */
    {
        UCHAR mp[512];
        UCHAR mpcdb[10]={0x5A,0,0x2A,0,0,0,0,0x02,0x00,0};

        memset(mp,0,sizeof(mp));
        memset(&sx,0,sizeof(sx));
        sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sx.sptd.CdbLength          = 10;
        sx.sptd.SenseInfoLength    = SENSE_SIZE;
        sx.sptd.DataIn             = SCSI_IOCTL_DATA_IN;
        sx.sptd.DataTransferLength = 512;
        sx.sptd.TimeOutValue       = 10;
        sx.sptd.DataBuffer         = mp;
        sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX,sense);
        memcpy(sx.sptd.Cdb,mpcdb,10);
        DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);

        if (sx.sptd.ScsiStatus == 0) {
            WORD bdLen = ((WORD)mp[6]<<8)|mp[7];
            const UCHAR *page = mp + 8 + bdLen;
            if (page[1] >= 14) {
                WORD maxRd  = ((WORD)page[8]<<8) |page[9];
                WORD bufKB  = ((WORD)page[12]<<8)|page[13];
                WORD maxWr  = 0;
                if (page[1] >= 20)
                    maxWr = ((WORD)page[18]<<8)|page[19];
                {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%u KB", bufKB);
                    printf("  Buffer    : %-28s|\n", tmp);
                }
                {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%u KB/s (~%ux CD)", maxRd, maxRd/150);
                    printf("  Max read  : %-28s|\n", tmp);
                }
                if (maxWr) {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%u KB/s (~%ux CD)", maxWr, maxWr/150);
                    printf("  Max write : %-28s|\n", tmp);
                }
                printf("  Mech type : %-28s|\n",
                       ((page[6]>>4)&7)==1?"Tray":
                       ((page[6]>>4)&7)==0?"Caddy":"Other");
                {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "CD-R=%s CD-RW=%s DVD-R=%s",
                             (page[3]&0x01)?"Y":"N",
                             (page[3]&0x02)?"Y":"N",
                             (page[3]&0x10)?"Y":"N");
                    printf("  Write cap : %-28s|\n", tmp);
                }
            }
        }
    }

    /* ---- GET CONFIGURATION - current profile + 0x0113 ---- */
    {
        UCHAR gc[64];
        UCHAR gccdb[10]={0x46,0x00,0,0,0,0,0,0,0x40,0};

        memset(gc,0,sizeof(gc));
        memset(&sx,0,sizeof(sx));
        sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sx.sptd.CdbLength          = 10;
        sx.sptd.SenseInfoLength    = SENSE_SIZE;
        sx.sptd.DataIn             = SCSI_IOCTL_DATA_IN;
        sx.sptd.DataTransferLength = 64;
        sx.sptd.TimeOutValue       = 10;
        sx.sptd.DataBuffer         = gc;
        sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX,sense);
        memcpy(sx.sptd.Cdb,gccdb,10);
        DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);

        if (sx.sptd.ScsiStatus == 0) {
            WORD profile = ((WORD)gc[6]<<8)|gc[7];
            const char *profName =
                profile==0x0000?"No disc":
                profile==0x0008?"CD-ROM":
                profile==0x0009?"CD-R":
                profile==0x000A?"CD-RW":
                profile==0x0010?"DVD-ROM":
                profile==0x0011?"DVD-R":
                profile==0x0012?"DVD-RAM":
                profile==0x001A?"DVD+RW":
                profile==0x001B?"DVD+R":
                profile==0x002B?"DVD+R DL":
                profile==0x0040?"BD-ROM":
                profile==0x0041?"BD-R SRM":
                profile==0x0042?"BD-R RRM":
                profile==0x0043?"BD-RE":"Unknown";
            {
                char tmp[48];
                snprintf(tmp, sizeof(tmp), "%s (0x%04X)", profName, profile);
                printf("  Disc      : %-28s|\n", tmp);
            }
        }
    }

    /* ---- 0xE2 - ASUS/RS8801 vendor identifier ---- */
    {
        UCHAR e2[32];
        UCHAR e2cdb[12]={0xE2,0,0,0,0,0,0,0,0x20,0,0,0};

        memset(e2,0,sizeof(e2));
        memset(&sx,0,sizeof(sx));
        sx.sptd.Length             = sizeof(SCSI_PASS_THROUGH_DIRECT);
        sx.sptd.CdbLength          = 12;
        sx.sptd.SenseInfoLength    = SENSE_SIZE;
        sx.sptd.DataIn             = SCSI_IOCTL_DATA_IN;
        sx.sptd.DataTransferLength = 32;
        sx.sptd.TimeOutValue       = 10;
        sx.sptd.DataBuffer         = e2;
        sx.sptd.SenseInfoOffset    = offsetof(SPTD_EX,sense);
        memcpy(sx.sptd.Cdb,e2cdb,12);
        DeviceIoControl(hDrive,IOCTL_SCSI_PASS_THROUGH_DIRECT,
                        &sx,sizeof(sx),&sx,sizeof(sx),&br,NULL);

        if (sx.sptd.ScsiStatus == 0) {
            /* Extract printable vendor string from response */
            char vstr[32] = {0};
            int  vlen = 0;
            for (j = 4; j < 32 && vlen < 20; j++) {
                if (e2[j] >= 0x20 && e2[j] < 0x7F)
                    vstr[vlen++] = e2[j];
                else if (vlen > 0)
                    break;
            }
            if (vlen > 0) {
                char tmp[40];
                snprintf(tmp, sizeof(tmp), "%s (via 0xE2)", vstr);
                printf("  Vendor ID : %-28s|\n", tmp);
            }
            if (e2[0]=='L'&&e2[1]=='D'&&e2[2]=='R'&&e2[3]=='E')
                printf("  LibreDrive: %-28s|\n", "ACTIVE (LDRE signature)");
        }
    }

    printf("  +------------------------------------------+\n");
    printf("\n");
}

/* =========================================================
   COMMAND: resetnormal
   Attempt to exit kernel/service mode and return to normal mode.
   ========================================================= */
static int cmd_resetnormal(void)
{
    UCHAR sense[SENSE_SIZE];
    UCHAR cdb[10] = {0x3B,0x00,0xFF,0,0,0,0,0,0,0};
    UCHAR payload[0x100] = {0};
    int   st = 0, attempt;

    printf("=== RESET TO NORMAL MODE ===\n\n");
    printf("Attempting to exit kernel/service mode...\n\n");

    send_scsi(g_hDrive, cdb, 10, payload, 0x100,
              SCSI_IOCTL_DATA_OUT, sense, &st);
    printf("  WRITE BUFFER mode=0: %s\n", st==0?"GOOD":"FAIL");

    for (attempt = 0; attempt < 30; attempt++) {
        UCHAR tcdb[6] = {0,0,0,0,0,0};
        Sleep(1000);
        send_scsi(g_hDrive, tcdb, 6, NULL, 0,
                  SCSI_IOCTL_DATA_UNSPECIFIED, sense, &st);
        if (st == 0) {
            printf("  Drive ready after %d seconds\n", attempt+1);
            break;
        }
        printf("\r  Waiting %d/30...", attempt+1);
        fflush(stdout);
    }
    printf("\n\nRun: drivekit inquiry to check firmware version\n");
    return 0;
}

/* =========================================================
   COMMAND: triggerkernel
   Sends single READ BUFFER 0xB0 offset=0x04 length=0xA4 (164 bytes)
   From Wireshark capture of autoflasher: 3c 02 b0 00 00 04 00 00 a4 00
   Note: length field is 0x00A4 = 164 bytes, NOT 0xA400!
   ========================================================= */
static int cmd_triggerkernel(void)
{
    UCHAR sense[SENSE_SIZE];
    UCHAR buf[0xA400];
    int   st = 0, b;

    printf("=== KERNEL MODE TRIGGER ===\n\n");
    printf("  Sending READ BUFFER 0xB0 offset=0x04 len=0xA400 (41KB)...\n");
    printf("  (This triggers drive to enter kernel mode and reboot)\n\n");

    {
        UCHAR cdb[10] = {0x3C,0x02,0xB0,0x00,0x00,0x04,0x00,0x00,0xA4,0x00};
        memset(buf, 0, sizeof(buf));
        send_scsi(g_hDrive, cdb, 10, buf, 0xA400,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        printf("  Status: %s", st==0?"GOOD":"FAIL");
        if (st != 0)
            printf(" (key=%02X ASC=%02X)", sense[2]&0x0F, sense[12]);
        printf("\n");
        if (st == 0) {
            printf("  First bytes:");
            for (b = 0; b < 16; b++) printf(" %02X", buf[b]);
            printf("\n");
        }
    }

    printf("\n  Waiting for drive to reboot into kernel mode...\n");
    {
        int attempt;
        for (attempt = 0; attempt < 120; attempt++) {
            UCHAR cdb[6]  = {0,0,0,0,0,0};
            UCHAR sense2[SENSE_SIZE];
            int   st2 = 0;
            UCHAR skey, asc;
            Sleep(1000);

            send_scsi(g_hDrive, cdb, 6, NULL, 0,
                      SCSI_IOCTL_DATA_UNSPECIFIED, sense2, &st2);
            skey = sense2[2] & 0x0F;
            asc  = sense2[12];

            /* Clear unit attention */
            if (skey == 0x06) {
                UCHAR rscdb[6] = {0x03,0,0,0,0x12,0};
                UCHAR rsbuf[18];
                int   rst = 0;
                memset(rsbuf, 0, sizeof(rsbuf));
                send_scsi(g_hDrive, rscdb, 6, rsbuf, 18,
                          SCSI_IOCTL_DATA_IN, sense2, &rst);
                continue;
            }

            printf("\r  Attempt %2d/60: skey=%02X ASC=%02X  ",
                   attempt+1, skey, asc);
            fflush(stdout);

            if (st2 == 0) {
                printf("READY\n\n");

                /* Check kernel mode */
                UCHAR rb[0x30];
                UCHAR f1cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
                memset(rb, 0, sizeof(rb));
                send_scsi(g_hDrive, f1cdb, 10, rb, 0x30,
                          SCSI_IOCTL_DATA_IN, sense2, &st2);
                if (st2 == 0) {
                    int is_kernel = (memcmp(rb+0x14,"        ",8)!=0);
                    printf("  Drive mode: %s\n\n",
                           is_kernel?"*** KERNEL MODE ***":"normal mode");
                    if (is_kernel)
                        printf("  Run: drivekit rawdump %c --bufid B0\n",
                               g_drivePath[4]);
                }
                return 0;
            }
        }
        printf("\n  Drive did not become ready in 60s.\n");
    }
    return 0;
}

/* =========================================================
   COMMAND: checkfw
   Checks connected drive's firmware against drives.json
   Open community database of known Pioneer firmware.
   Place drives.json in same directory as drivekit.exe
   ========================================================= */
static int cmd_checkfw(void)
{
    UCHAR   buf[0x500];
    UCHAR   sense[SENSE_SIZE];
    UCHAR   cdb[10];
    int     st = 0;
    char    vendor[9]   = {0};
    char    model[17]   = {0};
    char    fw[5]       = {0};
    char    serial[16]  = {0};
    char    drive_id[5] = {0};
    char   *cs_ptr, *fw_ptr, *date_ptr, *drv_ptr;
    FILE   *fp;
    char    line[512];
    char    db_path[MAX_PATH];
    int     found       = 0;
    int     total       = 0;

    printf("=== FIRMWARE CHECK ===\n\n");

    /* Read drive identity via INQUIRY */
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0x12; cdb[4] = 0x60;
    memset(buf, 0, sizeof(buf));
    send_scsi(g_hDrive, cdb, 6, buf, 0x60,
              SCSI_IOCTL_DATA_IN, sense, &st);
    if (st != 0) {
        printf("  INQUIRY failed\n");
        return 1;
    }
    memcpy(vendor, buf+8,  8); vendor[8]  = 0;
    memcpy(model,  buf+16, 16); model[16] = 0;
    memcpy(fw,     buf+32, 4); fw[4]      = 0;
    /* Trim trailing spaces */
    { int i; for(i=7;i>=0&&vendor[i]==' ';i--) vendor[i]=0; }
    { int i; for(i=15;i>=0&&model[i]==' ';i--) model[i]=0; }
    { int i; for(i=3;i>=0&&fw[i]==' ';i--) fw[i]=0; }

    /* Read drive ID from 0xF1 */
    {
        UCHAR f1[0x50];
        UCHAR f1cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0x00,0x50,0};
        memset(f1, 0, sizeof(f1));
        send_scsi(g_hDrive, f1cdb, 10, f1, 0x50,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0) {
            /* Platform string at +0x10: "SAT 8231ID35"
               Skip alpha/space prefix to find the hex drive ID */
            const char *p = (const char*)(f1+0x10);
            /* Skip to first digit */
            while (*p && !(*p>='0'&&*p<='9') && !(*p>='A'&&*p<='F')) p++;
            if (*p) {
                char tmp[5] = {0};
                int i;
                for (i=0; i<4 && p[i] && ((p[i]>='0'&&p[i]<='9')||(p[i]>='A'&&p[i]<='F')); i++)
                    tmp[i] = p[i];
                strncpy(drive_id, tmp, 4);
            }
        }
    }

    /* Serial from feature 0x108 */
    {
        UCHAR feat[64];
        UCHAR fcdb[10] = {0x46,0x00,0x01,0x08,0,0,0,0,0x40,0};
        memset(feat, 0, sizeof(feat));
        send_scsi(g_hDrive, fcdb, 10, feat, 64,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0 && feat[9] == 0x08) {
            int slen = feat[11];
            if (slen > 12) slen = 12;
            memcpy(serial, feat+12, slen);
        }
    }

    printf("  Vendor   : %s\n", vendor);
    printf("  Model    : %s\n", model);
    printf("  Firmware : %s\n", fw);
    if (drive_id[0]) printf("  Drive ID : 0x%s\n", drive_id);
    if (serial[0])   printf("  Serial   : %s\n", serial);
    printf("\n");

    /* Find drives.json - same dir as executable */
    {
        char exe_path[MAX_PATH];
        char *last_sep;
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
        last_sep = strrchr(exe_path, '\\');
        if (last_sep) {
            *last_sep = 0;
            snprintf(db_path, MAX_PATH, "%s\\drives.json", exe_path);
        } else {
            strcpy(db_path, "drives.json");
        }
    }

    fp = fopen(db_path, "r");
    if (!fp) {
        /* Try current directory */
        fp = fopen("drives.json", "r");
        if (!fp) {
            printf("  drives.json not found.\n");
            printf("  Place drives.json in same directory as drivekit.exe\n");
            printf("  Download from: https://github.com/eivindschjerven/drivekit\n");
            return 1;
        }
    }

    printf("  Searching drives.json...\n\n");

    /* JSON parser — handles both compact (one object per line)
       and pretty-printed (multi-line) JSON objects */
    {
        char obj[2048] = {0};
        int  obj_len = 0;
        int  depth = 0;

        while (fgets(line, sizeof(line), fp)) {
            int li;
            for (li = 0; line[li]; li++) {
                if (obj_len < (int)sizeof(obj)-2)
                    obj[obj_len++] = line[li];
                if (line[li] == '{') depth++;
                else if (line[li] == '}') {
                    depth--;
                    if (depth <= 0 && obj_len > 2) {
                        obj[obj_len] = 0;
                        if (strstr(obj, "\"checksum\"")) total++;
                        fw_ptr = strstr(obj, "\"fw\"");
                        if (fw_ptr) {
                            char fw_val[8]={0}, cs[10]={0};
                            char date[12]={0}, did[8]={0};
                            char *q, *p, *p2, *p3;
                            int  ii;
                            q = strchr(fw_ptr, ':');
                            if (q) {
                                q++; while(*q==' '||*q=='"') q++;
                                ii=0; while(q[ii]&&q[ii]!='"'&&ii<7){fw_val[ii]=q[ii];ii++;}
                            }
                            if (strcmp(fw_val, fw) == 0) {
                                cs_ptr   = strstr(obj, "\"checksum\"");
                                date_ptr = strstr(obj, "\"date\"");
                                drv_ptr  = strstr(obj, "\"drive_id\"");
                                if (cs_ptr) {
                                    p = strchr(cs_ptr,':');
                                    if(p){p++;while(*p==' '||*p=='"')p++;
                                        ii=0;while(p[ii]&&p[ii]!='"'&&ii<9){cs[ii]=p[ii];ii++;}}
                                }
                                if (date_ptr) {
                                    p2 = strchr(date_ptr,':');
                                    if(p2){p2++;while(*p2==' '||*p2=='"')p2++;
                                        ii=0;while(p2[ii]&&p2[ii]!='"'&&ii<11){date[ii]=p2[ii];ii++;}}
                                }
                                if (drv_ptr) {
                                    p3 = strchr(drv_ptr,':');
                                    if(p3){p3++;while(*p3==' '||*p3=='"')p3++;
                                        ii=0;while(p3[ii]&&p3[ii]!='"'&&ii<7){did[ii]=p3[ii];ii++;}}
                                }
                                printf("  MATCH FOUND:\n");
                                printf("    Checksum : %s\n", cs);
                                printf("    Drive ID : %s\n", did);
                                printf("    Date     : %s\n", date);
                                printf("    Status   : LibreDrive supported (original firmware)\n");
                                found++;
                            }
                        }
                        obj_len = 0; obj[0] = 0; depth = 0;
                    }
                }
            }
        }
    }
    fclose(fp);

    if (!found) {
        printf("  No match found in drives.json for firmware %s\n\n", fw);
        printf("  This firmware may be:\n");
        printf("    - A patched/modified version\n");
        printf("    - A newer version not yet in the database\n");
        printf("    - An unsupported model\n");
        printf("\n  Run: drivekit fwversion G  for more drive details\n");
    }

    printf("\n  Database: %d firmware entries checked\n", total);
    return 0;
}

/* =========================================================
   COMMAND: checkcompat
   Checks connected drive against compatibility.json —
   our analyzed firmware database with confirmed crossflash
   compatibility groups, second unlock key findings, and
   H8S/2600 memory map data.

   Unlike drives.json (LibreDrive list), compatibility.json
   is built from actual firmware file analysis and is safe
   to use for crossflash decisions.

   Place compatibility.json in same directory as drivekit.exe
   ========================================================= */
static int cmd_checkcompat(void)
{
    UCHAR   buf[0x60];
    UCHAR   sense[SENSE_SIZE];
    UCHAR   cdb[10];
    int     st = 0;
    char    model[17]   = {0};
    char    fw[5]       = {0};
    char    platform[16]= {0};
    char    drive_id_str[5] = {0};
    WORD    drive_id    = 0;
    FILE   *fp;
    char    line[1024];
    char    db_path[MAX_PATH];
    int     found_exact = 0;
    int     found_compat= 0;
    int     total       = 0;
    const char *db_name = "compatibility.json";

    printf("=== COMPATIBILITY CHECK ===\n\n");

    /* INQUIRY */
    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0x12; cdb[4] = 0x60;
    memset(buf, 0, sizeof(buf));
    send_scsi(g_hDrive, cdb, 6, buf, 0x60, SCSI_IOCTL_DATA_IN, sense, &st);
    if (st != 0) { printf("  INQUIRY failed\n"); return 1; }
    memcpy(model, buf+16, 16); model[16] = 0;
    memcpy(fw,    buf+32, 4);  fw[4]     = 0;
    { int i; for(i=15;i>=0&&model[i]==' ';i--) model[i]=0; }
    { int i; for(i=3; i>=0&&fw[i]==' ';   i--) fw[i]=0;    }

    /* Platform from 0xF1 */
    {
        UCHAR f1[0x30];
        UCHAR f1cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
        memset(f1, 0, sizeof(f1));
        send_scsi(g_hDrive, f1cdb, 10, f1, 0x30, SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0) {
            int j;
            for (j=0;j<12&&f1[0x10+j]>=0x20&&f1[0x10+j]<0x7F;j++)
                platform[j] = f1[0x10+j];
            /* Extract hex drive ID - find 4 consecutive hex digits */
            {
                const char *p = platform;
                int found = 0;
                while (*p && !found) {
                    /* Check if 4 consecutive hex digits start here */
                    if ((p[0]>='0'&&p[0]<='9')||(p[0]>='A'&&p[0]<='F')) {
                        if (((p[1]>='0'&&p[1]<='9')||(p[1]>='A'&&p[1]<='F')) &&
                            ((p[2]>='0'&&p[2]<='9')||(p[2]>='A'&&p[2]<='F')) &&
                            ((p[3]>='0'&&p[3]<='9')||(p[3]>='A'&&p[3]<='F'))) {
                            char tmp[5]={0};
                            memcpy(tmp, p, 4);
                            strncpy(drive_id_str, tmp, 4);
                            drive_id = (WORD)strtol(tmp, NULL, 16);
                            found = 1;
                        }
                    }
                    p++;
                }
            }
        }
    }

    printf("  Model    : %s\n", model);
    printf("  Firmware : %s\n", fw);
    printf("  Platform : %s\n", platform);
    if (drive_id) printf("  Drive ID : 0x%04X\n", drive_id);
    printf("\n");

    /* Find compatibility.json */
    {
        char exe_path[MAX_PATH] = {0};
        char *last_sep;
#ifdef _WIN32
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);
#else
        { ssize_t n = readlink("/proc/self/exe", exe_path, MAX_PATH-1); if(n>0) exe_path[n]=0; }
#endif
        last_sep = strrchr(exe_path, '\\');
        if (!last_sep) last_sep = strrchr(exe_path, '/');
        if (last_sep) {
            *last_sep = 0;
#ifdef _WIN32
            snprintf(db_path, MAX_PATH, "%s\\%s", exe_path, db_name);
#else
            snprintf(db_path, MAX_PATH, "%s/%s", exe_path, db_name);
#endif
        } else {
            strncpy(db_path, db_name, MAX_PATH-1);
        }
    }

    fp = fopen(db_path, "r");
    if (!fp) fp = fopen(db_name, "r");
    if (!fp) {
        printf("  ERROR: %s not found.\n", db_name);
        printf("  Place compatibility.json in same directory as drivekit.exe\n");
        return 1;
    }

    printf("  Searching compatibility.json...\n\n");

    /* Parse JSON line by line - collect fields per object */
    printf("  === Exact platform matches ===\n");
    {
        char cur_file[256]={0}, cur_ver[16]={0}, cur_model[64]={0};
        char cur_type[16]={0}, cur_pid[16]={0}, cur_compat[512]={0};
        int  in_compat = 0;

        rewind(fp);
        while (fgets(line, sizeof(line), fp)) {
            char *p, *q;
            /* Trim */
            while(*line==' '||*line=='\t') memmove(line,line+1,strlen(line));

            if (strstr(line, "\"filename\"")) {
                /* New object starting - reset */
                memset(cur_file,0,sizeof(cur_file));
                memset(cur_ver,0,sizeof(cur_ver));
                memset(cur_model,0,sizeof(cur_model));
                memset(cur_type,0,sizeof(cur_type));
                memset(cur_pid,0,sizeof(cur_pid));
                memset(cur_compat,0,sizeof(cur_compat));
                in_compat = 0;
                p=strstr(line,"\"filename\"");
                p=strchr(p,':'); if(!p) continue;
                p=strchr(p,'"'); if(!p) continue; p++;
                q=strchr(p,'"'); if(!q) continue;
                memcpy(cur_file, p, q-p < 255 ? q-p : 255);
            }
            else if (strstr(line, "\"version\"")) {
                p=strstr(line,"\"version\"");
                p=strchr(p,':'); if(!p) continue;
                p=strchr(p,'"'); if(!p) continue; p++;
                q=strchr(p,'"'); if(!q) continue;
                memcpy(cur_ver, p, q-p < 15 ? q-p : 15);
            }
            else if (strstr(line, "\"model\"")) {
                p=strstr(line,"\"model\"");
                p=strchr(p,':'); if(!p) continue;
                p=strchr(p,'"'); if(!p) continue; p++;
                q=strchr(p,'"'); if(!q) continue;
                memcpy(cur_model, p, q-p < 63 ? q-p : 63);
            }
            else if (strstr(line, "\"file_type\"")) {
                p=strstr(line,"\"file_type\"");
                p=strchr(p,':'); if(!p) continue;
                p=strchr(p,'"'); if(!p) continue; p++;
                q=strchr(p,'"'); if(!q) continue;
                memcpy(cur_type, p, q-p < 15 ? q-p : 15);
            }
            else if (strstr(line, "\"platform_id\"")) {
                char search[16];
                char lpid[16]={0};
                int i;
                p=strstr(line,"\"platform_id\"");
                p=strchr(p,':'); if(!p) continue;
                p=strchr(p,'"'); if(!p) continue; p++;
                q=strchr(p,'"'); if(!q) continue;
                memcpy(cur_pid, p, q-p < 15 ? q-p : 15);

                /* Check if this matches our drive */
                snprintf(search, sizeof(search), "0x%04x", drive_id);
                for(i=0;cur_pid[i]&&i<15;i++) lpid[i]=tolower((unsigned char)cur_pid[i]);
                if (strcmp(lpid, search)==0) {
                    /* Only print if we haven't seen this model+version combo */
                    char combo[80]={0};
                    int  already_seen = 0;
                    int  si;
                    snprintf(combo, sizeof(combo), "%s|%s", cur_model, cur_ver);
                    /* Check seen list (simple array) */
                    static char seen[32][80];
                    static int  nseen = 0;
                    for(si=0;si<nseen;si++)
                        if(strcmp(seen[si],combo)==0){already_seen=1;break;}
                    if(!already_seen && nseen<32)
                        memcpy(seen[nseen++],combo,sizeof(combo));
                    if(!already_seen) {
                        printf("  MATCH: %-35s v%s\n", cur_model, cur_ver);
                        if (fw[0] && strstr(cur_ver, fw))
                            printf("         *** VERSION MATCHES CONNECTED DRIVE ***\n");
                        printf("\n");
                        found_exact++;
                    }
                }
            }
            else if (strstr(line, "\"crossflash_compatible\"")) {
                in_compat = 1;
            }
            else if (in_compat && strstr(line, "\"0x")) {
                p=strchr(line,'"'); if(p) p++;
                q=p?strchr(p,'"'):NULL;
                if(p&&q&&strlen(cur_compat)+20<511) {
                    char tmp[16]={0};
                    memcpy(tmp,p,q-p<15?q-p:15);
                    if(cur_compat[0]) strcat(cur_compat,",");
                    strcat(cur_compat,tmp);
                }
            }
            else if (in_compat && strchr(line,']')) {
                in_compat = 0;
            }
        }
    }

    if (!found_exact)
        printf("  No exact platform match found for 0x%04X\n\n", drive_id);

    /* Crossflash compatible section */
    rewind(fp);
    printf("  === Crossflash compatible firmware ===\n");
    printf("  (same compatibility group — safe to crossflash)\n\n");
    {
        static const WORD compat_groups[][5] = {
            {0x8231,0x8232,0x8B30,0,0},
            {0x8301,0x8600,0x8800,0,0},
            {0x8410,0x8510,0x8511,0x8A10,0},
            {0x8490,0x8590,0x8591,0,0},
            {0x8601,0x8801,0,0,0},
            {0x8721,0x8722,0,0,0},
            {0x8000,0x8800,0,0,0},
            {0x8D30,0x8D31,0,0,0},
            {0x8E20,0x8E21,0,0,0},
            {0x8F00,0x8F01,0,0,0},
            {0x9330,0x9331,0,0,0},
            {0,0,0,0,0}
        };
        int gi,gj;
        WORD compat[5]={0};
        int ncompat=0;

        for(gi=0;compat_groups[gi][0];gi++)
            for(gj=0;gj<5&&compat_groups[gi][gj];gj++)
                if(compat_groups[gi][gj]==drive_id) {
                    int k;
                    for(k=0;k<5&&compat_groups[gi][k];k++)
                        if(compat_groups[gi][k]!=drive_id)
                            compat[ncompat++]=compat_groups[gi][k];
                }

        if (!ncompat) {
            printf("  No crossflash group found for 0x%04X\n\n", drive_id);
        } else {
            /* Scan JSON for compat platform IDs */
            char cur_file[256]={0},cur_ver[16]={0},cur_model[64]={0};
            char cur_type[16]={0},cur_pid[16]={0};
            rewind(fp);
            while(fgets(line,sizeof(line),fp)) {
                char *p,*q;
                while(*line==' '||*line=='\t') memmove(line,line+1,strlen(line));
                if(strstr(line,"\"filename\"")) {
                    memset(cur_file,0,sizeof(cur_file));memset(cur_ver,0,sizeof(cur_ver));
                    memset(cur_model,0,sizeof(cur_model));memset(cur_type,0,sizeof(cur_type));
                    memset(cur_pid,0,sizeof(cur_pid));
                    p=strstr(line,"\"filename\"");p=strchr(p,':');if(!p)continue;
                    p=strchr(p,'"');if(!p)continue;p++;q=strchr(p,'"');if(!q)continue;
                    memcpy(cur_file,p,q-p<255?q-p:255);
                }
                else if(strstr(line,"\"version\"")) {
                    p=strstr(line,"\"version\"");p=strchr(p,':');if(!p)continue;
                    p=strchr(p,'"');if(!p)continue;p++;q=strchr(p,'"');if(!q)continue;
                    memcpy(cur_ver,p,q-p<15?q-p:15);
                }
                else if(strstr(line,"\"model\"")) {
                    p=strstr(line,"\"model\"");p=strchr(p,':');if(!p)continue;
                    p=strchr(p,'"');if(!p)continue;p++;q=strchr(p,'"');if(!q)continue;
                    memcpy(cur_model,p,q-p<63?q-p:63);
                }
                else if(strstr(line,"\"file_type\"")) {
                    p=strstr(line,"\"file_type\"");p=strchr(p,':');if(!p)continue;
                    p=strchr(p,'"');if(!p)continue;p++;q=strchr(p,'"');if(!q)continue;
                    memcpy(cur_type,p,q-p<15?q-p:15);
                }
                else if(strstr(line,"\"platform_id\"")) {
                    int ci;
                    p=strstr(line,"\"platform_id\"");
                    p=strchr(p,':');if(!p)continue;
                    p=strchr(p,'"');if(!p)continue;p++;
                    q=strchr(p,'"');if(!q)continue;
                    memcpy(cur_pid,p,q-p<15?q-p:15);
                    for(ci=0;ci<ncompat;ci++) {
                        char search[16];
                        char lpid[16]={0};
                        int i;
                        snprintf(search,sizeof(search),"0x%04x",compat[ci]);
                        for(i=0;cur_pid[i]&&i<15;i++) lpid[i]=tolower((unsigned char)cur_pid[i]);
                        if(strcmp(lpid,search)==0) {
                            /* Deduplicate by model+version */
                            char combo[80]={0};
                            int already=0, si;
                            static char cseen[64][80];
                            static int  ncseen=0;
                            snprintf(combo,sizeof(combo),"%s|%s",cur_model,cur_ver);
                            for(si=0;si<ncseen;si++)
                                if(strcmp(cseen[si],combo)==0){already=1;break;}
                            if(!already&&ncseen<64)
                                memcpy(cseen[ncseen++],combo,sizeof(combo));
                            if(!already) {
                                printf("  0x%04X  %-35s v%s\n",
                                       compat[ci], cur_model, cur_ver);
                                found_compat++;
                            }
                        }
                    }
                }
            }
            if(!found_compat) printf("  No compatible firmware found\n");
        }
    }

    fclose(fp);
    printf("\n  NOTE: Only flash firmware to drives in the same\n");
    printf("        compatibility group. Wrong firmware = brick!\n\n");
    return 0;
}
/* =========================================================
   Tries READ BUFFER modes 0,1,2,3,6 on vendor buffer IDs
   to find any accessible combination after unlock.
   ========================================================= */
static int cmd_probemodes(void)
{
    static const UCHAR ids[] = {
        0xA0, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
        0xF5, 0xF6, 0xF7, 0xFE, 0xFF
    };
    static const UCHAR modes[] = {0x00,0x01,0x02,0x03,0x06};
    int ni = sizeof(ids)/sizeof(ids[0]);
    int nm = sizeof(modes)/sizeof(modes[0]);
    int i, m;

    printf("=== PROBE READ BUFFER MODES ===\n\n");
    printf("  %-6s  %-6s  %s\n", "Mode", "BufID", "Preview");
    printf("  %-6s  %-6s  %s\n", "------","------","-------");

    for (m = 0; m < nm; m++) {
        for (i = 0; i < ni; i++) {
            UCHAR cdb[10];
            UCHAR buf[64];
            UCHAR sense[SENSE_SIZE];
            int   st = 0, b;

            memset(cdb, 0, sizeof(cdb));
            cdb[0]=0x3C; cdb[1]=modes[m]; cdb[2]=ids[i];
            cdb[8]=0x40;

            memset(buf, 0, sizeof(buf));
            send_scsi(g_hDrive, cdb, 10, buf, 64,
                      SCSI_IOCTL_DATA_IN, sense, &st);

            if (st == 0) {
                printf("  0x%02X    0x%02X    ", modes[m], ids[i]);
                for (b = 0; b < 16; b++) printf("%02X ", buf[b]);
                printf("\n");
            }
        }
    }
    return 0;
}

static void print_help(void)
{
    printf("DriveKit v1.0 - Optical Drive Research Toolkit\n");
    printf("by cPix / Razor 1911 (c) 2026\n");
    printf("================================================\n\n");
    printf("Usage:\n");
    printf("  drivekit <command> <drive_letter> [options]\n\n");
    printf("Identification:\n");
    printf("  info          Full drive information with serial decode\n");
    printf("  inquiry       Read drive vendor/model/firmware (alias: info)\n");
    printf("  discinfo      Read and parse BD/DVD disc information\n");
    printf("  modelcheck    Pioneer model lookup and internal model string\n");
    printf("  keycheck      Show unlock key for connected drive\n");
    printf("  checkcompat   Check drive against compatibility.json\n");
    printf("  probevendor   Probe vendor opcodes 0xC0-0xFF\n");
    printf("  probef0       Probe READ BUFFER IDs 0xF0-0xFF (dumps all buffers incl 0xF1)\n");
    printf("  probeb0       Read/decode RS8801 buffer 0xB0\n");
    printf("  rawdump       Raw READ BUFFER dump (--bufid 0xxx)\n");
    printf("  dumpfw        Read/scan Pioneer 5A/2A firmware window (does not unlock)\n\n");
    printf("Flashing:\n");
    printf("  unlock        Pioneer service mode unlock (auto session token)\n");
    printf("  hwdump        Enable 0xB0 dump on both pre/post-cutoff drives\n");
    printf("                  Dumps H8S/2600 kernel code to hwdump_b0.bin\n");
    printf("  flash         AUTO-DETECT pre/post-cutoff and flash (RECOMMENDED)\n");
    printf("                  --file kernel.bin --file2 normal.bin\n");
    printf("  flashfw       Legacy flash command (use 'flash' instead)\n");
    printf("  crossflash    Post-cutoff downgrade/crossflash (direct, no auto-detect)\n");
    printf("                  --file kernel.bin --file2 normal.bin [--key 0xAA475E15]\n");
    printf("  flashinfo     Show flash-relevant drive info (model string, key, platform)\n");
    printf("  xordiff       XOR two encrypted firmware files to find version bytes\n");
    printf("                  --file fw_new.bin --file2 fw_old.bin\n");
    printf("  patchfw       Patch firmware header to spoof version for downgrade\n");
    printf("  decryptkernel Decode KernelFront cipher; --patch applies gen-marker fix\n");
    printf("                  --file kernel.100 [--patch] [--file2 out.bin]\n");
    printf("  decodenormal  Decrypt normal firmware envelope; reports UHD capability\n");
    printf("                  --file S8D31051.104 [--file2 decoded_body.bin]\n");
    printf("  encryptkernel Re-encrypt a patched decoded kernel body back to .100\n");
    printf("                  --file decoded.bin --file2 original.100 [--file3 out.100]\n");
    printf("  autoflash     Auto-detect and flash from firmware\\ folder\n");
    printf("  resetnormal   Attempt to exit kernel/service mode\n");
    printf("  triggerkernel Trigger kernel mode via READ BUFFER 0xB0\n");
    printf("  brutekey      Try all known Pioneer unlock keys\n");
    printf("  sendcdb       Send raw SCSI CDB to drive\n\n");
    printf("Other:\n");
    printf("  about         About DriveKit and credits\n\n");
    printf("Options:\n");
    printf("  --file  name        Kernel firmware file\n");
    printf("  --file2 name        Normal firmware file\n");
    printf("  --file3 name        Second normal firmware pass (post-cutoff drives)\n");
    printf("  --bufid 0xF4        Buffer ID for rawdump (default 0xF4)\n");
    printf("  --force             Skip compatibility checks\n");
    printf("  --enableversion     Bypass era mismatch guard (research only — expect 04/4C/02)\n");
    printf("  --nounlock          Skip unlock step\n");
    printf("  --key 0x5CF2E094    Override unlock key\n");
    printf("  --patch             Apply generation marker patch (decryptkernel)\n\n");
    printf("Examples:\n");
    printf("  drivekit info G\n");
    printf("  drivekit unlock G\n");
    printf("  drivekit flashfw G --file S9330360.102 --file2 S9330361.101 --nounlock\n");
    printf("  drivekit rawdump G --bufid 0xB0\n");
    printf("  drivekit dumpfw G --file firmware_dump.bin\n");
    printf("  drivekit sendcdb G 3B 05 FF 00 00 00 00 01 00 00\n\n");
    printf("Note: Always eject disc before unlock/flash. Run as Administrator.\n");
}

/* FW153 candidate structure for autoflash */
typedef struct {
    char path[MAX_PATH];
    char hw[16];
    char ver[8];
    char model[32];
    int  is_kernel;
    long filesize;
} FW153;

/* =========================================================
   COMMAND: autoflash
   Scans ./firmware/ folder for Pioneer firmware files,
   detects valid files by content (Pioneer copyright header)
   regardless of filename, matches compatible kernel+firmware
   to connected drive, then flashes automatically.
   ========================================================= */
static int cmd_autoflash(void)
{
    /* .153 header offsets */
    #define H153_HW      0xB4
    #define H153_TYPE    0x110
    #define H153_VER     0xA0
    #define H153_MODEL   0x60
    #define H153_SIZE    0x200

    WIN32_FIND_DATAA fd;
    HANDLE           hf;
    char             fw_dir[MAX_PATH];
    char             pattern[MAX_PATH];
    char             exe_path[MAX_PATH];
    char            *last_sep;
    FW153            candidates[64];
    int              n_cand = 0;
    char             drive_hw[16]  = {0};
    char             drive_ver[8]  = {0};
    int              st = 0;
    UCHAR            sense[SENSE_SIZE];

    printf("=== AUTO FLASH ===\n\n");

    /* Find firmware folder next to exe */
    GetModuleFileNameA(NULL, exe_path, MAX_PATH);
    last_sep = strrchr(exe_path, '\\');
    if (last_sep) { *last_sep = 0; snprintf(fw_dir, MAX_PATH, "%s\\firmware", exe_path); }
    else           strcpy(fw_dir, "firmware");

    printf("  Scanning: %s\\\n\n", fw_dir);

    /* Read drive platform from 0xF1 */
    {
        UCHAR f1[0x30];
        UCHAR cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
        int   j;
        memset(f1, 0, sizeof(f1));
        send_scsi(g_hDrive, cdb, 10, f1, 0x30,
                  SCSI_IOCTL_DATA_IN, sense, &st);
        if (st == 0) {
            /* Platform string at +0x10 e.g. "SAT 8801ID60" - only
               copy printable bytes, same as the proven-working
               extraction used elsewhere in this file. A raw
               strncpy here will happily copy non-printable/garbage
               bytes if the offset assumption is even slightly off,
               which then feeds directly into the compatibility
               match below. */
            for (j=0; j<8 && f1[0x10+j]>=0x20 && f1[0x10+j]<0x7F; j++)
                drive_hw[j] = (char)f1[0x10+j];
            drive_hw[j] = 0;
        }
        /* Firmware version always comes from INQUIRY - it's more
           reliable than any offset guess into 0xF1, and is what
           the rest of the tool (cmd_inquiry, print_drive_info) uses. */
        {
            UCHAR inq[64];
            UCHAR icdb[6] = {0x12,0,0,0,0x40,0};
            int   ist;
            send_scsi(g_hDrive, icdb, 6, inq, 64,
                      SCSI_IOCTL_DATA_IN, sense, &ist);
            if (ist == 0) { strncpy(drive_ver, (char*)inq+32, 4); drive_ver[4]=0; }
        }
    }

    printf("  Drive platform : %.8s\n", drive_hw);
    printf("  Drive firmware : %.4s\n\n", drive_ver);

    /* Scan firmware folder - all files, detect by content */
    snprintf(pattern, MAX_PATH, "%s\\*.*", fw_dir);
    hf = FindFirstFileA(pattern, &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        printf("  No files found in firmware\\ folder.\n");
        printf("  Download Pioneer firmware files and place in:\n");
        printf("    %s\\\n", fw_dir);
        return 1;
    }

    do {
        FILE *fp;
        char  full_path[MAX_PATH];
        UCHAR hdr[H153_SIZE];
        char  hw[16]    = {0};
        char  ver[8]    = {0};
        char  type[12]  = {0};
        char  model[32] = {0};
        int   is_kernel = -1;
        long  fsz;

        /* Skip directories and files too small for a .153 header */
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.nFileSizeLow < H153_SIZE + 16) continue;

        snprintf(full_path, MAX_PATH, "%s\\%s", fw_dir, fd.cFileName);
        fp = fopen(full_path, "rb");
        if (!fp) continue;

        fseek(fp, 0, SEEK_END); fsz = ftell(fp); fseek(fp, 0, SEEK_SET);
        if (fsz < H153_SIZE) { fclose(fp); continue; }

        fread(hdr, 1, H153_SIZE, fp);
        fclose(fp);

        /* Check Pioneer copyright magic */
        if (memcmp(hdr, "********", 8) != 0) continue;

        /* Parse fields - fixed offsets, verified against real Pioneer
           .1xx/.153 microcode headers (identical layout across every
           sample file checked: BD-RW 211M, S12U, XD06U).
             0x68 (104) : model string, e.g. "BD-RW   BDR-211M"
             0x90 (144) : revision,      e.g. "1.53"
             0xB0 (176) : hardware/platform, e.g. "SAT 8800"
             0x110(272) : file type,     "Kernel" or "Normal"
           Each field is a printable ASCII run terminated by a NUL,
           so bound the copy on both length and printable range. */
        {
            int j;
            for (j=0; j<8 && hdr[0xB0+j]>=0x20 && hdr[0xB0+j]<0x7F; j++) hw[j]  = hdr[0xB0+j];
            hw[j] = 0;

            for (j=0; j<7 && hdr[0x90+j]>=0x20 && hdr[0x90+j]<0x7F; j++) ver[j] = hdr[0x90+j];
            ver[j] = 0;
            /* Save firmware version for trigger key lookup */
            if (!g_fw_version[0]) strncpy(g_fw_version, ver, 7);

            for (j=0; j<11 && hdr[0x110+j]>=0x20 && hdr[0x110+j]<0x7F; j++) type[j] = hdr[0x110+j];
            type[j] = 0;
            if      (strncmp(type,"Kernel",6)==0) is_kernel=1;
            else if (strncmp(type,"Normal",6)==0) is_kernel=0;

            for (j=0; j<31 && hdr[0x68+j]>=0x20 && hdr[0x68+j]<0x7F; j++) model[j] = hdr[0x68+j];
            model[j] = 0;
        }

        if (is_kernel < 0) continue;  /* not a valid .153 */

        printf("  Found: %-30s  HW=%-8s  FW=%-5s  %-20s  %s\n",
               fd.cFileName, hw, ver,
               model[0] ? model : "?",
               is_kernel ? "Kernel" : "Normal");

        if (n_cand < 64) {
            strncpy(candidates[n_cand].path,   full_path, MAX_PATH-1);
            strncpy(candidates[n_cand].hw,     hw,  15);
            strncpy(candidates[n_cand].ver,     ver, 7);
            strncpy(candidates[n_cand].model,   model, 31);
            candidates[n_cand].is_kernel  = is_kernel;
            candidates[n_cand].filesize   = fsz;
            n_cand++;
        }

    } while (FindNextFileA(hf, &fd));
    FindClose(hf);

    if (n_cand == 0) {
        printf("\n  No valid .153 firmware files found.\n");
        return 1;
    }

    /* Match: find compatible Normal + Kernel pair for this drive */
    {
        int  ki = -1, fi = -1;  /* kernel index, firmware index */
        int  i;
        char best_ver[8] = {0};

        printf("\n  Matching to drive (HW: %.8s)...\n\n", drive_hw);

        if (drive_hw[0] == 0) {
            printf("  ERROR: Could not read this drive's hardware/platform ID.\n");
            printf("  Refusing to guess a firmware match - flashing the wrong\n");
            printf("  family can brick the drive. Use 'drivekit driveinfo' or\n");
            printf("  check the drive-info banner for the Platform string, then\n");
            printf("  pick a firmware file manually with 'flashfw' instead.\n");
            return 1;
        }

        /* Find best matching Normal firmware */
        for (i = 0; i < n_cand; i++) {
            if (candidates[i].is_kernel) continue;
            if (candidates[i].hw[0] == 0) continue;
            /* Platform must match: first 3 chars of HW e.g. "SAT" */
            if (strncmp(candidates[i].hw, drive_hw, 3) != 0) continue;
            /* HW ID must match: chars 4-7 e.g. "8800" */
            if (strncmp(candidates[i].hw+4, drive_hw+4, 4) != 0) continue;
            /* Model string should match: e.g. "BDR-211M" or "BDR-S11"
               This prevents picking S8800431 (BDR-S11) when you have a BDR-211M */
            /* Extract short model from drive (e.g. "BDR-211M" from INQUIRY)
               and compare against firmware's model field */
            if (candidates[i].model[0] != 0) {
                /* If firmware has a model string, it should contain
                   the same BDR/DVR prefix as the drive reports */
                const char *fw_model = candidates[i].model;
                const char *drive_model_str = NULL;
                /* Look for "BDR-" or "DVR-" in the firmware model */
                if (strstr(fw_model, "BDR-") || strstr(fw_model, "DVR-")) {
                    /* Try to match model prefixes if possible, but don't
                       fail completely if drive model is missing - just prefer
                       exact matches */
                } else {
                    /* Model string is present but doesn't look like a drive model */
                    continue;
                }
            }
            /* Prefer newest version */
            if (best_ver[0] == 0 ||
                strcmp(candidates[i].ver, best_ver) > 0) {
                fi = i;
                strncpy(best_ver, candidates[i].ver, 7);
            }
        }

        /* Find the Kernel file that matches BOTH the drive's HW family
           AND the exact same HW+model as the chosen Normal firmware */
        if (fi >= 0) {
            for (i = 0; i < n_cand; i++) {
                if (!candidates[i].is_kernel) continue;
                if (candidates[i].hw[0] == 0) continue;
                if (strncmp(candidates[i].hw, drive_hw, 3) != 0) continue;
                if (strncmp(candidates[i].hw+4, drive_hw+4, 4) != 0) continue;
                /* Must match the selected Normal firmware's exact HW string */
                if (strncmp(candidates[i].hw, candidates[fi].hw, 8) != 0) continue;
                /* Also match model string to ensure we don't pair S8800430
                   (Kernel for BDR-S11) with S8800601 (Normal for BDR-211M) */
                if (candidates[i].model[0] != 0 && candidates[fi].model[0] != 0) {
                    if (strncmp(candidates[i].model, candidates[fi].model, 16) != 0)
                        continue;
                }
                ki = i;
                break;
            }
        }

        if (fi < 0) {
            printf("  No compatible Normal firmware found for this drive.\n");
            printf("  Drive HW: %.8s\n", drive_hw);
            printf("  Available HW types in firmware folder:\n");
            for (i = 0; i < n_cand; i++)
                if (!candidates[i].is_kernel)
                    printf("    %.8s  %s\n", candidates[i].hw, candidates[i].ver);
            return 1;
        }

        printf("  Selected firmware:\n");
        if (candidates[fi].model[0] != 0)
            printf("    Model   : %s\n", candidates[fi].model);
        if (ki >= 0)
            printf("    Kernel  : %s  (v%s)\n",
                   strrchr(candidates[ki].path,'\\')+1,
                   candidates[ki].ver);
        printf("    Normal  : %s  (v%s)\n",
               strrchr(candidates[fi].path,'\\')+1,
               candidates[fi].ver);

        /* Check if same version already installed */
        if (strncmp(candidates[fi].ver, drive_ver, 4) == 0 && !g_force) {
            printf("\n  Drive already has firmware v%s.\n", drive_ver);
            printf("  Use --force to flash anyway.\n");
            return 0;
        }

        printf("\n  Ready to flash v%s -> v%s\n",
               drive_ver[0] ? drive_ver : "?",
               candidates[fi].ver);
        printf("  Eject disc if inserted, then press ENTER to continue (Ctrl+C to abort)...\n");
        getchar();

        /* Set up file paths for flashfw */
        strncpy(g_outFile,  ki>=0 ? candidates[ki].path : candidates[fi].path, MAX_PATH-1);
        strncpy(g_outFile2, candidates[fi].path, MAX_PATH-1);

        printf("\n");
        return cmd_flashfw();
    }

    #undef H153_SIZE
    #undef H153_HW
    #undef H153_TYPE
    #undef H153_VER
    #undef H153_MODEL
}


static int cmd_flashfw(void)
{
    UCHAR  sense[SENSE_SIZE];
    int    st = 0;
    FILE  *fp;
    UCHAR *data;
    long   filesize;
    DWORD  kernel_offset = 0; /* send full file including header */
    DWORD  kernel_size;
    DWORD  offset;
    char   fname[256];
    /* Target firmware (--file2) header info — parsed early so the pre-pass
       logic knows whether this is a cross-era flash before sending the kernel. */
    char   fw2_ver[8]    = {0}; /* version string e.g. "1.05" */
    int    fw2_postcut   = 0;   /* 1 if Generated Date >= 22/12/27 */
    UCHAR *fw_prepass    = NULL; /* pre-loaded normal FW for cross-era pre-pass */
    long   fw_prepass_sz = 0;   /* size after any truncation */
    /* two_pass_needed: set after era detection; covers both:
       - pre-cutoff drive  → post-cutoff FW  (upgrade)
       - post-cutoff drive → pre-cutoff FW   (downgrade, --patch) */
    int    two_pass_needed = 0;
    WORD   fw_kernel_id    = 0; /* platform ID parsed from kernel file header (e.g. 0x8D31) */

    /* Helper macro: handle drive busy between chunks
       GET EVENT STATUS → REQUEST SENSE → retry
       Defined here so all code paths in cmd_flashfw can use it. */
    #define HANDLE_BUSY() do { \
        UCHAR _es[8], _s2[SENSE_SIZE]; int _st2=0; \
        UCHAR _escdb[10]={0x4A,0x01,0,0,0x5A,0,0,0,0x08,0}; \
        send_scsi(g_hDrive,_escdb,10,_es,8,SCSI_IOCTL_DATA_IN,_s2,&_st2); \
        UCHAR _rscdb[6]={0x03,0,0,0,0x12,0}; UCHAR _rb[18]; \
        send_scsi(g_hDrive,_rscdb,6,_rb,18,SCSI_IOCTL_DATA_IN,_s2,&_st2); \
        Sleep(100); \
    } while(0)

    if (!g_outFile[0] && !g_outFile2[0]) {
        fprintf(stderr, "Usage: drivekit flashfw G --file kernel.bin [--file2 normal.bin]\n");
        fprintf(stderr, "       drivekit flashfw G --file2 normal.bin  (normal firmware only)\n");
        return 1;
    }
    strncpy(fname, g_outFile, sizeof(fname)-1);

    /* Check no disc before doing anything else */
    printf("=== FLASH FIRMWARE ===\n\n");

    /* Ask user to dump firmware before flashing */
    {
        int do_dump = 0;
        if (!g_force) {
            printf("  Do you want to dump current firmware before flashing? [Y/n]: ");
            fflush(stdout);
            char ans[8] = {0};
            fgets(ans, sizeof(ans), stdin);
            if (ans[0] != 'n' && ans[0] != 'N') do_dump = 1;
        }

        if (do_dump) {
            UCHAR  f1[0x30];
            UCHAR  f1sense[SENSE_SIZE];
            char   dumpname[64] = {0};
            char   platform[16] = {0};
            char   fwver[8]     = {0};
            UCHAR  inq[96];
            UCHAR  inqcdb[6] = {0x12,0,0,0,96,0};
            UCHAR  inqsense[SENSE_SIZE];
            int    inqst = 0;

            memset(f1, 0, sizeof(f1));
            memset(inq, 0, sizeof(inq));

            if (rb_data(0xF1, 0, f1, 0x30, f1sense) == 0) {
                int i, j=0;
                for (i=0x10; i<0x18 && f1[i]; i++)
                    if (f1[i] != ' ') platform[j++] = f1[i];
            }
            send_scsi(g_hDrive, inqcdb, 6, inq, 96,
                      SCSI_IOCTL_DATA_IN, inqsense, &inqst);
            if (inqst == 0) {
                int i, j=0;
                for (i=32; i<36 && inq[i]; i++)
                    if (inq[i] != ' ') fwver[j++] = inq[i];
            }

            if (platform[0] && fwver[0])
                snprintf(dumpname, sizeof(dumpname),
                         "backup_%s_%s.bin", platform, fwver);
            else
                snprintf(dumpname, sizeof(dumpname), "backup_predump.bin");

            printf("  Dumping current firmware to %s...\n", dumpname);
            {
                FILE *fp = fopen(dumpname, "wb");
                if (fp) {
                    DWORD  cap = 0;
                    UCHAR  chunk[0x100];
                    DWORD  off;
                    rb_descriptor(0xF4, &cap);
                    printf("  Dumping 0xF4 (%lu bytes)...\n", cap);
                    for (off = 0; off < cap; off += sizeof(chunk)) {
                        UCHAR  sense2[SENSE_SIZE];
                        DWORD  rlen = cap - off;
                        if (rlen > sizeof(chunk)) rlen = sizeof(chunk);
                        memset(chunk, 0, sizeof(chunk));
                        rb_data(0xF4, off, chunk, rlen, sense2);
                        fwrite(chunk, 1, rlen, fp);
                    }
                    fclose(fp);
                    printf("  Backup saved: %s\n\n", dumpname);
                } else {
                    printf("  WARNING: Could not create backup file!\n\n");
                }
            }
        }
    }

    /* Confirm before flashing */
    if (!g_force) {
        char ans[8] = {0};
        printf("  Do you want to proceed with flashing? [y/N]: ");
        fflush(stdout);
        fgets(ans, sizeof(ans), stdin);
        if (ans[0] != 'y' && ans[0] != 'Y') {
            printf("  Flashing aborted by user.\n");
            return 0;
        }
        printf("\n");
    }
    {
        UCHAR cdb[10] = {0x46,0x00,0,0,0,0,0,0x01,0x00,0};
        UCHAR buf[256];
        UCHAR sense2[SENSE_SIZE];
        int   st2 = 0;
        WORD  profile;
        printf("  Checking no disc...\n");
        memset(buf, 0, sizeof(buf));
        send_scsi(g_hDrive, cdb, 10, buf, 256,
                  SCSI_IOCTL_DATA_IN, sense2, &st2);
        profile = ((WORD)buf[6]<<8)|buf[7];
        if (profile != 0x0000) {
            printf("  WARNING: Disc detected (profile=0x%04X).\n", profile);
            printf("  Eject disc before flashing. Unlock will fail with disc.\n");
            if (!g_force) { return 1; }
            printf("  --force specified, continuing anyway.\n\n");
        } else {
            printf("  No disc - OK\n\n");
        }
    }

    /* Probe READ BUFFER 0xB0 to detect pre-cutoff drive.
       Pre-cutoff: 0xB0 readable → g_pre_cutoff = 1
       Post-cutoff: 0xB0 returns sense 05/24/00 → g_pre_cutoff stays 0
       This flag controls tkey selection at the commit trigger step. */
    if (!g_pre_cutoff) {
        UCHAR b0buf[4] = {0};
        UCHAR b0sense[SENSE_SIZE] = {0};
        int   b0st = rb_data(0xB0, 0, b0buf, 4, b0sense);
        if (b0st == 0 || (b0sense[2] & 0x0F) == 0) {
            g_pre_cutoff = 1;
            printf("  Drive era: PRE-CUTOFF (0xB0 readable)\n");
        } else {
            printf("  Drive era: POST-CUTOFF (0xB0 not readable)\n");
            if (g_fakedate) {
                g_pre_cutoff = 1;
                printf("  --fakedate: forcing pre-cutoff mode for two-pass protocol\n");
            }
        }
    }

    /* Early-load normal FW (--file2) to detect cross-era and build pre-pass.
       For pre-cutoff drive → post-cutoff FW, BDRFlash protocol requires:
         [2a] normal FW pass 1  (0x000000 .. fwsize-0x10000)  bufID=0xF0
         [2b] kernel            (bufID=0xFE)
         [2c] normal FW pass 2  (0x000000 .. fwsize full)     bufID=0xF0
       The commit key is the SAME unlock key — no tkey substitution needed.
       Confirmed from USBPcap of BDRFlash (Generated Date: 24/10/09 firmware). */
    if (g_outFile2[0]) {
        FILE *fp_pre;
        long  fp_pre_sz;
        fp_pre = fopen(g_outFile2, "rb");
        if (!fp_pre) { fprintf(stderr, "Cannot open %s\n", g_outFile2); return 1; }
        fseek(fp_pre, 0, SEEK_END);
        fp_pre_sz = ftell(fp_pre);
        fseek(fp_pre, 0, SEEK_SET);
        fw_prepass = (UCHAR*)malloc(fp_pre_sz);
        if (!fw_prepass) { fclose(fp_pre); return 1; }
        fread(fw_prepass, 1, fp_pre_sz, fp_pre);
        fclose(fp_pre);

        /* --fakedate: patch Generated Date to 22/12/27 before era detection */
        if (g_fakedate) {
            if (patch_generated_date(fw_prepass, (DWORD)fp_pre_sz, "22/12/27"))
                printf("  --fakedate: patched normal FW Generated Date → 22/12/27\n");
            else
                printf("  --fakedate: WARNING: Generated Date not found in normal FW header\n");
        }

        /* Parse version + date from header */
        {
            int k;
            DWORD scan = (fp_pre_sz < 0x300) ? (DWORD)fp_pre_sz : 0x300;
            if ((DWORD)fp_pre_sz > 0x90 + 8) {
                for (k = 0; k < 7 && fw_prepass[0x90+k] >= 0x20 && fw_prepass[0x90+k] < 0x7F; k++)
                    fw2_ver[k] = (char)fw_prepass[0x90+k];
                fw2_ver[k] = 0;
            }
            UCHAR *gd = (UCHAR*)memmem_win(fw_prepass, scan, "Generated Date", 14);
            if (gd) {
                UCHAR *col = (UCHAR*)memchr(gd, ':', 32);
                if (col) {
                    char fw_date[12] = {0};
                    col += 2;
                    for (k = 0; k < 10 && col[k] >= 0x20 && col[k] != 0x0D; k++)
                        fw_date[k] = col[k];
                    for (k = 9; k >= 0 && fw_date[k] == ' '; k--) fw_date[k] = 0;
                    fw2_postcut = (strcmp(fw_date, "22/12/27") >= 0);
                    printf("  Target FW: version=%s  Date=%s → %s\n",
                           fw2_ver[0] ? fw2_ver : "?",
                           fw_date,
                           fw2_postcut ? "POST-CUTOFF" : "PRE-CUTOFF");
                }
            }
        }

        /* Apply pre-cutoff NAND boundary truncation */
        fw_prepass_sz = fp_pre_sz;
        if (fw_prepass_sz > 0x1E0000) {
            printf("  Pre-cutoff: FW truncated to 0x1E0000 (NAND boundary)\n");
            fw_prepass_sz = 0x1E0000;
        }
    }

    /* Determine if two-pass protocol is needed:
       - pre-cutoff drive  + post-cutoff target FW  (upgrade)
       - post-cutoff drive + --patch downgrade: target file has post-cutoff date
         (the patch changes the generation marker, not the date field) */
    two_pass_needed = (g_pre_cutoff && fw2_postcut);
    /* post→pre downgrade (--patch) does NOT need two-pass — confirmed by working
       third-party flasher that sends only kernel + normal in a single pass. */
    if (two_pass_needed)
        printf("  Two-pass protocol: ENABLED (%s)\n\n",
               g_pre_cutoff ? "pre→post upgrade" : "post→pre downgrade");

    /* Cross-era pre-pass moved to AFTER unlock — see below. */
    if (0 && two_pass_needed && g_outFile[0] && fw_prepass) {
        DWORD pass1_sz = (fw_prepass_sz > 0x10000) ? (DWORD)(fw_prepass_sz - 0x10000) : (DWORD)fw_prepass_sz;
        DWORD fw_off   = 0;
        UCHAR cdb[10];
        printf("[2a/3] Cross-era pre-pass: normal FW pass 1 (0x%lX bytes)...\n", pass1_sz);
        while (fw_off < pass1_sz) {
            DWORD n = pass1_sz - fw_off;
            if (n > 0x8000) n = 0x8000;
            memset(cdb, 0, sizeof(cdb));
            cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xF0;
            cdb[3]=(UCHAR)(fw_off>>16);
            cdb[4]=(UCHAR)(fw_off>>8);
            cdb[5]=(UCHAR)(fw_off);
            cdb[6]=(UCHAR)(n>>16);
            cdb[7]=(UCHAR)(n>>8);
            cdb[8]=(UCHAR)(n);
            send_scsi(g_hDrive, cdb, 10, fw_prepass + fw_off, n,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st != 0) {
                HANDLE_BUSY();
                send_scsi(g_hDrive, cdb, 10, fw_prepass + fw_off, n,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    printf("\n  FAILED at 0x%lX: key=%02X ASC=%02X\n",
                           fw_off, sense[2]&0x0F, sense[12]);
                    free(fw_prepass); return 1;
                }
            }
            fw_off += n;
            printf("\r  %lu / %lu bytes", fw_off, pass1_sz);
            fflush(stdout);
            Sleep(50);
        }
        printf("\n  Done. (pass 2 of normal FW will follow after kernel)\n\n");
        HANDLE_BUSY();
    }

    if (g_outFile[0]) { /* kernel flash - skip if --file2 only */
    printf("  File : %s\n", fname);

    fp = fopen(fname, "rb");
    if (!fp) { fprintf(stderr, "Cannot open %s\n", fname); return 1; }
    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = (UCHAR*)malloc(filesize);
    if (!data) { fclose(fp); return 1; }
    fread(data, 1, filesize, fp);
    fclose(fp);

    kernel_size = (DWORD)filesize;
    printf("  Size : 0x%lX bytes (full file including header)\n", kernel_size);

    /* --fakedate: patch kernel Generated Date in-memory */
    if (g_fakedate) {
        if (patch_generated_date(data, kernel_size, "22/12/27"))
            printf("  --fakedate: patched kernel Generated Date → 22/12/27\n");
        else
            printf("  --fakedate: WARNING: Generated Date not found in kernel header\n");
    }

    /* --patch: KernelFront generation marker patch (same logic as cmd_crossflash).
       Detects KernelFront envelope, decrypts payload, patches 0xFF->0x01,
       recomputes checksum, re-encrypts back into data[]. */
    if (g_patch_flag && kernel_size >= 0x11200) {
        int kf_ok = 0;
        DWORD pi; int printable = 1;
        for (pi = 0; pi < 0x100; pi++) {
            UCHAR c = data[pi];
            if (c == 0x00 || c == 0x0D || c == 0x0A) continue;
            if (c < 0x20 || c > 0x7E) { printable = 0; break; }
        }
        if (printable) {
            DWORD k0 = (DWORD)data[0x200] | ((DWORD)data[0x201]<<8) |
                       ((DWORD)data[0x202]<<16) | ((DWORD)data[0x203]<<24);
            DWORD c0 = (DWORD)data[0x1200] | ((DWORD)data[0x1201]<<8) |
                       ((DWORD)data[0x1202]<<16) | ((DWORD)data[0x1203]<<24);
            DWORD p0 = ror32(c0 ^ k0, (int)(k0 & 31));
            if ((p0 >> 24) <= 0x7F) kf_ok = 1;
        }
        if (kf_ok) {
            printf("  KernelFront: detected — decrypting + patching generation marker...\n");
            UCHAR *plain = (UCHAR*)malloc(0x10000);
            if (plain) {
                kf_decrypt_body(data + 0x200, data + 0x1200, plain);
                UCHAR marker = plain[0xFE];
                if (marker == 0xFF || marker == 0x00) {
                    plain[0xFE] = 0x01;
                    printf("  KernelFront: generation marker patched 0x%02X -> 0x01\n", marker);
                    /* Checksum at body offset 0x1020 is BIG-ENDIAN.
                       marker_delta = (0x01 - old_marker) * 0x100  (wrapping u32)
                       compensation = -(marker_delta)               (wrapping u32)
                       new_word = old_word + compensation
                       For marker=0xFF: delta=(0x01-0xFF)*0x100 = (-0xFE)*0x100 = 0xFFFF0200 (wrapping)
                                        compensation = -0xFFFF0200 = 0x0000FE00
                       So checksum increases by 0x0000FE00. */
                    {
                        DWORD marker_delta = ((DWORD)0x01 - (DWORD)marker) * (DWORD)0x100;
                        DWORD compensation = (DWORD)(-(int)marker_delta);
                        DWORD old_cs = ((DWORD)plain[0x1020] << 24) |
                                       ((DWORD)plain[0x1021] << 16) |
                                       ((DWORD)plain[0x1022] <<  8) |
                                        (DWORD)plain[0x1023];
                        DWORD new_cs = old_cs + compensation;
                        plain[0x1020] = (UCHAR)(new_cs >> 24);
                        plain[0x1021] = (UCHAR)(new_cs >> 16);
                        plain[0x1022] = (UCHAR)(new_cs >>  8);
                        plain[0x1023] = (UCHAR)(new_cs      );
                        printf("  KernelFront: checksum 0x%08lX -> 0x%08lX (BE, compensation=0x%08lX)\n",
                               old_cs, new_cs, compensation);
                    }
                } else if (marker == 0x01) {
                    printf("  KernelFront: generation marker already 0x01 — no patch needed\n");
                } else {
                    printf("  KernelFront: unknown marker 0x%02X — skipping patch\n", marker);
                }
                /* Re-encrypt back into data[] */
                kf_decrypt_body(data + 0x200, plain, data + 0x1200);
                printf("  KernelFront: re-encrypted OK\n");
                free(plain);
            }
        } else {
            printf("  KernelFront: not detected (header not ASCII or decrypt check failed)\n");
        }
    }

    {
        /* Extract hardware version from header for display (e.g. "SAT 8D31", "SAT 8801") */
        UCHAR *hw_line = memmem_win(data, 0x200, "Hardware Version", 16);
        char hw_str[16] = {0};
        if (hw_line) {
            UCHAR *col = (UCHAR*)memchr(hw_line, ':', 32);
            if (col) {
                col += 2;
                int k;
                for (k = 0; k < 15 && col[k] >= 0x20 && col[k] != 0x0D; k++)
                    hw_str[k] = col[k];
                /* Trim trailing spaces */
                for (k = 14; k >= 0 && hw_str[k] == ' '; k--)
                    hw_str[k] = 0;
            }
        }
        if (hw_str[0])
            printf("  HW   : %s confirmed\n", hw_str);
        else
            printf("  WARN : Hardware Version not found in header\n");
    }
    if (memmem_win(data, 0x200, "Kernel", 6))
        printf("  Type : Kernel confirmed\n");

    /* -------------------------------------------------------
       Compatibility check (port of sub_4136A7 + sub_405E71)
       BDRFlash originally compares kernel struct vs firmware
       struct (both parsed from .153 files). We compare the
       drive's current platform (from 0xF1) against the kernel
       file's hardware version field in the .153 header.
       Drive ID groups from sub_4136A7 call sites determine
       which models can be crossflashed with each other.
       Platform pairs: SAT<->STE and ATA<->TEA are allowed.
       ------------------------------------------------------- */
    if (!g_skip_checks) {
    {
        /* Compatibility groups from sub_4136A7 */
        static const WORD groups[][5] = {
            /* DVR-era pairs (from sub_4136A7 0x413890 area) */
            { 0x0010, 0x0011, 0,      0,      0      },
            { 0x0050, 0x0051, 0,      0,      0      },
            { 0x0052, 0x0053, 0,      0,      0      },
            { 0x0054, 0x0055, 0,      0,      0      },
            { 0x0056, 0x0057, 0,      0,      0      },
            { 0x0058, 0x0059, 0,      0,      0      },
            { 0x0060, 0x0061, 0,      0,      0      },
            { 0x0062, 0x0063, 0,      0,      0      },
            { 0x0064, 0x0065, 0,      0,      0      },
            { 0x0066, 0x0067, 0,      0,      0      },
            { 0x0068, 0x0069, 0,      0,      0      },
            { 0x0070, 0x0071, 0,      0,      0      },
            { 0x0072, 0x0073, 0,      0,      0      },
            { 0x0074, 0x0075, 0,      0,      0      },
            { 0x0076, 0x0077, 0,      0,      0      },
            { 0x0078, 0x0079, 0,      0,      0      },
            /* BDR-era groups */
            { 0x8231, 0x8232, 0x8B30, 0,      0      },
            { 0x8301, 0x8600, 0x8800, 0,      0      },
            { 0x8410, 0x8510, 0x8511, 0x8A10, 0      },
            { 0x8490, 0x8590, 0x8591, 0,      0      },
            { 0x8601, 0x8801, 0,      0,      0      },
            { 0x8721, 0x8722, 0,      0,      0      },
            { 0x8000, 0x8800, 0,      0,      0      },
            { 0x8D30, 0x8D31, 0,      0,      0      },
            { 0x8E20, 0x8E21, 0,      0,      0      },
            { 0x8F00, 0x8F01, 0,      0,      0      },
            { 0x9000, 0x9001, 0,      0,      0      },
            { 0x9200, 0x9201, 0,      0,      0      },
            { 0x9330, 0x9331, 0,      0,      0      },
            { 0x9400, 0x9401, 0,      0,      0      },
            { 0x9620, 0x9621, 0,      0,      0      },  /* BDR-XS08U */
            { 0, 0, 0, 0, 0 }
        };

        /* Platform pairs that are cross-flashable (sub_4136A7) */
        /* SAT<->STE and ATA<->TEA are allowed */

        /* Get drive ID from 0xF1 */
        UCHAR rb[0x30];
        UCHAR f1cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
        UCHAR sense2[SENSE_SIZE];
        int   st2 = 0;
        WORD  driveID = 0;
        char  driveHW[16] = {0};
        char  fileHW[12]  = {0};
        int   i, j;

        memset(rb, 0, sizeof(rb));
        send_scsi(g_hDrive, f1cdb, 10, rb, 0x30,
                  SCSI_IOCTL_DATA_IN, sense2, &st2);

        if (st2 == 0) {
            /* Drive ID from platform string e.g. "SAT 8D31", "SAT 8801" */
            char platform[16] = {0};
            /* Copy only printable characters from 0xF1 offset 0x10,
               same technique as print_drive_info to ensure proper
               null-termination and exclude garbage bytes */
            {
                int k;
                for (k=0; k<12 && rb[0x10+k]>=0x20 && rb[0x10+k]<0x7F; k++)
                    platform[k] = rb[0x10+k];
                platform[k] = 0;  /* explicit null terminator */
            }
            memcpy(driveHW, platform, sizeof(driveHW)-1); /* driveHW[16], copies up to 15 chars */
            {
                /* Find 4 consecutive hex digits */
                const char *p = platform;
                while (*p) {
                    if (((p[0]>='0'&&p[0]<='9')||(p[0]>='A'&&p[0]<='F')) &&
                        ((p[1]>='0'&&p[1]<='9')||(p[1]>='A'&&p[1]<='F')) &&
                        ((p[2]>='0'&&p[2]<='9')||(p[2]>='A'&&p[2]<='F')) &&
                        ((p[3]>='0'&&p[3]<='9')||(p[3]>='A'&&p[3]<='F'))) {
                        char tmp[5]={0};
                        memcpy(tmp,p,4);
                        driveID = (WORD)strtol(tmp, NULL, 16);
                        break;
                    }
                    p++;
                }
            }
            printf("  Drive    : ID=0x%04X  HW=%s\n", driveID,
                   driveHW);
            
            /* Validate: if driveID is still 0, the platform string
               didn't contain a valid hex number, which is bad. This
               would cause pioneer_key() to return the default ASUS
               key instead of the correct one. */
            if (driveID == 0) {
                /* Could not extract ID - warn but continue using platform string */
                printf("  WARN: Could not extract drive ID from platform '%s'\n", platform);
                printf("  Will match by hardware version string instead.\n\n");
            }
        } else {
            printf("  WARN: Could not read 0xF1 for compatibility check\n");
            printf("  Refusing to proceed - need valid drive ID to select correct key.\n");
            free(data); return 1;
        }

        /* Get hardware version from .153 header at offset 0x27 */
        /* Header line: "Hardware Version : SAT 8801" */
        {
            UCHAR *hw = memmem_win(data, 0x200,
                                   "Hardware Version", 16);
            if (hw) {
                UCHAR *colon = (UCHAR*)memchr(hw, ':', 32);
                if (colon) {
                    colon += 2;
                    int k;
                    for (k = 0; k < 11 && colon[k] >= 0x20 &&
                         colon[k] != 0x0D; k++)
                        fileHW[k] = colon[k];
                    /* Trim trailing spaces */
                    for (k = 10; k >= 0 && fileHW[k] == ' '; k--)
                        fileHW[k] = 0;
                }
            }
            printf("  Firmware : HW=%s\n", fileHW[0]?fileHW:"unknown");
        }

        /* Parse firmware drive ID from fileHW e.g. "SAT 8801" */
        WORD fileID = 0;
        {
            const char *p = fileHW;
            while (*p && (*p < '0' || *p > '9')) p++;
            if (*p) fileID = (WORD)strtol(p, NULL, 16);
        }
        fw_kernel_id = fileID; /* save for commit trigger lookup */

        /* Check drive ID group compatibility */
        int group_ok = (driveID == fileID); /* exact match always OK */
        if (!group_ok && driveID && fileID) {
            for (i = 0; groups[i][0]; i++) {
                int drive_in = 0, file_in = 0;
                for (j = 0; j < 5 && groups[i][j]; j++) {
                    if (groups[i][j] == driveID) drive_in = 1;
                    if (groups[i][j] == fileID)  file_in  = 1;
                }
                if (drive_in && file_in) { group_ok = 1; break; }
            }
        }

        printf("  Platform : %s -> %s (crossflash allowed)\n",
               driveHW, fileHW);
        printf("  Drive ID : %s (0x%04X vs 0x%04X)\n",
               group_ok ? "compatible" :
               (driveID && fileID ? "*** DIFFERENT GROUP ***"
                                  : "unknown"),
               driveID, fileID);

        if (!group_ok && driveID && fileID) {
            printf("\n  WARN: Drive ID not in same compatibility group.\n");
            printf("  This is a cross-model flash (e.g. BDR-209 -> BDR-211).\n");
            if (!g_force) {
                printf("  Use --force to proceed anyway.\n");
                free(data); return 1;
            }
            printf("  --force specified, continuing cross-model flash.\n\n");
        }

        /* Note: sub_413097 in BDRFlash also verifies file size
           [esi+4Ch] vs actual — our file loaded cleanly so implicit */
        printf("\n");
    }
    } /* end !g_skip_checks */

    /* Build unlock payload from drive table model string */
    build_pioneer_payload_auto(g_payload);
    printf("  Payload  : %.16s + key\n\n", (char*)g_payload);

    /* Pre-read 0xF1 token BEFORE unlock — post-cutoff drives return
       00 00 5C 00 token in normal mode that's needed for trigger later!
       Must be done BEFORE 0xF1 triggers kernel mode! */
    {
        /* START STOP 0x20 — enables chunked transfer and session token */
        {
            UCHAR sscdb[6] = {0x1B,0x00,0x00,0x00,0x20,0x00};
            UCHAR sssense[SENSE_SIZE] = {0};
            int ssst = 0;
            send_scsi(g_hDrive, sscdb, 6, NULL, 0,
                      SCSI_IOCTL_DATA_UNSPECIFIED, sssense, &ssst);
            printf("  [DBG] START STOP 0x20: %s\n", ssst==0?"GOOD":"FAIL");
            Sleep(500);
        }

        /* Read 0xF1 before unlock */

        UCHAR f1sense[SENSE_SIZE] = {0};
        memset(g_f1token, 0, sizeof(g_f1token));
        rb_data(0xF1, 0, g_f1token, 0x30, f1sense);
        if (g_f1token[0] == 0x00 && g_f1token[1] == 0x00 && g_f1token[2] != 0x00) {
            g_has_f1token = 1;
            printf("  [DBG] 0xF1 token captured: %02X %02X %02X %02X\n",
                   g_f1token[0],g_f1token[1],g_f1token[2],g_f1token[3]);
        } else {
            printf("  [DBG] 0xF1 pre-read: %02X %02X %02X %02X (serial/normal)\n",
                   g_f1token[0],g_f1token[1],g_f1token[2],g_f1token[3]);
        }
    }

    /* Wait for drive ready */
    if (!g_skip_checks) {
        int attempt;
        int consecutive = 0;
        printf("[0a/3] Checking drive ready...\n");
        for (attempt = 0; attempt < 30; attempt++) {
            UCHAR cdb[6] = {0,0,0,0,0,0};
            UCHAR sense2[SENSE_SIZE];
            int   st2 = 0;
            send_scsi(g_hDrive, cdb, 6, NULL, 0,
                      SCSI_IOCTL_DATA_UNSPECIFIED, sense2, &st2);
            if (st2 == 0 || sense2[12] == 0x3A) {
                consecutive++;
                if (consecutive >= 3) {
                    printf("  READY\n\n");
                    Sleep(1000);
                    break;
                }
            } else {
                consecutive = 0;
                printf("\r  Waiting %d/30... skey=%02X ASC=%02X  ",
                       attempt+1, sense2[2]&0x0F, sense2[12]);
                fflush(stdout);
            }
            Sleep(1000);
            if (attempt == 29) {
                printf("\n  Drive not ready. Retry.\n");
                free(data); return 1;
            }
        }
    }

    if (g_nounlock) {
        printf("[1/3] Unlock skipped (--nounlock)\n\n");
    } else {
        printf("[1/3] Unlock (key 0x%08lX)...\n",
               ((DWORD)g_payload[0x13]<<24)|((DWORD)g_payload[0x12]<<16)|
               ((DWORD)g_payload[0x11]<<8)|(DWORD)g_payload[0x10]);
        printf("  Payload: ");
        { int pi; for(pi=0;pi<20;pi++) printf("%02X ",g_payload[pi]); printf("\n"); }
        printf("  String : \"%.16s\"\n\n", (char*)g_payload);
        {
            UCHAR wcdb[10] = {0x3B,0x04,0xFF,0,0,0,0,0x01,0,0};
            UCHAR es[8];
            UCHAR escdb[10]={0x4A,0x01,0,0,0x5A,0,0,0,0x08,0};
            send_scsi(g_hDrive, wcdb, 10, g_payload, PAYLOAD_SIZE,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st != 0) {
                /* Try post-cutoff mode=0x01 bufID=0x00 sweep
                   Skip for pre-cutoff drives — they don't need this unlock */
                if (g_pre_cutoff && !g_fakedate) {
                    printf("  Pre-cutoff drive — skipping post-cutoff mode sweep.\n");
                    printf("  Proceeding without unlock (0xB0 accessible).\n\n");
                    st = 0; /* treat as OK, proceed without unlock */
                    g_unlock_mode = 0x04; /* keep pre-cutoff mode */
                } else {
                UCHAR alt_modes[]  = {0x01, 0x00, 0x0A, 0x0B, 0x0C, 0x0D};
                UCHAR alt_bufids[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                int found = 0, mi;
                printf("  Standard unlock failed - trying post-cutoff mode sweep...\n");
                for (mi = 0; mi < 6; mi++) {
                    UCHAR acdb[10] = {0x3B,alt_modes[mi],alt_bufids[mi],
                                      0,0,0,0,0x00,0x20,0};
                    UCHAR asense[SENSE_SIZE];
                    int ast = 0;
                    send_scsi(g_hDrive, acdb, 10, g_payload, 0x20,
                              SCSI_IOCTL_DATA_OUT, asense, &ast);
                    if (ast == 0 || (asense[2]&0x0F) == 0x00) {
                        printf("  Post-cutoff unlock GOOD (mode=0x%02X bufID=0x%02X)\n",
                               alt_modes[mi], alt_bufids[mi]);
                        g_unlock_mode  = alt_modes[mi];
                        g_unlock_bufid = alt_bufids[mi];
                        st = 0;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    /* Try again with shorter payload (no key) */
                    UCHAR short_payload[0x20] = {0};
                    memcpy(short_payload, g_payload, 0x10); /* model string only */
                    printf("  Retrying with short payload (model string only)...\n");
                    for (mi = 0; mi < 6; mi++) {
                        UCHAR acdb[10] = {0x3B,alt_modes[mi],alt_bufids[mi],
                                          0,0,0,0,0x00,0x20,0};
                        UCHAR asense[SENSE_SIZE];
                        int ast = 0;
                        send_scsi(g_hDrive, acdb, 10, short_payload, 0x20,
                                  SCSI_IOCTL_DATA_OUT, asense, &ast);
                        if (ast == 0 || (asense[2]&0x0F) == 0x00) {
                            printf("  Post-cutoff unlock GOOD (mode=0x%02X short payload)\n",
                                   alt_modes[mi]);
                            g_unlock_mode  = alt_modes[mi];
                            g_unlock_bufid = alt_bufids[mi];
                            st = 0;
                            found = 1;
                            break;
                        }
                    }
                }
                if (!found) {
                    printf("  FAILED key=%02X ASC=%02X ASCQ=%02X\n",
                           sense[2]&0x0F, sense[12], sense[13]);
                    free(data); return 1;
                }
                } /* end else (!g_pre_cutoff) */
            } else {
                printf("  GOOD\n");
                /* Read 0xF1 after unlock to confirm service mode entry */
                {
                    UCHAR f1post[0x30] = {0};
                    UCHAR f1psense[SENSE_SIZE] = {0};
                    if (rb_data(0xF1, 0, f1post, 0x30, f1psense) == 0) {
                        printf("  [DBG] 0xF1 after unlock: %02X %02X %02X %02X (platform: %.12s)\n",
                               f1post[0], f1post[1], f1post[2], f1post[3],
                               (f1post[0x10] >= 0x20) ? (char*)&f1post[0x10] : "?");
                    } else {
                        printf("  [DBG] 0xF1 after unlock: FAIL key=%02X ASC=%02X\n",
                               f1psense[2]&0x0F, f1psense[12]);
                    }
                }
                printf("\n");
            }
            Sleep(500);
            memset(es, 0, sizeof(es));
            send_scsi(g_hDrive, escdb, 10, es, 8,
                      SCSI_IOCTL_DATA_IN, sense, &st);
        }
        Sleep(1000); /* ENTRY_SETTLE: 1 second after unlock per reference session.rs */
    }

    /* Inquiry(0x60) after unlock — present in reference session.rs CDB sequence
       but confirmed to BREAK the flash on Pioneer BDR-BDS7 (post-cutoff, SAT 8D30/8D31).
       Drive returns revision "0000" in service mode and the subsequent commit fails
       with 04/4C/02. Disabled — the drive does not need this to advance its state machine.
       Left here as documentation; do NOT re-enable without testing post→post first. */
    if (0) {
        UCHAR inq[96] = {0};
        UCHAR inqcdb[6] = {0x12, 0, 0, 0, 0x60, 0};
        UCHAR inqsense[SENSE_SIZE] = {0};
        int   inqst = 0;
        send_scsi(g_hDrive, inqcdb, 6, inq, 0x60,
                  SCSI_IOCTL_DATA_IN, inqsense, &inqst);
    }

    /* Cross-era pre-pass: normal FW pass 1, sent AFTER unlock.
       Required for both upgrade (pre→post) and downgrade (post→pre via --patch).
       Drive must be in service mode (unlocked) before accepting WRITE BUFFER 0xF0. */
    if (two_pass_needed && g_outFile[0] && fw_prepass) {
        /* Pass 1 sends the FULL firmware (matching cmd_crossflash xf_send_normal_fw).
           Earlier versions subtracted 0x10000 here — that was wrong and caused 04/4C/02. */
        DWORD pass1_sz = (DWORD)fw_prepass_sz;
        DWORD fw_off   = 0;
        UCHAR p1cdb[10];
        printf("[2a/3] Cross-era pre-pass: normal FW pass 1 (0x%lX bytes)...\n", pass1_sz);
        while (fw_off < pass1_sz) {
            DWORD n = pass1_sz - fw_off;
            if (n > 0x8000) n = 0x8000;
            memset(p1cdb, 0, sizeof(p1cdb));
            p1cdb[0]=0x3B; p1cdb[1]=0x07; p1cdb[2]=0xF0;
            p1cdb[3]=(UCHAR)(fw_off>>16);
            p1cdb[4]=(UCHAR)(fw_off>>8);
            p1cdb[5]=(UCHAR)(fw_off);
            p1cdb[6]=(UCHAR)(n>>16);
            p1cdb[7]=(UCHAR)(n>>8);
            p1cdb[8]=(UCHAR)(n);
            send_scsi(g_hDrive, p1cdb, 10, fw_prepass + fw_off, n,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st != 0) {
                HANDLE_BUSY();
                send_scsi(g_hDrive, p1cdb, 10, fw_prepass + fw_off, n,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    printf("\n  FAILED at 0x%lX: key=%02X ASC=%02X ASCQ=%02X\n",
                           fw_off, sense[2]&0x0F, sense[12], sense[13]);
                    free(data); free(fw_prepass); return 1;
                }
            }
            fw_off += n;
            printf("\r  %lu / %lu bytes", fw_off, pass1_sz);
            fflush(stdout);
            Sleep(50);
        }
        printf("\n  Done. (pass 2 of normal FW will follow after kernel)\n\n");
        HANDLE_BUSY();
    }

    /* Step 2: Send complete kernel .153 file (including 0x200 header)
       Wireshark confirmed: autoflasher sends full file from offset 0  */
    /* Read 0xF1 and 0xA0 before flashing - BDRFlash does this
       to put drive in correct state for firmware receive */
    {
        UCHAR  rb[0x30];
        UCHAR  a0[0x10];
        UCHAR  rbsense[SENSE_SIZE];
        int    rb_st = 0, a0_st = 0;
        
        if (g_unlock_mode == 0x01) {
            printf("  Pre-flash: skipping reads (post-cutoff service mode)\n\n");
        } else {
            printf("  Pre-flash: reading 0xF1...\n");
            rb_data(0xF1, 0, rb, 0x30, rbsense);
            if (rbsense[2] != 0) {
                printf("    WARNING: 0xF1 read returned sense key %02X ASC=%02X\n",
                       rbsense[2]&0x0F, rbsense[12]);
            }
            printf("  Pre-flash: reading 0xA0...\n");
            rb_data(0xA0, 0x90, a0, 0x10, rbsense);
            if (rbsense[2] != 0) {
                printf("    WARNING: 0xA0 read returned sense key %02X ASC=%02X\n",
                       rbsense[2]&0x0F, rbsense[12]);
            }
            Sleep(200);
        }
    }

    printf("[2/3] Sending kernel (0x8000 chunks, %ld bytes)...\n", filesize);
    {
        UCHAR cdb[10];
        offset = 0;

        /* Post-cutoff NEW protocol (from XD07 1.06 updater analysis):
           1. Generate 0x200 random bytes as session token
           2. Send token to bufID=0xFE offset=0x0000 len=0x200
           3. Send firmware to bufID=0xFE offset=0x1200
           4. Trigger uses same random token as payload! */
        if (g_unlock_mode == 0x01) {
            /* Step 1: Generate random session token */
            UCHAR token[0x200] = {0};
            srand((unsigned int)GetTickCount());
            DWORD ti;
            for (ti = 0; ti < 0x200; ti++)
                token[ti] = (UCHAR)(rand() & 0xFF);

            printf("  [DBG] Generated session token (first 8): %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   token[0],token[1],token[2],token[3],
                   token[4],token[5],token[6],token[7]);

            /* Step 2: Send token to bufID=0xFE offset=0x0000 len=0x200 */
            printf("  Sending session token (bufID=0xFE offset=0x0000 len=0x200)...\n");
            memset(cdb, 0, sizeof(cdb));
            cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xFE;
            cdb[6]=0x00; cdb[7]=0x02; cdb[8]=0x00; /* len=0x200 */
            send_scsi(g_hDrive, cdb, 10, token, 0x200,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            printf("  Token send: %s", (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
            if (st!=0) printf(" (key=%02X ASC=%02X)", sense[2]&0xF, sense[12]);
            printf("\n");

            /* Step 3: Send kernel to bufID=0xFE offset=0x1200 */
            printf("  Sending kernel (bufID=0xFE offset=0x1200 len=0x%lX)...\n", (DWORD)filesize);
            memset(cdb, 0, sizeof(cdb));
            cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xFE;
            cdb[3]=0x00; cdb[4]=0x12; cdb[5]=0x00; /* offset=0x1200 */
            cdb[6]=(UCHAR)(filesize>>16);
            cdb[7]=(UCHAR)(filesize>>8);
            cdb[8]=(UCHAR)(filesize);
            send_scsi(g_hDrive, cdb, 10, data, (DWORD)filesize,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st == 0 || (sense[2]&0x0F) == 0) {
                printf("  %ld / %ld bytes - OK\n", (DWORD)filesize, (DWORD)filesize);
                printf("  [DBG] Kernel sense: key=%02X ASC=%02X\n", sense[2]&0x0F, sense[12]);
                Sleep(500);
                offset = (DWORD)filesize;
                /* Save token for trigger */
                memcpy(g_f1token, token, 0x20);
                g_has_f1token = 1;
            } else {
                printf("  FAILED: key=%02X ASC=%02X\n", sense[2]&0x0F, sense[12]);
                free(data); return 1;
            }
        } else {
        /* Send kernel as single transfer (offset=0, full file).
           Post-cutoff drives reject explicit offsets > 0 for bufID=0xFE with 05/24/00 —
           the drive auto-advances its internal kernel buffer pointer. */
        {
            DWORD total = (DWORD)filesize;
            printf("  Sending as single transfer (bufID=0xFE offset=0 len=0x%lX)...\n", total);
            memset(cdb, 0, sizeof(cdb));
            cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xFE;
            cdb[6]=(UCHAR)(total>>16);
            cdb[7]=(UCHAR)(total>>8);
            cdb[8]=(UCHAR)(total);
            send_scsi(g_hDrive, cdb, 10, data, total,
                      SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st == 0 || (sense[2]&0x0F) == 0) {
                printf("  %lu / %lu bytes - OK\n", total, total);
                offset = total;
            } else {
                printf("  FAILED: key=%02X ASC=%02X ASCQ=%02X\n",
                       sense[2]&0x0F, sense[12], sense[13]);
                free(data); return 1;
            }
        }
        } /* end else (single transfer kernel send) */
    }
    printf("  Done.\n\n");
    free(data);

    } /* end kernel section - g_outFile */

    /* KERNEL_SETTLE: 2 second wait after kernel transfer before sending normal FW.
       From reference session.rs: KERNEL_SETTLE = Duration::from_secs(2) */
    if (g_outFile[0]) {
        printf("  Waiting 2s after kernel (KERNEL_SETTLE)...\n");
        Sleep(2000);
    }

    /* Send normal firmware (--file2).
       For cross-era pre-cutoff: this is pass 2 (pass 1 was already sent above).
       For all other cases: this is the only normal FW send. */
    if (g_outFile2[0] && fw_prepass) {
        /* Re-use pre-loaded buffer — no re-read needed */
        UCHAR *fw      = fw_prepass;
        long   fwsize  = fw_prepass_sz;   /* already truncated to 0x1E0000 if needed */
        DWORD  fwoffset = 0;

        if (two_pass_needed && g_outFile[0])
            printf("[2c/3] Normal FW pass 2 (%s, 0x%lX bytes)...\n", g_outFile2, (DWORD)fwsize);
        else
            printf("[2c/3] Sending firmware (%s)...\n  [DBG] g_unlock_mode=0x%02X bufID=0x%02X\n",
                   g_outFile2, g_unlock_mode, g_unlock_mode==0x01?0x00:0xF0);

        if (memmem_win(fw, 0x200, "Normal", 6))
            printf("  Type : Normal confirmed\n");
        else
            printf("  WARN : Not a Normal firmware file\n");

        /* Send complete firmware in 0x8000 chunks, bufID=0xF0 */
        if (g_unlock_mode == 0x01) {
            /* Post-cutoff service mode path */
            UCHAR cdb[10];
            DWORD fw_off = 0;
            printf("  Sending normal firmware (bufID=0xF0 offset=0x0000 len=0x%lX)...\n", (DWORD)fwsize);
            while (fw_off < (DWORD)fwsize) {
                DWORD n = (DWORD)fwsize - fw_off;
                if (n > 0x8000) n = 0x8000;
                memset(cdb, 0, sizeof(cdb));
                cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xF0;
                cdb[3]=(UCHAR)(fw_off>>16);
                cdb[4]=(UCHAR)(fw_off>>8);
                cdb[5]=(UCHAR)(fw_off);
                cdb[6]=(UCHAR)(n>>16);
                cdb[7]=(UCHAR)(n>>8);
                cdb[8]=(UCHAR)(n);
                send_scsi(g_hDrive, cdb, 10, fw + fw_off, n,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    HANDLE_BUSY();
                    send_scsi(g_hDrive, cdb, 10, fw + fw_off, n,
                              SCSI_IOCTL_DATA_OUT, sense, &st);
                    if (st != 0) {
                        printf("\n  FAILED at 0x%lX: key=%02X ASC=%02X\n",
                               fw_off, sense[2]&0x0F, sense[12]);
                        free(fw_prepass); fw_prepass = NULL; return 1;
                    }
                }
                fw_off += n;
                printf("\r  %lu / %lu bytes", fw_off, (DWORD)fwsize);
                fflush(stdout);
                Sleep(50);
            }
            printf("\n");
            fwoffset = (DWORD)fwsize;
        } else {
            while (fwoffset < (DWORD)fwsize) {
                UCHAR cdb[10];
                DWORD n = (DWORD)fwsize - fwoffset;
                if (n > 0x8000) n = 0x8000;
                memset(cdb, 0, sizeof(cdb));
                cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xF0;
                cdb[3]=(UCHAR)(fwoffset>>16);
                cdb[4]=(UCHAR)(fwoffset>>8);
                cdb[5]=(UCHAR)(fwoffset);
                cdb[6]=(UCHAR)(n>>16);
                cdb[7]=(UCHAR)(n>>8);
                cdb[8]=(UCHAR)(n);
                send_scsi(g_hDrive, cdb, 10, fw + fwoffset, n,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    HANDLE_BUSY();
                    send_scsi(g_hDrive, cdb, 10, fw + fwoffset, n,
                              SCSI_IOCTL_DATA_OUT, sense, &st);
                    if (st != 0) {
                        printf("\n  FAILED at 0x%lX: key=%02X ASC=%02X\n",
                               fwoffset, sense[2]&0x0F, sense[12]);
                        free(fw_prepass); fw_prepass = NULL; return 1;
                    }
                }
                fwoffset += n;
                printf("\r  %lu / %lu bytes", fwoffset, (DWORD)fwsize);
                fflush(stdout);
                Sleep(50);
            }
            printf("\n");
        }
        printf("  Done.\n\n");

        /* GET EVENT STATUS + REQUEST SENSE after last firmware chunk */
        HANDLE_BUSY();

        free(fw_prepass); fw_prepass = NULL;
    } else if (!g_outFile2[0]) {
        printf("  TIP: Use --file2 S8801601.153 to send firmware\n\n");
    }

    /* Second normal firmware pass (post-cutoff drives require normal→kernel→normal) */
    if (g_outFile3[0]) {
        FILE  *fp3;
        UCHAR *fw3;
        long   fw3size;
        DWORD  fw3offset = 0;

        printf("[2e/3] Sending firmware pass 2 (%s)...\n", g_outFile3);
        fp3 = fopen(g_outFile3, "rb");
        if (!fp3) {
            fprintf(stderr, "Cannot open %s\n", g_outFile3);
            return 1;
        }
        fseek(fp3, 0, SEEK_END);
        fw3size = ftell(fp3);
        fseek(fp3, 0, SEEK_SET);
        fw3 = (UCHAR*)malloc(fw3size);
        if (!fw3) { fclose(fp3); return 1; }
        fread(fw3, 1, fw3size, fp3);
        fclose(fp3);

        if (memmem_win(fw3, 0x200, "Normal", 6))
            printf("  Type : Normal confirmed\n");

        {
            while (fw3offset < (DWORD)fw3size) {
                UCHAR cdb[10];
                DWORD n = (DWORD)fw3size - fw3offset;
                if (n > 0x8000) n = 0x8000;
                memset(cdb, 0, sizeof(cdb));
                cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xF0;
                cdb[3]=(UCHAR)(fw3offset>>16);
                cdb[4]=(UCHAR)(fw3offset>>8);
                cdb[5]=(UCHAR)(fw3offset);
                cdb[6]=(UCHAR)(n>>16);
                cdb[7]=(UCHAR)(n>>8);
                cdb[8]=(UCHAR)(n);
                send_scsi(g_hDrive, cdb, 10, fw3 + fw3offset, n,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    HANDLE_BUSY();
                    send_scsi(g_hDrive, cdb, 10, fw3 + fw3offset, n,
                              SCSI_IOCTL_DATA_OUT, sense, &st);
                    if (st != 0) {
                        printf("\n  FAILED at 0x%lX: key=%02X ASC=%02X\n",
                               fw3offset, sense[2]&0x0F, sense[12]);
                        free(fw3); return 1;
                    }
                }
                fw3offset += n;
                printf("\r  %lu / %lu bytes", fw3offset, (DWORD)fw3size);
                fflush(stdout);
                Sleep(50);
            }
            printf("\n  Done.\n\n");
        }
        HANDLE_BUSY();
        free(fw3);
    }

    /* Allow drive time to finish processing last firmware chunk
       before issuing the commit trigger.  A drive in bad state
       from previous failed attempts returns 04/4C (HARDWARE ERROR /
       LOGICAL UNIT FAILED SELF-CONFIGURATION) if triggered too soon.
       If you see 04/4C: power-cycle the drive (unplug USB power for
       10+ seconds) and retry from scratch — the drive flash controller
       latches an error flag that only clears on hard power reset. */
    HANDLE_BUSY();
    Sleep(500);

    /* Execution trigger
       Confirmed from Wireshark capture [564]: mode=5 bufID=0xFF len=0x100
       with the 0xF1 session token as payload!
       For post-cutoff: read 0xF1 AFTER firmware send (in service mode)
       then use that token with standard trigger */
    printf("[2d/3] Execution trigger...\n");
    {
        UCHAR sense2[SENSE_SIZE] = {0};
        UCHAR trig_payload[0x100] = {0};
        int   st2 = 0;

        if (g_unlock_mode == 0x01) {
            /* Post-cutoff trigger: use 0xF1 token captured before unlock
               Confirmed from Wireshark [564]: mode=5 bufID=0xFF len=0x100 */
            UCHAR f1buf[0x30] = {0};
            UCHAR f1sense[SENSE_SIZE] = {0};

            /* Try reading 0xF1 now (in service mode) */
            rb_data(0xF1, 0, f1buf, 0x30, f1sense);
            printf("  0xF1 after firmware send: %02X %02X %02X %02X\n",
                   f1buf[0],f1buf[1],f1buf[2],f1buf[3]);

            /* Use random session token as trigger payload! */
            if (g_has_f1token) {
                memcpy(trig_payload, g_f1token, 0x20);
                printf("  Using random session token as trigger payload\n");
            } else {
                memcpy(trig_payload, g_payload, 0x20);
                printf("  Using model string as trigger payload (fallback)\n");
            }

            /* Try with MakeMKV firmware name per MrPenguin's insight:
               "last 4 bytes can be anything — only 16-byte firmware name matters"
               MrPenguin suggests: PIONEER BDR-BDS6 for XD06U (follows XD08U=BDS8 pattern)
               CDB length MUST be >= 19 bytes per MrPenguin! Using 20 bytes (0x14) */
            UCHAR xs06_payload[0x100] = {0};
            UCHAR bds6_payload[0x100] = {0};
            memcpy(xs06_payload, "PIONEER BDR-XS06", 16);
            memcpy(bds6_payload, "PIONEER BDR-BDS6", 16);
            /* Last 4 bytes can be anything — use key anyway */
            xs06_payload[0x10] = 0xF2; xs06_payload[0x11] = 0x8A;
            xs06_payload[0x12] = 0xA9; xs06_payload[0x13] = 0x08;
            bds6_payload[0x10] = 0xF2; bds6_payload[0x11] = 0x8A;
            bds6_payload[0x12] = 0xA9; bds6_payload[0x13] = 0x08;

            /* THE CORRECT TRIGGER:
               - mode=0x05 bufID=0xFF len=0x100
               - Payload = random token (0x200 bytes)
               - BUT bytes 0x10-0x13 replaced with drive-specific key!
               XD07 index=0 key=0xF0116415 (from dword_5D4B38 table) */
            /* Use exactly the same key selected by build_pioneer_payload_auto().
               g_payload[0x10..0x13] came from pioneer_keys[]. */
            DWORD tkey = ((DWORD)g_payload[0x10]      ) |
                         ((DWORD)g_payload[0x11] <<  8) |
                         ((DWORD)g_payload[0x12] << 16) |
                         ((DWORD)g_payload[0x13] << 24);
            {
                UCHAR tpayload[0x100];
                memcpy(tpayload, trig_payload, 0x100);
                tpayload[0x10] = (UCHAR)(tkey & 0xFF);
                tpayload[0x11] = (UCHAR)((tkey>>8) & 0xFF);
                tpayload[0x12] = (UCHAR)((tkey>>16) & 0xFF);
                tpayload[0x13] = (UCHAR)((tkey>>24) & 0xFF);
                UCHAR tcdb[12] = {0x3B,0x05,0xFF,0,0,0,0,0x01,0x00,0,0,0};
                UCHAR tsense[SENSE_SIZE] = {0};
                printf("  Trigger: mode=5 bufID=0xFF len=0x100 key=0x%08X\n", tkey);
                send_scsi(g_hDrive, tcdb, 12, tpayload, 0x100,
                          SCSI_IOCTL_DATA_OUT, tsense, &st2);
                printf("  Trigger: %s",
                       (st2==0||(tsense[2]&0xF)==0)?"GOOD":"FAIL");
                if (st2 != 0 && (tsense[2]&0xF) != 0)
                    printf(" (key=%02X ASC=%02X)", tsense[2]&0xF, tsense[12]);
                printf("\n");
                memcpy(sense2, tsense, SENSE_SIZE);
                st2 = (st2==0||(tsense[2]&0xF)==0) ? 0 : 1;
                goto trigger_done;
            }
            trigger_done:;
        } else {
            /* Pre-cutoff drive OR post-cutoff drive with mode=0x04 unlock:
               commit trigger (mode=0x05 bufID=0xFF).
               For pre→pre and pre→post: key = unlock key (g_payload[0x10..0x13]).
               For post→pre downgrade (--patch, post-cutoff drive, pre-cutoff target FW):
               commit key = pre-cutoff target key; model = pre-cutoff model string. */
            UCHAR cdb[12] = {0x3B,0x05,0xFF,0,0,0,0,0x01,0x00,0,0,0};
            UCHAR trig_payload[0x100];
            memcpy(trig_payload, g_payload, 0x100);
            DWORD commit_key = ((DWORD)g_payload[0x10]      ) |
                               ((DWORD)g_payload[0x11] <<  8) |
                               ((DWORD)g_payload[0x12] << 16) |
                               ((DWORD)g_payload[0x13] << 24); /* = unlock key */

            if (two_pass_needed) {
                printf("  Cross-era commit: using unlock key=0x%08lX\n", commit_key);
            }


            printf("  Trigger payload: %.16s key=%02X%02X%02X%02X\n",
                   (char*)trig_payload,
                   trig_payload[0x13], trig_payload[0x12],
                   trig_payload[0x11], trig_payload[0x10]);
            send_scsi(g_hDrive, cdb, 12, trig_payload, 0x100,
                      SCSI_IOCTL_DATA_OUT, sense2, &st2);
        }
        printf("  Status: %s", st2==0?"GOOD":"FAIL");
        if (st2 != 0) {
            printf(" (key=%02X ASC=%02X ASCQ=%02X)",
                   sense2[2]&0x0F, sense2[12], sense2[13]);
            if (sense2[12] == 0x4C) {
                printf("\n  NOTE: 04/4C = HARDWARE ERROR / LOGICAL UNIT FAILED SELF-CONFIGURATION\n");
                printf("  The drive accepted the trigger but its internal flash commit failed.\n");
                printf("  Possible causes:\n");
                printf("    1. WRONG FLASH SEQUENCE (ASCQ=02): cross-era (pre→post) flash REQUIRES\n");
                printf("       two-pass normal FW protocol: pass1 before kernel, pass2 after.\n");
                printf("       Check that --file2 was specified and drivekit version is >= v15.\n");
                printf("    2. STALE DRIVE STATE (ASCQ=00 or 02): from previous failed attempts.\n");
                printf("       >>> POWER CYCLE: unplug USB power 10+ seconds, then retry. <<<\n");
            }
        }
        printf("\n\n");
    }
    Sleep(2000);

    /* Wait for drive to complete internal flash and become ready.
       Skip when called from crossflash recovery (g_force) — drive
       reboots on its own, no need to poll. */
    if (g_force) {
        printf("[2a/3] Flash triggered - waiting for drive to reboot...\n");
        Sleep(15000);
        /* Auto-verify */
        {
            UCHAR inq[96] = {0};
            UCHAR inqcdb[6] = {0x12,0,0,0,96,0};
            UCHAR inqsense[SENSE_SIZE] = {0};
            int   inqst = 0;
            send_scsi(g_hDrive, inqcdb, 6, inq, 96,
                      SCSI_IOCTL_DATA_IN, inqsense, &inqst);
            if (inqst == 0) {
                char vendor[9]={0}, model[17]={0}, fw[5]={0};
                memcpy(vendor, inq+8,  8);
                memcpy(model,  inq+16, 16);
                memcpy(fw,     inq+32, 4);
                printf("  +---------------------------+\n");
                printf("  | Flash verified!           |\n");
                printf("  | Vendor  : %-15s |\n", vendor);
                printf("  | Model   : %-15s |\n", model);
                printf("  | Firmware: %-15s |\n", fw);
                printf("  +---------------------------+\n\n");
            } else {
                printf("  Drive still rebooting - run: drivekit inquiry E\n\n");
            }
        }
    } else {
    /* Wait for drive to complete internal flash and become ready */
    printf("[2a/3] Waiting for flash to complete...\n");
    {
        int ready = 0;
        int attempt;

        /* Phase 1: GET EVENT STATUS loop — break when drive signals ready */
        for (attempt = 0; attempt < 160; attempt++) {
            UCHAR escdb[10]={0x4A,0x01,0,0,0x5A,0,0,0,0x08,0};
            UCHAR es[8], sense2[SENSE_SIZE];
            int   st2 = 0;
            Sleep(200);
            memset(es, 0, sizeof(es));
            send_scsi(g_hDrive, escdb, 10, es, 8,
                      SCSI_IOCTL_DATA_IN, sense2, &st2);
            printf("\r  GET EVENT %3d/160  %02X %02X %02X %02X %02X %02X %02X %02X  ", 
                   attempt+1, es[0],es[1],es[2],es[3],es[4],es[5],es[6],es[7]);
            fflush(stdout);
            /* Event class 0x02 = Operational Change (device reset/reboot)
               Event class 0x04 = Media event
               Either signals the drive has rebooted */
            if (st2 == 0 && (es[4] == 0x02 || es[4] == 0x04)) {
                printf("\n  Drive reboot event detected.\n");
                break;
            }
            /* If GET EVENT itself fails with unit attention = drive rebooted */
            if (st2 != 0 && (sense2[2]&0x0F) == 0x06) {
                printf("\n  Unit attention - drive rebooted.\n");
                break;
            }
        }
        printf("\n");

        /* Phase 2: TEST UNIT READY + REQUEST SENSE after every TUR (BDRFlash method) */
        for (attempt = 0; attempt < 300; attempt++) {  /* up to 5 minutes */
            UCHAR cdb[6]   = {0,0,0,0,0,0};
            UCHAR rscdb[6] = {0x03,0,0,0,0x12,0};
            UCHAR sense2[SENSE_SIZE];
            UCHAR rsbuf[18];
            int   st2=0, rst=0;
            UCHAR skey, asc;
            Sleep(500);  /* 500ms intervals like BDRFlash */

            /* TUR */
            send_scsi(g_hDrive, cdb, 6, NULL, 0,
                      SCSI_IOCTL_DATA_UNSPECIFIED, sense2, &st2);
            skey = sense2[2] & 0x0F;
            asc  = sense2[12];

            /* REQUEST SENSE after every TUR - BDRFlash always does this */
            memset(rsbuf, 0, sizeof(rsbuf));
            send_scsi(g_hDrive, rscdb, 6, rsbuf, 18,
                      SCSI_IOCTL_DATA_IN, sense2, &rst);

            /* During NAND write sense key=0x0C is normal - drive is busy writing */
            if (rsbuf[2] == 0x0C) {
                printf("\r  TUR %3d/300: NAND writing (key=0C)...  ", attempt+1);
                fflush(stdout);
                continue;
            }

            printf("\r  TUR %3d/300: skey=%02X ASC=%02X  ",
                   attempt+1, skey, asc);
            fflush(stdout);

            if (st2 == 0 || asc == 0x3A) {                /* Verify drive actually rebooted to normal mode */
                UCHAR f1cdb[10]={0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
                UCHAR f1buf[0x30]; int f1st=0;
                memset(f1buf,0,sizeof(f1buf));
                send_scsi(g_hDrive,f1cdb,10,f1buf,0x30,SCSI_IOCTL_DATA_IN,sense2,&f1st);
                /* If F1 read failed but TUR passed - drive is rebooting, declare success */
                if (f1st != 0) {
                    printf("\nFlash complete - drive rebooting!\n\n");
                    ready = 1; break;
                }
                /* Check if drive exited kernel mode - look for non-"0000" firmware version
                   Scan the F1 response for "0000" pattern indicating kernel mode */
                { int still_kernel = 0;
                  int bi;
                  for(bi=0; bi<0x2C-3; bi++) {
                      if(f1buf[bi]=='0'&&f1buf[bi+1]=='0'&&
                         f1buf[bi+2]=='0'&&f1buf[bi+3]=='0') {
                          still_kernel=1; break;
                      }
                  }
                if(still_kernel) {
                    printf("\r  TUR %3d/300: drive ready but still kernel mode - waiting...  ", attempt+1);
                    fflush(stdout);
                    continue;
                } }
                printf("Flash complete - drive ready!\n\n");
                ready = 1; break;
            }
            /* Unit attention (0x06) = drive just reset/rebooted — success! */
            if (skey == 0x06) {
                printf("\n  Drive rebooted (unit attention) - flash complete!\n\n");
                ready = 1; break;
            }
            if (skey == 0x02 || (skey==0x04 && asc==0x4C)) continue;
        }
        printf("\n");
        if (!ready) {
            printf("  Drive did not respond to TUR — but flash trigger was GOOD.\n");
            printf("  Wait 10-15 seconds then run: drivekit inquiry E\n");
        } else {
            /* Auto-verify: print firmware version */
            UCHAR inq[96] = {0};
            UCHAR inqcdb[6] = {0x12,0,0,0,96,0};
            UCHAR inqsense[SENSE_SIZE] = {0};
            int   inqst = 0;
            Sleep(1000);
            send_scsi(g_hDrive, inqcdb, 6, inq, 96,
                      SCSI_IOCTL_DATA_IN, inqsense, &inqst);
            if (inqst == 0) {
                char vendor[9]={0}, model[17]={0}, fw[5]={0};
                memcpy(vendor, inq+8,  8); vendor[8]=0;
                memcpy(model,  inq+16, 16); model[16]=0;
                memcpy(fw,     inq+32, 4); fw[4]=0;
                printf("  +---------------------------+\n");
                printf("  | Flash verified!           |\n");
                printf("  | Vendor  : %-15s |\n", vendor);
                printf("  | Model   : %-15s |\n", model);
                printf("  | Firmware: %-15s |\n", fw);
                printf("  +---------------------------+\n\n");
            }
        }
    } /* end if (!g_force) wait block */
    } /* end else */

    Sleep(500);

    /* Verify flash success — skip when called from crossflash recovery,
       auto-verify already done in the g_force wait block above */
    if (!g_force) {
    printf("[3/3] Verifying flash...\n");
    {
        UCHAR rb[0x30];
        UCHAR sense2[SENSE_SIZE];
        int   st2 = 0, b;

        /* READ BUFFER 0xF1 — check drive returned to normal mode */
        {
            UCHAR cdb[10] = {0x3C,0x02,0xF1,0,0,0,0,0,0x30,0};
            memset(rb, 0, sizeof(rb));
            send_scsi(g_hDrive, cdb, 10, rb, 0x30,
                      SCSI_IOCTL_DATA_IN, sense2, &st2);
            if (st2 == 0) {
                /* 0xF1 offset 0x00: serial/model string (normal) or blank (kernel)
                   Normal mode:  rb[0] is a printable ASCII char (e.g. 'S' in "SAT 8D31...")
                   Kernel mode:  rb[0] is 0x00 or non-printable
                   Platform at 0x10, kernel version at 0x18 */
                int is_kernel = (rb[0] < 0x20);
                printf("  Mode     : %s\n",
                       is_kernel ? "KERNEL MODE (unexpected!)"
                                 : "NORMAL MODE - flash successful!");
                printf("  Platform : %.8s\n", rb+0x10);
            } else {
                printf("  0xF1 read failed\n");
            }
        }

        /* READ BUFFER 0xA0 offset=0x90 */
        {
            UCHAR cdb[10] = {0x3C,0x02,0xA0,0,0,0x90,0,0,0x10,0};
            UCHAR a0[0x10];
            memset(a0, 0, sizeof(a0));
            send_scsi(g_hDrive, cdb, 10, a0, 0x10,
                      SCSI_IOCTL_DATA_IN, sense2, &st2);
            if (st2 == 0) {
                printf("  0xA0+90h :");
                for (b = 0; b < 16; b++) printf(" %02X", a0[b]);
                printf("\n");
            }
        }

        /* TEST UNIT READY */
        {
            UCHAR cdb[6] = {0,0,0,0,0,0};
            send_scsi(g_hDrive, cdb, 6, NULL, 0,
                      SCSI_IOCTL_DATA_UNSPECIFIED, sense2, &st2);
            printf("  TUR      : %s\n", st2==0?"READY":"not ready");
        }

        /* REQUEST SENSE — clear unit attention */
        {
            UCHAR rscdb[6]={0x03,0,0,0,0x12,0};
            UCHAR rsbuf[18];
            send_scsi(g_hDrive,rscdb,6,rsbuf,18,
                      SCSI_IOCTL_DATA_IN,sense2,&st2);
        }

    printf("  Run: drivekit inquiry %s  to confirm firmware version.\n", g_drivePath);
    } /* end inner verify block */
    } /* end if (!g_force) verify block */
    return 0;
}

/* =========================================================
   MAIN
   ========================================================= */
int main(int argc, char *argv[])
{
    int    ret = 0;
    char  *cmd = NULL;
    char  *drv = NULL;

    SetConsoleOutputCP(65001); /* UTF-8 output */
    setvbuf(stdout, NULL, _IONBF, 0); /* never buffer - so if a SCSI
        call hangs, whatever was already printed is actually visible
        on screen instead of sitting in a buffer */

    memset(g_outFile,  0, sizeof(g_outFile));
    memset(g_outFile2, 0, sizeof(g_outFile2));
    memset(g_outFile3, 0, sizeof(g_outFile3));

    if (argc < 2) { print_help(); return 0; }

    cmd = argv[1];

    /* Parse arguments */
    {
        int i;
        for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_help(); return 0;
        } else if (strcmp(argv[i], "--bufid") == 0 && i+1 < argc) {
            g_bufID = (UCHAR)strtol(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--file") == 0 && i+1 < argc) {
            strncpy(g_outFile, argv[++i], sizeof(g_outFile)-1);
        } else if (strcmp(argv[i], "--file2") == 0 && i+1 < argc) {
            strncpy(g_outFile2, argv[++i], sizeof(g_outFile2)-1);
        } else if (strcmp(argv[i], "--file3") == 0 && i+1 < argc) {
            strncpy(g_outFile3, argv[++i], sizeof(g_outFile3)-1);
        } else if (strcmp(argv[i], "--force") == 0) {
            g_force = 1;
        } else if (strcmp(argv[i], "--key") == 0 && i+1 < argc) {
            g_key_override = (DWORD)strtoul(argv[++i], NULL, 16);
        } else if (strcmp(argv[i], "--patch") == 0) {
            g_patch_flag = 1;
        } else if (strcmp(argv[i], "--fakedate") == 0) {
            g_fakedate = 1;
        } else if (strcmp(argv[i], "--enableversion") == 0) {
            g_enableversion = 1;
        } else if (strcmp(argv[i], "--e5") == 0) {
            g_e5eng = 1;
        } else if (strcmp(argv[i], "--nounlock") == 0) {
            g_nounlock = 1;
        } else if (strcmp(argv[i], "--postcutoff") == 0) {
            g_nounlock = 1;
            g_unlock_mode = 0x01;  /* force post-cutoff mode */
        } else if (strncmp(argv[i], "--maxsize", 9) == 0 && argv[i+1]) {
            g_maxDumpSize = (DWORD)strtoul(argv[++i], NULL, 0);
        } else if (!drv) {
            /* Drive letter: single letter A-Z, not a flag or path */
            int isFlag = (argv[i][0] == '-');
            int isPath = (strchr(argv[i], '\\') != NULL ||
                          strchr(argv[i], '/')  != NULL ||
                          strchr(argv[i], '.')  != NULL);
            if (!isFlag && !isPath && strlen(argv[i]) <= 2)
                drv = argv[i];   /* treat as drive letter */
            else if (!isFlag && !g_outFile[0])
                strncpy(g_outFile, argv[i], sizeof(g_outFile)-1);
        }
    }
    } /* end arg parse block */

    /* File-only commands need no drive, no banner, no prompts — dispatch immediately */
    if (strcmp(cmd, "xordiff")       == 0) return cmd_xordiff();
    if (strcmp(cmd, "patchfw")       == 0) return cmd_patchfw();
    if (strcmp(cmd, "decryptkernel") == 0) return cmd_decryptkernel();
    if (strcmp(cmd, "decodenormal")  == 0) return cmd_decodenormal();
    if (strcmp(cmd, "encryptkernel") == 0) return cmd_encryptkernel();

    printf("\n");
    printf(" \xE2\x96\x84\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84                                           \xE2\x96\x80\xE2\x96\x84\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x84\xE2\x96\x80         \xE2\x96\x84\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\n");
    printf("     \xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x80               \xE2\x96\x84                         \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88    \xE2\x96\xA0\xE2\x96\x84   \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x90\n");
    printf("  \xE2\x96\x84\xE2\x96\x84\xE2\x96\xA0\xE2\x96\x90\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\xA0\xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x80\xE2\x96\x84 \xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x90\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x8C\xE2\x96\x84\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x90\xE2\x96\x91\xE2\x96\x88\xE2\x96\x8C\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\n");
    printf("     \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84  \xE2\x96\x84\xE2\x96\x84  \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x84\xE2\x96\x80\xE2\x96\x84\xE2\x96\xA0 \xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84  \xE2\x96\x84\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80      \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88  \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\n");
    printf("     \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x8C \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88 \xE2\x96\x8C\xE2\x96\x93\xE2\x96\x8C\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C \xE2\x96\x88\xE2\x96\x93\xE2\x96\x93\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C      \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C  \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\n");
    printf("     \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x93\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x90 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x8C\xE2\x96\x93\xE2\x96\x88\xE2\x96\x8C  \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88     \xE2\x96\x90 \xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88   \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x90   \xE2\x96\xA0\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88  \xE2\x96\x84\n");
    printf("     \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x91\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88  \xE2\x96\x80\xE2\x96\x80\xE2\x96\xA0 \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x90 \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88 \xE2\x96\x8C\xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88\xE2\x96\x84\xE2\x96\x84\xE2\x96\x88\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x80    \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x91\xE2\x96\x8C  \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88   \xE2\x96\x90\xE2\x96\x8C\xE2\x96\x91\xE2\x96\x88\xE2\x96\x90\n");
    printf("     \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x90      \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x84 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x90\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88           \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88  \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88    \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x90\n");
    printf("    \xE2\x96\x90\xE2\x96\x90\xE2\x96\x92\xE2\x96\x88\xE2\x96\x90 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x92 \xE2\x96\x8C\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\xA0     \xE2\x96\x90\xE2\x96\x8C\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x90 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x90\xE2\x96\x84\xE2\x96\xA0\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x84    \xE2\x96\x90\xE2\x96\x90\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\x8C \xE2\x96\x88\xE2\x96\x92\xE2\x96\x88\xE2\x96\xA0   \xE2\x96\x90\xE2\x96\x88\xE2\x96\x92\xE2\x96\x92\xE2\x96\x88\xE2\x96\x84\n");
    printf("     \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88      \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x80\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x80 \xE2\x96\x80\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x88\xE2\x96\x80\xE2\x96\x88      \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88    \xE2\x96\x80\xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\n");
    printf("  \xE2\x96\x84\xE2\x96\x84 \xE2\x96\x88\xE2\x96\x93\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x93\xE2\x96\x88 \xE2\x96\x84\xE2\x96\x88\xE2\x96\x80\xE2\x96\x84\xE2\x96\x80 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x84 \xE2\x96\x80\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x80\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x80\xE2\x96\xA0\xE2\x96\xA0\xE2\x96\x80  \xE2\x96\x80\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84 \xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\xA0\n");
    printf("     \xE2\x96\x90\xE2\x96\x92\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x92\xE2\x96\x88 \xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80   \xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80 \xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80   \xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80     \xE2\x96\x80\xE2\x96\x84\xE2\x96\x84\xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80    \xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\n");
    printf("     \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88 \xE2\x96\x88\xE2\x96\x88\xE2\x96\x91\xE2\x96\x8C Drive Kit v1.0           cPix / Razor 1911 (c) 2026\n");
    printf("     \xE2\x96\x88\xE2\x96\x91\xE2\x96\x88\xE2\x96\x88\xE2\x96\xA0\xE2\x96\x88\xE2\x96\x88\xE2\x96\x80  Optical drive research toolkit\n");
    printf("    \xE2\x96\x84\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x80\xE2\x96\x84\n");
    printf("\n");

    if (strcmp(cmd, "about") == 0) {
        printf("\n");
        printf("  DriveKit v1.0\n");
        printf("  Optical Drive Research Toolkit\n");
        printf("  by BabaYaga / Razor 1911 (c) 2026\n");
        printf("  ====================================\n\n");
        printf("  Pioneer BD optical drive research toolkit.\n");
        printf("  Firmware flashing, drive identification, SCSI probing,\n");
        printf("  crossflash and downgrade for Pioneer BD-R/BD-RE drives.\n\n");

        printf("  KEY DISCOVERIES\n");
        printf("  ---------------\n");
        printf("  - CROSSFLASH/DOWNGRADE CONFIRMED (Sept 14 2026)\n");
        printf("    First Pioneer post-cutoff downgrade via our own tool!\n");
        printf("    XD08U 1.04 -> 1.02: SUCCESS. Protocol reverse engineered from official Pioneer updater executables.\n\n");
        printf("  - Two-pass NAND write protocol (from greg1wto capture)\n");
        printf("    Firmware written to NAND TWICE - first pass bypasses\n");
        printf("    version check, second pass with kernel is permanent.\n");
        printf("    0x1E0000 bytes (1920KB) per pass in 0x8000 chunks.\n\n");
        printf("  - Unlock trigger payload structure (confirmed)\n");
        printf("    [0x00-0x0F] = model string (e.g. PIONEER BDR-BDS8)\n");
        printf("    [0x10-0x13] = unlock key (big-endian)\n");
        printf("    [0x14-0xFF] = zeros\n");
        printf("    Universal key 0x9A782361 works on all tested drives.\n\n");
        printf("  - Kernel file layout: 0x1200 Pioneer header + kernel code\n");
        printf("    Kernel written to NAND at offset 0x1200\n\n");
        printf("  - Session token (READ BUFFER 0xA0 offset=0x90)\n");
        printf("    Dynamic 16-byte unlock token, changes each power-on\n");
        printf("  - Internal model strings (PIONEER BDR-BDS7, BDS8 etc)\n");
        printf("    Differ from INQUIRY strings on newer drive families\n");
        printf("  - Firmware pair matching: kernel ID must match normal fw\n");
        printf("    Mismatched pair returns ASC=4C (self-test failed)\n");
        printf("  - Rolling XOR encrypted firmware (MrPenguin H8S analysis)\n");
        printf("    Crypto engine at 0xFF3FF000, key: x*(16807)%%0x7FFFFFFF\n");
        printf("  - Version check in ENCRYPTED binary - header patch fails\n");
        printf("  - Serial number year encoding confirmed (cxplay)\n");
        printf("  - KernelFront cipher reverse engineered (heisenberg)\n");
        printf("    H8S/2600 kernel payload XOR/rotate cipher fully decoded\n");
        printf("    decode(v,k) = ROR32(v^k, k&31) using 1024-entry LE key table\n");
        printf("    Enables direct kernel inspection, patching and re-encryption\n");
        printf("  - Kernel patch locations for downgrade (MattJackson)\n");
        printf("    Identified which bytes in the decrypted kernel must be\n");
        printf("    patched to allow downgrade below version lock\n");
        printf("    Note: full patch set may not yet be fully implemented\n\n");

        printf("  HARDWARE\n");
        printf("  --------\n");
        printf("  Pioneer BD drives use Renesas H8S/2600 (big-endian CISC)\n");
        printf("  Memory map (SAT 8801):\n");
        printf("    0x00100000 = bootloader\n");
        printf("    0x00400000 = main firmware\n");
        printf("    0x00410000 = model string\n");
        printf("    0xFF3FF000 = crypto/DMA engine\n");
        printf("  Universal unlock key: 0x9A782361 (sent BE: 9A 78 23 61)\n\n");

        printf("  CREDITS\n");
        printf("  -------\n");
        printf("  greg1wto        Provided tools enabling Wireshark capture\n");
        printf("                  enabling Wireshark capture of a live flash session\n");
        printf("                  Revealed NAND write protocol that made\n");
        printf("                  crossflash/downgrade possible!\n");
        printf("  blackened2687   BDRFlash/AutoFlasher author\n");
        printf("                  Pioneer flash protocol pioneer\n");
        printf("  MrPenguin       H8S/2600 deep firmware analysis\n");
        printf("                  Rolling XOR cipher reverse engineering\n");
        printf("                  BDR-S12U pypcode/Ghidra SLA analysis\n");
        printf("                  Unlock key endianness clarification\n");
        printf("  cxplay          1.4GB+ firmware archive\n");
        printf("                  S9330360/361 discovery\n");
        printf("                  Serial number year formula\n");
        printf("  Sayaka          Firmware hunting methodology\n");
        printf("                  BDR-UD04 UHD confirmation\n");
        printf("  Coopervid       Support, testing, community liaison\n");
        printf("  MakeMKV comm.   Drive testing and firmware contributions\n");
        printf("  heisenberg      KernelFront cipher decryption and analysis\n");
        printf("                  Development support and testing throughout\n");
        printf("                  Wireshark capture analysis for SAT 9331\n");
        printf("                  Huge thanks - this tool would not exist without you\n");
        printf("  MattJackson     Decrypted the kernel file and identified the\n");
        printf("                  patch locations required for successful downgrade\n");
        printf("                  below version lock. Shared code openly and has\n");
        printf("                  been invaluable helping everyone with problems.\n\n");

        printf("  BDRFlash special thanks:\n");
        printf("  Pat LaVarre, >NIL<, Agent Smith, Liggy, Mike Chen,\n");
        printf("  ala42, czary2mary, jadburner, cvs, alexx12345, seku,\n");
        printf("  Leman39, wujooj, jurireal, alphaville0527, SnowFox,\n");
        printf("  Kirby, haysey70, Majestic12, elflorek, floppydumper,\n");
        printf("  redwine, cryptojoe3737, TeddyRaspin,\n");
        printf("  asmcom, payalnik23, aliter404\n\n");

        printf("  Tools: Wireshark+USBPcap, IDA Pro, x64dbg, pypcode,\n");
        printf("         Visual Studio 2022, WSL, GCC\n\n");
        printf("  Research and educational purposes only.\n\n");

        printf("                        /\\                \n");
        printf("          Razor 1911   /__\\   Since 1985 \n");
        printf("                      /\\  /\\ \n");
        printf("                     /__\\/__\\ \n");
        return 0;
    }

    /* All other commands need a drive letter. If one wasn't given
       explicitly, enumerate optical drives and - when more than one
       is present - make the user pick, so nobody accidentally
       flashes the wrong drive. */
    if (!drv) {
        static char chosen_drv[4];
        if (select_drive_interactive(chosen_drv, sizeof(chosen_drv))) {
            fprintf(stderr, "Usage: drivekit %s <drive_letter>\n", cmd);
            return 1;
        }
        drv = chosen_drv;
        printf("\n  Using drive: %s:\n\n", drv);

        /* Offer --force and --nounlock interactively too, so they
           don't have to be typed on the command line every run.
           Only asked here (not when a drive letter was already
           given explicitly), and only for flags not already passed
           as arguments. */
        printf("  Current flags: --force=%s  --nounlock=%s\n",
               g_force ? "on" : "off", g_nounlock ? "on" : "off");

        if (!g_force) {
            char line[16];
            printf("  Enable --force (skip compatibility/ready checks)? [y/N]: ");
            fflush(stdout);
            if (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = '\0';
                if (line[0] == 'y' || line[0] == 'Y') {
                    g_force = 1;
                    printf("  --force enabled.\n");
                }
            }
        }
        if (!g_nounlock) {
            char line[16];
            printf("  Enable --nounlock (skip unlock step, for older drives)? [y/N]: ");
            fflush(stdout);
            if (fgets(line, sizeof(line), stdin)) {
                line[strcspn(line, "\r\n")] = '\0';
                if (line[0] == 'y' || line[0] == 'Y') {
                    g_nounlock = 1;
                    printf("  --nounlock enabled.\n");
                }
            }
        }
        printf("\n");
    }

    if (open_drive(drv)) return 1;

    /* Skip drive info banner for flash commands - reads disturb drive state */
    if (strcmp(cmd, "flashfw")    != 0 &&
        strcmp(cmd, "crossflash")  != 0 &&
        strcmp(cmd, "xordiff")     != 0 &&
        strcmp(cmd, "triggerflash")!= 0 &&
        strcmp(cmd, "dumpfw")      != 0 &&
        strcmp(cmd, "unlock")      != 0 &&
        strcmp(cmd, "brutekey")    != 0)
        print_drive_info(g_hDrive, g_drivePath);

    if      (strcmp(cmd, "inquiry")     == 0) ret = cmd_inquiry();
    else if (strcmp(cmd, "info")        == 0) ret = cmd_inquiry();
    else if (strcmp(cmd, "driveinfo")  == 0) ret = cmd_driveinfo2();
    else if (strcmp(cmd, "probef0")     == 0) ret = cmd_probef0();
    else if (strcmp(cmd, "rawdump")     == 0) ret = cmd_rawdump();
    else if (strcmp(cmd, "dumpfw")      == 0) ret = cmd_dumpfw();
    else if (strcmp(cmd, "unlock")      == 0) ret = cmd_unlock();
    else if (strcmp(cmd, "probevendor") == 0) ret = cmd_probevendor();
    else if (strcmp(cmd, "discinfo")    == 0) ret = cmd_discinfo();
    else if (strcmp(cmd, "querydriveinfo") == 0) ret = cmd_querydriveinfo();
    else if (strcmp(cmd, "probeb0")     == 0) ret = cmd_probeb0();
    else if (strcmp(cmd, "modelcheck")  == 0) ret = cmd_modelcheck();
    else if (strcmp(cmd, "keycheck")    == 0) ret = cmd_keycheck();
    else if (strcmp(cmd, "brutekey")    == 0) ret = cmd_brutekey();
    else if (strcmp(cmd, "autoflash")  == 0) ret = cmd_autoflash();
    else if (strcmp(cmd, "flashfw")    == 0) ret = cmd_flashfw();
    else if (strcmp(cmd, "flash")      == 0) ret = cmd_flash();
    else if (strcmp(cmd, "crossflash") == 0) ret = cmd_crossflash();
    else if (strcmp(cmd, "xordiff")    == 0) ret = cmd_xordiff();
    else if (strcmp(cmd, "flashinfo")  == 0) ret = cmd_flashinfo();
    else if (strcmp(cmd, "kernellimbo") == 0) {
        /* Enter kernel limbo on post-cutoff drives
           Unlocks drive, sends current firmware, fires XS06 trigger
           Drive enters kernel limbo ready for --nounlock flash */
        printf("=== KERNEL LIMBO MODE ===\n\n");
        printf("  This will erase the normal firmware partition.\n");
        printf("  Drive will enter kernel limbo (Firmware: 0000).\n");
        printf("  Then flash new firmware with: drivekit flashfw E --file2 <fw> --nounlock\n\n");
        printf("  Proceed? [y/N]: ");
        char yn[4]={0}; fgets(yn, sizeof(yn), stdin);
        if (yn[0] != 'y' && yn[0] != 'Y') { printf("Cancelled.\n"); ret = 0; }
        else {
            /* Step 1: Unlock */
            printf("\n[1/3] Unlocking...\n");
            ret = cmd_unlock();
            if (ret == 0) {
                /* Step 2: Send dummy firmware (just need to fill buffer) */
                printf("\n[2/3] Sending kernel trigger firmware...\n");
                Sleep(500);
                /* Step 3: Fire commit trigger with correct model string from g_mdl_map */
                printf("\n[3/3] Firing kernel limbo trigger...\n");
                UCHAR sense[SENSE_SIZE]={0};
                UCHAR xs06[0x100]={0};
                int st=0;
                build_pioneer_payload_auto(xs06);
                UCHAR tcdb[10]={0x3B,0x05,0xFF,0,0,0,0,0x01,0x00,0};
                send_scsi(g_hDrive, tcdb, 10, xs06, 0x100,
                          SCSI_IOCTL_DATA_OUT, sense, &st);
                printf("  Trigger: %s\n", (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
                if (st==0||(sense[2]&0xF)==0) {
                    Sleep(2000);
                    printf("\n  *** Drive should now be in kernel limbo ***\n");
                    printf("  Run: drivekit info E  (should show Firmware: 0000)\n");
                    printf("  Then: drivekit flashfw E --file2 <firmware> --nounlock\n");
                }
            }
        }
    }
    else if (strcmp(cmd, "e5test")      == 0) ret = cmd_e5test();
    else if (strcmp(cmd, "hwdump")  == 0) ret = cmd_hwdump();
    else if (strcmp(cmd, "kernelmode")  == 0) {
        /* Send BDRFlash-style kernel mode trigger:
           WRITE BUFFER mode=0x04 bufID=0xFF len=0x100
           with drive-specific model string + key (BE format, as H8S sees it) */
        UCHAR payload[0x100] = {0};
        UCHAR sense[SENSE_SIZE] = {0};
        int st = 0;
        build_pioneer_payload_auto(payload);
        printf("  Sending kernel mode trigger (BDRFlash method)...\n");
        printf("  Payload: %.16s + %02X%02X%02X%02X\n",
               (char*)payload,
               payload[0x10],payload[0x11],payload[0x12],payload[0x13]);
        UCHAR cdb[10] = {0x3B,0x04,0xFF,0,0,0,0,0x01,0x00,0};
        send_scsi(g_hDrive, cdb, 10, payload, 0x100,
                  SCSI_IOCTL_DATA_OUT, sense, &st);
        printf("  Status: %s", (st==0||(sense[2]&0xF)==0)?"GOOD":"FAIL");
        if (st != 0 && (sense[2]&0xF) != 0)
            printf(" (key=%02X ASC=%02X)", sense[2]&0xF, sense[12]);
        printf("\n");
        ret = (st==0||(sense[2]&0xF)==0) ? 0 : 1;
    }
    else if (strcmp(cmd, "resetnormal")  == 0) ret = cmd_resetnormal();
    else if (strcmp(cmd, "sendcdb")      == 0) {
        UCHAR cdb[16]={0}; UCHAR payload[0x100]={0};
        UCHAR sense[SENSE_SIZE]; int st=0, nc=0, i;
        /* sendcdb 3B 05 FE 00 00 00 00 01 00 00
           Sends raw CDB to drive, direction OUT with zero payload
           Usage: drivekit sendcdb G 3B 05 FE 00 00 00 00 01 00 00 */
        /* Parse hex bytes from remaining args */
        for(i=3; i<argc && nc<16; i++)
            cdb[nc++]=(UCHAR)strtol(argv[i],NULL,16);
        if(nc<6){printf("Usage: drivekit sendcdb G 3B 05 FE 00 00 00 00 01 00 00\n");}
        else {
            int direction = SCSI_IOCTL_DATA_OUT;
            /* Auto-detect direction: 0x3C = READ BUFFER → DATA_IN */
            if (cdb[0] == 0x3C || cdb[0] == 0x12 || cdb[0] == 0x03 ||
                cdb[0] == 0x4A || cdb[0] == 0x46 || cdb[0] == 0x51)
                direction = SCSI_IOCTL_DATA_IN;
            /* For IN commands use empty buffer, for OUT use unlock payload */
            if (direction == SCSI_IOCTL_DATA_IN)
                memset(payload, 0, PAYLOAD_SIZE);
            else
                build_pioneer_payload_auto(payload);
            {
                DWORD xfer = 0;
                if (nc == 6)  xfer = cdb[4];
                else if (nc >= 10) xfer = ((DWORD)cdb[6]<<16)|((DWORD)cdb[7]<<8)|cdb[8];
                if (xfer == 0 || xfer > PAYLOAD_SIZE) xfer = PAYLOAD_SIZE;
                printf("Sending CDB: ");
                for(i=0;i<nc;i++) printf("%02X ",cdb[i]); printf("\n");
                send_scsi(g_hDrive,cdb,nc,payload,xfer,direction,sense,&st);
            }
            printf("Status: %s",st==0?"GOOD":"FAIL");
            if(st!=0) printf(" key=%02X ASC=%02X",sense[2]&0x0F,sense[12]);
            printf("\n");
            if(st==0 && direction==SCSI_IOCTL_DATA_IN) {
                /* Get transfer length from CDB bytes */
                DWORD show = 0;
                if (nc == 6)  show = cdb[4];
                else if (nc >= 10) show = ((DWORD)cdb[6]<<16)|((DWORD)cdb[7]<<8)|cdb[8];
                if (show == 0 || show > 0x1000) show = 0x100;
                printf("Response (%lu bytes):\n", show);
                for(i=0;i<(int)show;i++) {
                    if(i%16==0) printf("  %04X  ",i);
                    printf("%02X ",payload[i]);
                    if(i%16==15) printf("\n");
                }
                if(show%16!=0) printf("\n");
            }
        }
        ret=0;
    }
    else if (strcmp(cmd, "checkfw")     == 0) ret = cmd_checkfw();
    else if (strcmp(cmd, "checkcompat") == 0) ret = cmd_checkcompat();
    else if (strcmp(cmd, "triggerkernel")== 0) ret = cmd_triggerkernel();
    else if (strcmp(cmd, "triggerflash") == 0) {
        /* Trigger kernel mode then immediately flash — same handle,
           kernel mode state preserved between the two operations  */
        ret = cmd_triggerkernel();
        if (ret == 0) {
            g_skip_checks = 1; /* drive already in kernel mode, skip checks */
            ret = cmd_flashfw();
        }
    }
    else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_help();
        ret = 1;
    }

    #undef HANDLE_BUSY
    CloseHandle(g_hDrive);
    return ret;
}

/* =========================================================
   CMD_FLASHINFO
   Diagnostic command — shows all flash-relevant drive info:
   model string, key, platform, what DriveKit would use for
   unlock payload. Use this to diagnose unknown drives.

   Usage: drivekit flashinfo E
   ========================================================= */
static int cmd_flashinfo(void)
{
    UCHAR sense[SENSE_SIZE] = {0};
    int   st = 0;

    printf("=== FLASH INFO ===\n\n");

    /* INQUIRY */
    {
        UCHAR inq[96]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
        UCHAR inqcdb[6]={0x12,0,0,0,96,0};
        send_scsi(g_hDrive,inqcdb,6,inq,96,SCSI_IOCTL_DATA_IN,inqs,&inqst);
        if (inqst==0) {
            char vendor[9]={0},model[17]={0},rev[5]={0},date[9]={0};
            int k;
            memcpy(vendor,inq+8,8); memcpy(model,inq+16,16);
            memcpy(rev,inq+32,4);
            for(k=0;k<8&&inq[0x25+k]>=0x20&&inq[0x25+k]<=0x7E;k++) date[k]=inq[0x25+k];
            printf("  INQUIRY:\n");
            printf("    Vendor   : %s\n", vendor);
            printf("    Model    : %s\n", model);
            printf("    Firmware : %s\n", rev);
            printf("    FW Date  : %s\n", date);
            printf("    Post-cutoff: %s\n\n",
                   strcmp(date,"22/12/01")>=0 ? "YES" : "NO");
        }
    }

    /* 0xF1 — platform, serial, kernel */
    {
        UCHAR f1[0x30]={0}; UCHAR f1s[SENSE_SIZE]={0};
        char serial[16]={0}, platform[16]={0}, kernel[8]={0};
        WORD did=0; int k;
        if (rb_data(0xF1,0,f1,0x30,f1s)==0) {
            for(k=0;k<12&&f1[k]>=0x20&&f1[k]<0x7F;k++) serial[k]=f1[k];
            for(k=0;k<12&&f1[0x10+k]>=0x20&&f1[0x10+k]<0x7F;k++) platform[k]=f1[0x10+k];
            for(k=0;k<8&&f1[0x18+k]>=0x20&&f1[0x18+k]<0x7F;k++) kernel[k]=f1[0x18+k];
            /* Extract drive ID from platform string */
            const char *p=platform;
            while(*p&&(*p<'0'||*p>'9')) p++;
            if(*p) did=(WORD)strtol(p,NULL,16);
            printf("  0xF1 (identity):\n");
            printf("    Serial   : %s\n", serial);
            printf("    Platform : %s\n", platform);
            printf("    Drive ID : 0x%04X\n", did);
            printf("    Kernel   : %s\n\n", kernel);
        } else {
            printf("  0xF1: not readable (post-cutoff normal mode)\n\n");
        }
    }

    /* 0xA0 at offset 0x90 — model string the drive returns */
    {
        UCHAR a0[0x20]={0}; UCHAR a0s[SENSE_SIZE]={0};
        UCHAR a0cdb[10]={0x3C,0x02,0xA0,0,0,0x90,0,0,0x20,0};
        int a0st=0;
        send_scsi(g_hDrive,a0cdb,10,a0,0x20,SCSI_IOCTL_DATA_IN,a0s,&a0st);
        printf("  0xA0 offset=0x90 (drive model string):\n");
        if(a0st==0) {
            char mdl[17]={0}; int k;
            for(k=0;k<16&&a0[k]>=0x20&&a0[k]<=0x7E;k++) mdl[k]=a0[k];
            printf("    Raw     : ");
            for(k=0;k<16;k++) printf("%02X ",a0[k]);
            printf("\n");
            printf("    String  : '%.16s'\n", mdl);
            printf("    Key     : %02X %02X %02X %02X (0x%02X%02X%02X%02X)\n\n",
                   a0[0x10],a0[0x11],a0[0x12],a0[0x13],
                   a0[0x13],a0[0x12],a0[0x11],a0[0x10]);
        } else {
            printf("    ERROR (key=%02X ASC=%02X)\n\n", a0s[2]&0x0F, a0s[12]);
        }
    }

    /* What DriveKit would use */
    {
        UCHAR payload[256]={0};
        WORD  did=0;
        char  kernelID[8]={0};
        build_pioneer_payload_auto(payload);
        printf("  DriveKit unlock payload:\n");
        printf("    Model   : '%.16s'\n", (char*)payload);
        printf("    Key     : %02X %02X %02X %02X (0x%02X%02X%02X%02X)\n",
               payload[0x10],payload[0x11],payload[0x12],payload[0x13],
               payload[0x13],payload[0x12],payload[0x11],payload[0x10]);
        printf("    Raw[0..19]: ");
        int k; for(k=0;k<20;k++) printf("%02X ",payload[k]);
        printf("\n\n");

        /* Show commit trigger key from tkey_map if post-cutoff */
        {
            UCHAR inq[64]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
            UCHAR inqcdb[6]={0x12,0,0,0,64,0};
            char date[9]={0};
            send_scsi(g_hDrive,inqcdb,6,inq,64,SCSI_IOCTL_DATA_IN,inqs,&inqst);
            if(inqst==0){int di;for(di=0;di<8&&inq[0x25+di]>=0x20&&inq[0x25+di]<=0x7E;di++) date[di]=inq[0x25+di];}
            if(strcmp(date,"22/12/01")>=0) {
                /* Post-cutoff — show tkey info */
                UCHAR f1[0x30]={0}; UCHAR f1s[SENSE_SIZE]={0};
                char plat[16]={0};
                if(rb_data(0xF1,0,f1,0x30,f1s)==0){
                    int ki; for(ki=0;ki<12&&f1[0x10+ki]>=0x20&&f1[0x10+ki]<0x7F;ki++) plat[ki]=f1[0x10+ki];
                    const char *p=plat; while(*p&&(*p<'0'||*p>'9')) p++;
                    if(*p) did=(WORD)strtol(p,NULL,16);
                    for(ki=0;ki<8&&f1[0x18+ki]>=0x20&&f1[0x18+ki]<0x7F;ki++) kernelID[ki]=f1[0x18+ki];
                }
                printf("  Commit trigger key (post-cutoff):\n");
                {
                    char kernel4[5] = {0};
                    DWORD tkey;
                    int ki;
                    for (ki = 0; ki < 4 && kernelID[ki]; ki++)
                        kernel4[ki] = kernelID[ki];
                    tkey = pioneer_key_lookup(did, kernel4);
                    printf("    DriveID 0x%04X / kernel %s -> 0x%08lX (from pioneer_keys)\n",
                           did, kernel4[0] ? kernel4 : "(none)", tkey);
                }
                printf("    Current kernel: %s\n\n", kernelID);
            }
        }
    }

    printf("  If unlock fails: check model string and key above.\n");
    printf("  Override with: --key 0xXXXXXXXX\n\n");

    return 0;
}

/* =========================================================
   CMD_XORDIFF
   XOR two encrypted Pioneer firmware files to find differing
   byte positions — reveals where version/date bytes are in
   the encrypted stream without needing the decryption key.

   Usage:
     drivekit xordiff --file fw_new.bin --file2 fw_old.bin

   How it works:
     file1[i] XOR file2[i] = plaintext1[i] XOR plaintext2[i]
     Where result is zero: firmware identical at that position.
     Where result is non-zero: version/date/checksum bytes differ.
   ========================================================= */
static int cmd_xordiff(void)
{
    FILE  *f1 = NULL, *f2 = NULL;
    UCHAR *buf1 = NULL, *buf2 = NULL;
    DWORD  size1, size2, compare_size;
    DWORD  i;
    int    ret = 0;

    if (!g_outFile[0] || !g_outFile2[0]) {
        fprintf(stderr,
            "Usage: drivekit xordiff --file fw_new.bin --file2 fw_old.bin\n\n"
            "  Finds differing byte positions between two encrypted firmware files.\n"
            "  Non-zero XOR positions = version/date/checksum bytes to patch.\n\n");
        return 1;
    }

    f1 = fopen(g_outFile, "rb");
    if (!f1) { fprintf(stderr, "Cannot open: %s\n", g_outFile); return 1; }
    fseek(f1, 0, SEEK_END); size1 = (DWORD)ftell(f1); fseek(f1, 0, SEEK_SET);
    buf1 = (UCHAR*)malloc(size1);
    if (!buf1) { fclose(f1); return 1; }
    fread(buf1, 1, size1, f1);
    fclose(f1);

    f2 = fopen(g_outFile2, "rb");
    if (!f2) { fprintf(stderr, "Cannot open: %s\n", g_outFile2); free(buf1); return 1; }
    fseek(f2, 0, SEEK_END); size2 = (DWORD)ftell(f2); fseek(f2, 0, SEEK_SET);
    buf2 = (UCHAR*)malloc(size2);
    if (!buf2) { fclose(f2); free(buf1); return 1; }
    fread(buf2, 1, size2, f2);
    fclose(f2);

    printf("=== XOR DIFF ===\n\n");
    printf("  File 1: %s (%lu bytes = 0x%06X)\n", g_outFile,  size1, size1);
    printf("  File 2: %s (%lu bytes = 0x%06X)\n", g_outFile2, size2, size2);

    /* Print version info from headers */
    printf("\n  File 1 header:\n");
    { DWORD j; char tmp[64]={0};
      for(j=0;j<(size1<0x200?size1:0x200)-4;j++) {
        if(memcmp(buf1+j,"Revi",4)==0||memcmp(buf1+j,"Gene",4)==0||
           memcmp(buf1+j,"ID :",4)==0||memcmp(buf1+j,"Hard",4)==0) {
            DWORD k; memset(tmp,0,sizeof(tmp));
            for(k=0;k<56&&j+k<size1;k++){if(buf1[j+k]<0x20||buf1[j+k]>0x7E)break;tmp[k]=buf1[j+k];}
            if(tmp[0]) printf("    %s\n",tmp);
        }
      }
    }
    printf("\n  File 2 header:\n");
    { DWORD j; char tmp[64]={0};
      for(j=0;j<(size2<0x200?size2:0x200)-4;j++) {
        if(memcmp(buf2+j,"Revi",4)==0||memcmp(buf2+j,"Gene",4)==0||
           memcmp(buf2+j,"ID :",4)==0||memcmp(buf2+j,"Hard",4)==0) {
            DWORD k; memset(tmp,0,sizeof(tmp));
            for(k=0;k<56&&j+k<size2;k++){if(buf2[j+k]<0x20||buf2[j+k]>0x7E)break;tmp[k]=buf2[j+k];}
            if(tmp[0]) printf("    %s\n",tmp);
        }
      }
    }

    compare_size = (size1 < size2) ? size1 : size2;
    printf("\n  Comparing 0x%06X bytes...\n\n", compare_size);

    /* Find and display all differing positions with context */
    DWORD diff_count = 0;
    DWORD last_diff  = 0xFFFFFFFF;

    printf("  === DIFFERING POSITIONS ===\n");
    for (i = 0; i < compare_size; i++) {
        UCHAR xorval = buf1[i] ^ buf2[i];
        if (xorval != 0) {
            /* New run — print context block */
            if (last_diff == 0xFFFFFFFF || i - last_diff > 16) {
                DWORD ctx = (i >= 8) ? i - 8 : 0;
                DWORD ci;
                printf("\n  @0x%06X:\n", ctx);
                printf("    file1: "); for(ci=ctx;ci<ctx+16&&ci<compare_size;ci++) printf("%02X ",buf1[ci]); printf("\n");
                printf("    file2: "); for(ci=ctx;ci<ctx+16&&ci<compare_size;ci++) printf("%02X ",buf2[ci]); printf("\n");
                printf("    xor  : ");
                for(ci=ctx;ci<ctx+16&&ci<compare_size;ci++) {
                    UCHAR x=buf1[ci]^buf2[ci];
                    if(x) printf("%02X ",x); else printf(".. ");
                }
                printf("\n");
            }
            last_diff = i;
            diff_count++;
        }
    }

    printf("\n  === SUMMARY ===\n");
    printf("  Total differing bytes : %lu\n", diff_count);
    if (size1 != size2)
        printf("  Size difference       : file1=0x%06X file2=0x%06X\n", size1, size2);
    if (diff_count > 0 && diff_count < 500)
        printf("\n  Use 'patchfw' to copy file1 values into file2 at these positions.\n");

    free(buf1);
    free(buf2);
    return ret;
}

/* =========================================================
   CMD_PATCHFW
   Patch a Pioneer firmware file's ASCII header to spoof
   version/date — allows pre-cutoff firmware to pass the
   post-cutoff kernel's version check.

   Copies version, date, and filename bytes from a reference
   firmware file (fw_ref) into the target file (fw_target),
   then saves as fw_target_patched.bin

   Usage:
     drivekit patchfw --file fw_ref.bin --file2 fw_target.bin

   Example:
     drivekit patchfw --file 9331051.102 --file2 S9331051.101
     → saves S9331051.101_patched.bin with version spoofed to 1.02
   ========================================================= */
static int cmd_patchfw(void)
{
    FILE  *f1 = NULL, *f2 = NULL;
    UCHAR *ref = NULL, *target = NULL;
    DWORD  size_ref, size_target;
    char   outpath[512];
    int    patches = 0;
    DWORD  i;

    if (!g_outFile[0] || !g_outFile2[0]) {
        fprintf(stderr,
            "Usage: drivekit patchfw --file fw_ref.bin --file2 fw_target.bin\n\n"
            "  Patches fw_target header to match fw_ref version/date/filename.\n"
            "  Output: fw_target_patched.bin\n\n");
        return 1;
    }

    /* Load reference (newer/accepted firmware) */
    f1 = fopen(g_outFile, "rb");
    if (!f1) { fprintf(stderr, "Cannot open ref: %s\n", g_outFile); return 1; }
    fseek(f1, 0, SEEK_END); size_ref = (DWORD)ftell(f1); fseek(f1, 0, SEEK_SET);
    ref = (UCHAR*)malloc(size_ref);
    if (!ref) { fclose(f1); return 1; }
    fread(ref, 1, size_ref, f1);
    fclose(f1);

    /* Load target (older firmware to patch) */
    f2 = fopen(g_outFile2, "rb");
    if (!f2) { fprintf(stderr, "Cannot open target: %s\n", g_outFile2); free(ref); return 1; }
    fseek(f2, 0, SEEK_END); size_target = (DWORD)ftell(f2); fseek(f2, 0, SEEK_SET);
    target = (UCHAR*)malloc(size_target);
    if (!target) { fclose(f2); free(ref); return 1; }
    fread(target, 1, size_target, f2);
    fclose(f2);

    printf("=== PATCH FIRMWARE HEADER ===\n\n");
    printf("  Reference : %s (%lu bytes)\n", g_outFile,  size_ref);
    printf("  Target    : %s (%lu bytes)\n", g_outFile2, size_target);

    /* Find and patch all differing bytes in header (first 0x200 bytes only)
       The encrypted payload starts around 0x160-0x200, so we only patch
       the plaintext ASCII header region */
    DWORD patch_limit = 0x200;
    if (patch_limit > size_ref)    patch_limit = size_ref;
    if (patch_limit > size_target) patch_limit = size_target;

    printf("\n  Patching ASCII header bytes only (0x000 - 0x%03X):\n", patch_limit);
    printf("  (Binary checksum/crypto regions are preserved)\n\n");

    for (i = 0; i < patch_limit; i++) {
        if (ref[i] != target[i]) {
            /* Only patch if BOTH bytes are ASCII printable or null/CR/LF
               Skip binary regions (crypto, checksums) */
            UCHAR r = ref[i], t = target[i];
            int r_safe = (r >= 0x20 && r <= 0x7E) || r == 0x00 || r == 0x0D || r == 0x0A;
            int t_safe = (t >= 0x20 && t <= 0x7E) || t == 0x00 || t == 0x0D || t == 0x0A;
            if (!r_safe || !t_safe) continue;  /* skip binary bytes */

            printf("    [0x%04X] 0x%02X", i, target[i]);
            if (target[i] >= 0x20 && target[i] <= 0x7E)
                printf(" ('%c')", target[i]);
            printf(" -> 0x%02X", ref[i]);
            if (ref[i] >= 0x20 && ref[i] <= 0x7E)
                printf(" ('%c')", ref[i]);
            printf("\n");
            target[i] = ref[i];
            patches++;
        }
    }

    printf("\n  %d byte(s) patched.\n", patches);

    /* Build output filename */
    snprintf(outpath, sizeof(outpath), "%s_patched.bin", g_outFile2);
    /* Strip path, use just filename */
    {
        char *slash = strrchr(outpath, '\\');
        if (!slash) slash = strrchr(outpath, '/');
        /* Keep full path but add _patched suffix before extension */
        /* Find last dot in g_outFile2 */
        char base[512];
        char *dot = strrchr(g_outFile2, '.');
        if (dot) {
            /* Insert _patched before extension */
            size_t base_len = dot - g_outFile2;
            strncpy(base, g_outFile2, base_len);
            base[base_len] = 0;
            snprintf(outpath, sizeof(outpath), "%s_patched%s", base, dot);
        } else {
            snprintf(outpath, sizeof(outpath), "%s_patched.bin", g_outFile2);
        }
    }

    /* Save patched file */
    {
        FILE *fout = fopen(outpath, "wb");
        if (!fout) {
            fprintf(stderr, "Cannot write: %s\n", outpath);
            free(ref); free(target);
            return 1;
        }
        fwrite(target, 1, size_target, fout);
        fclose(fout);
    }

    printf("\n  Saved: %s\n", outpath);
    printf("\n  Now crossflash with:\n");
    printf("    drivekit crossflash E --file <kernel> --file2 %s\n\n", outpath);

    free(ref);
    free(target);
    return 0;
}

/* =========================================================
   CMD_DECRYPTKERNEL
   Decode a Pioneer KernelFront-encrypted kernel file and
   write the plaintext body to disk.

   Layout of a KernelFront file (e.g. S9331050.100):
     file[0x000:0x200]  — 512-byte ASCII envelope header (not sent to drive)
     file[0x200:0x1200] — 1024 × LE DWORD key table  (1024 keys)
     file[0x1200:0x11200] — 65536-byte encrypted payload  (16384 dwords)

   Cipher (confirmed from H8S/2600 disassembly):
     For each DWORD pair (index i, key k = key_table[i % 1024]):
       plaintext[i] = ROR32(ciphertext[i] ^ k,  k & 31)

   The decoded body is written as-is (raw DWORD stream, LE).

   Optionally patches generation marker and recomputes body checksum
   when --patch flag is given:
     decoded_body[0xFE]  0xFF → 0x01  (generation marker)
     decoded_body[0x1020] adjusted so BE32 additive body sum = 0

   Usage:
     drivekit decryptkernel --file S9331050.100
     drivekit decryptkernel --file S9331050.100 --patch
     drivekit decryptkernel --file S9331050.100 --patch --out decoded.bin
   ========================================================= */

/* -------------------------------------------------------
   scan_kernel_body() — inspect a decrypted 64 KiB KernelFront body.

   Fills *out_marker  with the generation marker byte at body offset 0xFE.
   NOTE: UHD capability is NOT detected from the kernel body.
         Use scan_normal_fw_uhd() on the normal firmware envelope instead.
   ------------------------------------------------------- */

/* 24-byte UHD capability signature (SIG0).
   Present in the decoded normal firmware plaintext of UHD-capable drives.
   Found at offset 0x1738FC in S8D31051.104 (BDR-XD07U v1.04) decoded body.
   NOT present in the kernel body — kernel scans will always report No. */
static const UCHAR KF_UHD_SIG[24] = {
    0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00,
    0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00, 0xC4,
    0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
};

static void scan_kernel_body(const UCHAR *body, DWORD body_len,
                              UCHAR *out_marker, int *out_uhd)
{
    *out_marker = 0xFF;
    *out_uhd    = 0;

    if (body_len < 0x10000)
        return;

    *out_marker = body[0xFE];
    /* UHD detection intentionally removed — SIG0 lives in normal firmware,
       not the kernel body.  Call scan_normal_fw_uhd() for UHD detection. */
    (void)out_uhd;
}

/* -------------------------------------------------------
   normal_fw_probe_layout() — detect which of the known Pioneer normal
   firmware envelope layouts is in use, by decrypting 8 bytes and
   checking for the "PIONEER " magic.

   Two layouts have been observed:
     Standard  (v1.04 and earlier):
       [0x000 : 0x200  ]  512-byte ASCII header
       [0x200 : 0x10200]  64 KiB key table  (16384 LE DWORDs)
       [0x10200 :      ]  ciphertext

     Extended  (v1.06 and later):
       [0x000 : 0x10200]  enlarged header + extra data region
       [0x10200: 0x20200]  64 KiB key table  (16384 LE DWORDs)
       [0x20200 :      ]  ciphertext

   Fills *key_start, *ct_start.  Returns 1 if a layout was identified,
   0 if the file is too small or neither probe matched.
   ------------------------------------------------------- */
static int normal_fw_probe_layout(const UCHAR *data, DWORD size,
                                   DWORD *key_start, DWORD *ct_start)
{
    /* Probe helper: decrypt 2 dwords (8 bytes) and check for "PIONEER " */
    static const UCHAR PIONEER_MAGIC[8] = {'P','I','O','N','E','E','R',' '};
    UCHAR probe[8];
    DWORD i, ks, cs;

    /* Try standard layout first */
    ks = 0x200; cs = 0x10200;
    if (cs + 8 <= size && ks + 8 <= size) {
        for (i = 0; i < 2; i++) {
            DWORD ki = i % 16384;
            DWORD k  = (DWORD)data[ks+ki*4  ] | ((DWORD)data[ks+ki*4+1]<<8)
                     | ((DWORD)data[ks+ki*4+2]<<16) | ((DWORD)data[ks+ki*4+3]<<24);
            DWORD ct = (DWORD)data[cs+i*4   ] | ((DWORD)data[cs+i*4 +1]<<8)
                     | ((DWORD)data[cs+i*4 +2]<<16) | ((DWORD)data[cs+i*4 +3]<<24);
            DWORD pt = ror32(ct ^ k, (int)(k & 31));
            probe[i*4  ] = (UCHAR)(pt     ); probe[i*4+1] = (UCHAR)(pt>> 8);
            probe[i*4+2] = (UCHAR)(pt>>16 ); probe[i*4+3] = (UCHAR)(pt>>24);
        }
        if (memcmp(probe, PIONEER_MAGIC, 8) == 0) {
            *key_start = ks; *ct_start = cs; return 1;
        }
    }

    /* Try extended layout (v1.06+) */
    ks = 0x10200; cs = 0x20200;
    if (cs + 8 <= size && ks + 8 <= size) {
        for (i = 0; i < 2; i++) {
            DWORD ki = i % 16384;
            DWORD k  = (DWORD)data[ks+ki*4  ] | ((DWORD)data[ks+ki*4+1]<<8)
                     | ((DWORD)data[ks+ki*4+2]<<16) | ((DWORD)data[ks+ki*4+3]<<24);
            DWORD ct = (DWORD)data[cs+i*4   ] | ((DWORD)data[cs+i*4 +1]<<8)
                     | ((DWORD)data[cs+i*4 +2]<<16) | ((DWORD)data[cs+i*4 +3]<<24);
            DWORD pt = ror32(ct ^ k, (int)(k & 31));
            probe[i*4  ] = (UCHAR)(pt     ); probe[i*4+1] = (UCHAR)(pt>> 8);
            probe[i*4+2] = (UCHAR)(pt>>16 ); probe[i*4+3] = (UCHAR)(pt>>24);
        }
        if (memcmp(probe, PIONEER_MAGIC, 8) == 0) {
            *key_start = ks; *ct_start = cs; return 1;
        }
    }

    return 0;  /* unknown layout */
}

/* -------------------------------------------------------
   scan_normal_fw_uhd() — decrypt a normal firmware envelope and check
   for the 24-byte UHD capability signature (SIG0).

   Auto-detects layout (standard v1.04 or extended v1.06+) via
   normal_fw_probe_layout().  Returns 1 if SIG0 found, 0 otherwise.
   ------------------------------------------------------- */
static int scan_normal_fw_uhd(const UCHAR *normal_data, DWORD normal_size)
{
    UCHAR  *plain = NULL;
    DWORD   key_start = 0, ct_start = 0;
    DWORD   ct_dwords, di;
    int     found = 0;

    if (!normal_data || normal_size < 0x10204)
        return 0;

    if (!normal_fw_probe_layout(normal_data, normal_size, &key_start, &ct_start))
        return 0;  /* unrecognised layout */

    ct_dwords = (normal_size - ct_start) / 4;
    if (ct_dwords == 0)
        return 0;

    plain = (UCHAR*)malloc(ct_dwords * 4);
    if (!plain)
        return 0;

    {
        const UCHAR *key_bytes    = normal_data + key_start;
        const UCHAR *ct_bytes_ptr = normal_data + ct_start;
        for (di = 0; di < ct_dwords; di++) {
            DWORD ki = di % 16384;
            DWORD k  = (DWORD)key_bytes[ki*4    ]
                     | ((DWORD)key_bytes[ki*4 + 1] <<  8)
                     | ((DWORD)key_bytes[ki*4 + 2] << 16)
                     | ((DWORD)key_bytes[ki*4 + 3] << 24);
            DWORD ct = (DWORD)ct_bytes_ptr[di*4    ]
                     | ((DWORD)ct_bytes_ptr[di*4 + 1] <<  8)
                     | ((DWORD)ct_bytes_ptr[di*4 + 2] << 16)
                     | ((DWORD)ct_bytes_ptr[di*4 + 3] << 24);
            DWORD pt  = ror32(ct ^ k, (int)(k & 31));
            plain[di*4    ] = (UCHAR)(pt      );
            plain[di*4 + 1] = (UCHAR)(pt >>  8);
            plain[di*4 + 2] = (UCHAR)(pt >> 16);
            plain[di*4 + 3] = (UCHAR)(pt >> 24);
        }
    }

    /* Scan decoded plaintext for SIG0 */
    {
        DWORD plain_len = ct_dwords * 4;
        DWORD i;
        if (plain_len >= 24) {
            for (i = 0; i <= plain_len - 24; i++) {
                if (memcmp(plain + i, KF_UHD_SIG, 24) == 0) {
                    found = 1;
                    break;
                }
            }
        }
    }

    free(plain);
    return found;
}

/* Decrypt a KernelFront payload into a caller-supplied 0x10000-byte buffer.
   key_bytes points to file[0x200], enc_bytes to file[0x1200].
   Returns 1 on success, 0 on failure (enc_dwords must be 0x10000/4 = 16384). */
static int kf_decrypt_body(const UCHAR *key_bytes, const UCHAR *enc_bytes,
                            UCHAR *plain_out)
{
    DWORD di;
    DWORD enc_dwords = 0x10000 / 4;
    for (di = 0; di < enc_dwords; di++) {
        DWORD ki = di % 1024;
        DWORD k  = (DWORD)key_bytes[ki*4    ]        |
                   ((DWORD)key_bytes[ki*4 + 1] <<  8) |
                   ((DWORD)key_bytes[ki*4 + 2] << 16) |
                   ((DWORD)key_bytes[ki*4 + 3] << 24);
        DWORD ct = (DWORD)enc_bytes[di*4    ]        |
                   ((DWORD)enc_bytes[di*4 + 1] <<  8) |
                   ((DWORD)enc_bytes[di*4 + 2] << 16) |
                   ((DWORD)enc_bytes[di*4 + 3] << 24);
        DWORD pt = ror32(ct ^ k, (int)(k & 31));
        plain_out[di*4    ] = (UCHAR)(pt      );
        plain_out[di*4 + 1] = (UCHAR)(pt >>  8);
        plain_out[di*4 + 2] = (UCHAR)(pt >> 16);
        plain_out[di*4 + 3] = (UCHAR)(pt >> 24);
    }
    return 1;
}

/* Print a one-line kernel capability summary (used before and after flash).
   Pass normal_data/normal_size for UHD detection (scans decoded normal
   firmware envelope).  Either may be NULL/0 to skip UHD detection. */
static void print_kernel_caps(const UCHAR *kf_file, DWORD kf_size,
                               const UCHAR *normal_data, DWORD normal_size,
                               const char *label)
{
    UCHAR marker = 0xFF;
    int   uhd    = 0;

    if (kf_size >= 0x11200) {
        UCHAR *plain = (UCHAR*)malloc(0x10000);
        if (plain) {
            kf_decrypt_body(kf_file + 0x200, kf_file + 0x1200, plain);
            scan_kernel_body(plain, 0x10000, &marker, &uhd);
            free(plain);
        }
    }

    /* UHD capability lives in the normal firmware body, not the kernel */
    if (normal_data && normal_size >= 0x10204)
        uhd = scan_normal_fw_uhd(normal_data, normal_size);

    printf("  %s  Gen: %s (0x%02X)  UHD: %s\n",
           label,
           (marker == 0x01) ? "New" : (marker == 0x00 ? "Old" : "Old"),
           marker,
           uhd ? "Yes" : "No");
}

static DWORD ror32(DWORD v, int shift)
{
    shift &= 31;
    if (shift == 0) return v;
    return (v >> shift) | (v << (32 - shift));
}

static int cmd_decryptkernel(void)
{
    FILE  *fin  = NULL;
    FILE  *fout = NULL;
    UCHAR *raw  = NULL;
    UCHAR *body = NULL;   /* decoded body, raw bytes */
    long   fsize;
    DWORD  i;
    char   outpath[512];
    int    do_patch = g_patch_flag;  /* set by --patch on cmdline */

    /* --- input file --- */
    if (!g_outFile[0]) {
        fprintf(stderr, "Usage: drivekit decryptkernel --file <kernel.bin> [--patch] [--file2 out.bin]\n");
        return 1;
    }
    fin = fopen(g_outFile, "rb");
    if (!fin) { fprintf(stderr, "Cannot open %s\n", g_outFile); return 1; }
    fseek(fin, 0, SEEK_END); fsize = ftell(fin); fseek(fin, 0, SEEK_SET);

    if (fsize < 0x11200) {
        fprintf(stderr, "File too small for KernelFront layout (need >= 0x11200 bytes, got 0x%lX)\n", (DWORD)fsize);
        fclose(fin); return 1;
    }

    raw = (UCHAR*)malloc((DWORD)fsize);
    if (!raw) { fclose(fin); return 1; }
    fread(raw, 1, (DWORD)fsize, fin);
    fclose(fin); fin = NULL;

    /* --- locate key table and cipher payload --- */
    /* Key table: file[0x200..0x1200) = 1024 LE DWORDs */
    const UCHAR *key_bytes = raw + 0x200;
    /* Cipher payload: file[0x1200..0x11200) = 16384 LE DWORDs = 65536 bytes */
    const UCHAR *enc_bytes = raw + 0x1200;
    DWORD enc_dwords = 0x10000 / 4;   /* 16384 */

    body = (UCHAR*)malloc(0x10000);
    if (!body) { free(raw); return 1; }

    printf("Decoding KernelFront payload (%u dwords)...\n", enc_dwords);

    for (i = 0; i < enc_dwords; i++) {
        /* Load key dword i%1024 from key table (LE) */
        DWORD ki = i % 1024;
        DWORD k = (DWORD)key_bytes[ki*4 + 0]
                | ((DWORD)key_bytes[ki*4 + 1] <<  8)
                | ((DWORD)key_bytes[ki*4 + 2] << 16)
                | ((DWORD)key_bytes[ki*4 + 3] << 24);

        /* Load ciphertext dword (LE) */
        DWORD ct = (DWORD)enc_bytes[i*4 + 0]
                 | ((DWORD)enc_bytes[i*4 + 1] <<  8)
                 | ((DWORD)enc_bytes[i*4 + 2] << 16)
                 | ((DWORD)enc_bytes[i*4 + 3] << 24);

        /* Decrypt: ROR32(ct ^ k, k & 31) */
        DWORD pt = ror32(ct ^ k, (int)(k & 31));

        /* Store plaintext LE */
        body[i*4 + 0] = (UCHAR)(pt       );
        body[i*4 + 1] = (UCHAR)(pt >>  8 );
        body[i*4 + 2] = (UCHAR)(pt >> 16 );
        body[i*4 + 3] = (UCHAR)(pt >> 24 );
    }

    printf("Decode complete.\n");

    /* --- show marker --- */
    /* Generation marker is at BYTE offset 0xFE in the decoded body */
    UCHAR marker_byte = body[0xFE];
    printf("  Generation marker @ decoded[0xFE] = 0x%02X\n", marker_byte);

    /* --- show body checksum at 0x1020 --- */
    {
        DWORD sum = 0;
        for (i = 0; i < enc_dwords; i++) {
            DWORD v = (DWORD)body[i*4 + 0]
                    | ((DWORD)body[i*4 + 1] <<  8)
                    | ((DWORD)body[i*4 + 2] << 16)
                    | ((DWORD)body[i*4 + 3] << 24);
            /* BE32 additive: accumulate byte-swapped */
            DWORD vbe = ((v & 0xFF) << 24) | (((v>>8) & 0xFF) << 16)
                      | (((v>>16) & 0xFF) << 8) | ((v>>24) & 0xFF);
            sum += vbe;
        }
        printf("  Body additive BE32 checksum = 0x%08X  (expect 0x00000000)\n", sum);
    }

    /* --- optional patch --- */
    if (do_patch) {
        printf("\nApplying generation marker patch...\n");

        /* Read current checksum word at decoded body offset 0x1020 (dword index 0x1020/4 = 0x408) */
        DWORD cs_idx = 0x1020 / 4;  /* = 0x408 */
        DWORD cs_old_le = (DWORD)body[cs_idx*4 + 0]
                        | ((DWORD)body[cs_idx*4 + 1] <<  8)
                        | ((DWORD)body[cs_idx*4 + 2] << 16)
                        | ((DWORD)body[cs_idx*4 + 3] << 24);
        /* Convert to BE32 for arithmetic */
        DWORD cs_old_be = ((cs_old_le & 0xFF) << 24) | (((cs_old_le>>8) & 0xFF) << 16)
                        | (((cs_old_le>>16) & 0xFF) << 8) | ((cs_old_le>>24) & 0xFF);

        /* Generation marker is at BYTE offset 0xFE in the decoded body.
           It sits at byte position 2 (big-endian) of the BE32 word whose
           body byte range is [0xFC..0xFF] (dword index 0x3F in LE storage).
           The BE32 contribution of this word changes by (new_marker - old_marker) << 8. */
        UCHAR mk_old = body[0xFE];
        UCHAR mk_new = 0x01;
        body[0xFE] = mk_new;

        /* Delta in BE32 space: marker is byte-position 1 of the BE32 word
           (BE layout of bytes [0xFC,0xFD,0xFE,0xFF] is byte2=0xFE at shift 8) */
        DWORD marker_delta = ((DWORD)mk_new - (DWORD)mk_old) * 0x100;  /* << 8 */
        DWORD cs_new_be = cs_old_be - marker_delta;
        DWORD cs_new_le = ((cs_new_be & 0xFF) << 24) | (((cs_new_be>>8) & 0xFF) << 16)
                        | (((cs_new_be>>16) & 0xFF) << 8) | ((cs_new_be>>24) & 0xFF);

        printf("  Marker:   body[0x%03X]  0x%02X → 0x%02X\n", 0xFE, mk_old, mk_new);
        printf("  Checksum: dword[0x%03X]  BE: 0x%08X → 0x%08X\n",
               cs_idx, cs_old_be, cs_new_be);

        /* Apply checksum patch (marker already applied above) */
        body[cs_idx*4 + 0] = (UCHAR)(cs_new_le       );
        body[cs_idx*4 + 1] = (UCHAR)(cs_new_le >>  8 );
        body[cs_idx*4 + 2] = (UCHAR)(cs_new_le >> 16 );
        body[cs_idx*4 + 3] = (UCHAR)(cs_new_le >> 24 );

        /* Verify */
        DWORD sum = 0;
        for (i = 0; i < enc_dwords; i++) {
            DWORD v = (DWORD)body[i*4 + 0]
                    | ((DWORD)body[i*4 + 1] <<  8)
                    | ((DWORD)body[i*4 + 2] << 16)
                    | ((DWORD)body[i*4 + 3] << 24);
            DWORD vbe = ((v & 0xFF) << 24) | (((v>>8) & 0xFF) << 16)
                      | (((v>>16) & 0xFF) << 8) | ((v>>24) & 0xFF);
            sum += vbe;
        }
        printf("  Verify body sum after patch = 0x%08X  (%s)\n",
               sum, sum == 0 ? "OK" : "FAIL - checksum wrong!");
    }

    /* --- output path --- */
    if (g_outFile2[0]) {
        strncpy(outpath, g_outFile2, sizeof(outpath)-1);
        outpath[sizeof(outpath)-1] = '\0';
    } else {
        snprintf(outpath, sizeof(outpath), "%s_decoded%s.bin",
                 g_outFile, do_patch ? "_patched" : "");
    }

    fout = fopen(outpath, "wb");
    if (!fout) {
        fprintf(stderr, "Cannot write %s\n", outpath);
        free(raw); free(body); return 1;
    }

    if (do_patch) {
        /* Re-encrypt patched body and write full 0x11200 container
           (header + key table + re-encrypted body) for byte-level comparison. */
        const UCHAR *key_bytes2 = raw + 0x200;
        UCHAR *reenc = (UCHAR*)malloc(0x10000);
        if (!reenc) { fclose(fout); free(raw); free(body); return 1; }
        for (i = 0; i < 0x10000/4; i++) {
            DWORD ki = i % 1024;
            DWORD k  = (DWORD)key_bytes2[ki*4    ]        |
                       ((DWORD)key_bytes2[ki*4 + 1] <<  8) |
                       ((DWORD)key_bytes2[ki*4 + 2] << 16) |
                       ((DWORD)key_bytes2[ki*4 + 3] << 24);
            DWORD pt = (DWORD)body[i*4    ]        |
                       ((DWORD)body[i*4 + 1] <<  8) |
                       ((DWORD)body[i*4 + 2] << 16) |
                       ((DWORD)body[i*4 + 3] << 24);
            DWORD ct = rol32(pt, (int)(k & 31)) ^ k;
            reenc[i*4    ] = (UCHAR)(ct      );
            reenc[i*4 + 1] = (UCHAR)(ct >>  8);
            reenc[i*4 + 2] = (UCHAR)(ct >> 16);
            reenc[i*4 + 3] = (UCHAR)(ct >> 24);
        }
        /* Write: original header[0..0x1200) + re-encrypted body */
        fwrite(raw,   1, 0x1200,  fout);
        fwrite(reenc, 1, 0x10000, fout);
        free(reenc);
        fclose(fout);
        printf("\nPatched+re-encrypted kernel written to: %s  (0x11200 bytes)\n", outpath);
        printf("  Compare bytes 0x12FC, 0x2220, 0x2223 against Joni's reference.\n");
    } else {
        fwrite(body, 1, 0x10000, fout);
        fclose(fout);
        printf("\nDecoded body written to: %s  (%u bytes)\n", outpath, 0x10000);
    }

    free(raw);
    free(body);
    return 0;
}

/* =========================================================
   CMD_DECODENORMAL
   Decrypt a Pioneer normal firmware envelope and report UHD capability.

   Usage:
     drivekit decodenormal --file S8D31051.104
     drivekit decodenormal --file S8D31051.104 --file2 decoded_body.bin

   Normal firmware envelope layout:
     [0x000 : 0x200 ]  512-byte ASCII header
     [0x200 : 0x10200]  64 KiB key table  (16384 LE DWORDs)
     [0x10200 :      ]  ciphertext  (same XOR/ROR32 cipher as kernel)
   Decoded plaintext starts with "PIONEER ".
   SIG0 (24-byte UHD signature) is at 0x1738FC in XD07U v1.04 plaintext.
   ========================================================= */
static int cmd_decodenormal(void)
{
    FILE  *fin  = NULL;
    FILE  *fout = NULL;
    UCHAR *raw  = NULL;
    UCHAR *plain = NULL;
    long   fsize;
    DWORD  key_start, ct_start, ct_dwords, di;
    char   outpath[512];

    if (!g_outFile[0]) {
        fprintf(stderr, "Usage: drivekit decodenormal --file <normal.bin> [--file2 out.bin]\n");
        return 1;
    }
    fin = fopen(g_outFile, "rb");
    if (!fin) { fprintf(stderr, "Cannot open %s\n", g_outFile); return 1; }
    fseek(fin, 0, SEEK_END); fsize = ftell(fin); fseek(fin, 0, SEEK_SET);

    if (fsize < (long)0x10204) {
        fprintf(stderr, "File too small for normal firmware layout (need >= 0x10204 bytes, got 0x%lX)\n",
                (long)fsize);
        fclose(fin); return 1;
    }

    raw = (UCHAR*)malloc((DWORD)fsize);
    if (!raw) { fclose(fin); return 1; }
    fread(raw, 1, (DWORD)fsize, fin);
    fclose(fin); fin = NULL;

    /* Print header info */
    printf("Normal firmware: %s  (0x%lX bytes)\n", g_outFile, (long)fsize);
    printf("  Header [0x00]: %.64s\n", raw);
    if (fsize > 0x90 + 4)
        printf("  Version field [0x90]: %.8s\n", raw + 0x90);
    if (fsize > 0xB0 + 8)
        printf("  Platform [0xB0]:  %.8s\n", raw + 0xB0);

    /* Auto-detect envelope layout */
    key_start = 0; ct_start = 0;
    if (!normal_fw_probe_layout(raw, (DWORD)fsize, &key_start, &ct_start)) {
        fprintf(stderr, "Unknown normal firmware layout — cannot decrypt.\n");
        free(raw); return 1;
    }
    printf("  Layout: key=0x%05lX..0x%05lX  ct=0x%05lX  (%s)\n",
           (unsigned long)key_start, (unsigned long)(key_start + 0x10000),
           (unsigned long)ct_start,
           (ct_start == 0x10200) ? "standard" : "extended (v1.06+)");

    /* Decrypt */
    ct_dwords = ((DWORD)fsize - ct_start) / 4;
    printf("\nDecrypting body (%lu dwords)...\n", (unsigned long)ct_dwords);

    plain = (UCHAR*)malloc(ct_dwords * 4);
    if (!plain) { free(raw); return 1; }

    {
        const UCHAR *key_bytes    = raw + key_start;
        const UCHAR *ct_bytes_ptr = raw + ct_start;
        for (di = 0; di < ct_dwords; di++) {
            DWORD ki = di % 16384;
            DWORD k  = (DWORD)key_bytes[ki*4    ]
                     | ((DWORD)key_bytes[ki*4 + 1] <<  8)
                     | ((DWORD)key_bytes[ki*4 + 2] << 16)
                     | ((DWORD)key_bytes[ki*4 + 3] << 24);
            DWORD ct = (DWORD)ct_bytes_ptr[di*4    ]
                     | ((DWORD)ct_bytes_ptr[di*4 + 1] <<  8)
                     | ((DWORD)ct_bytes_ptr[di*4 + 2] << 16)
                     | ((DWORD)ct_bytes_ptr[di*4 + 3] << 24);
            DWORD pt  = ror32(ct ^ k, (int)(k & 31));
            plain[di*4    ] = (UCHAR)(pt      );
            plain[di*4 + 1] = (UCHAR)(pt >>  8);
            plain[di*4 + 2] = (UCHAR)(pt >> 16);
            plain[di*4 + 3] = (UCHAR)(pt >> 24);
        }
    }

    DWORD plain_len = ct_dwords * 4;

    /* Validate magic */
    printf("Decode complete.\n");
    printf("  Plaintext magic [0x00]: %.8s  (OK)\n", plain);

    /* Scan for SIG0 */
    {
        int found = 0;
        DWORD sig_off = 0;
        if (plain_len >= 24) {
            DWORD i;
            for (i = 0; i <= plain_len - 24; i++) {
                if (memcmp(plain + i, KF_UHD_SIG, 24) == 0) {
                    found = 1;
                    sig_off = i;
                    break;
                }
            }
        }
        if (found)
            printf("  UHD signature (SIG0): FOUND at plaintext offset 0x%06lX  → UHD capable: YES\n",
                   (unsigned long)sig_off);
        else
            printf("  UHD signature (SIG0): not found  → UHD capable: NO\n");
    }

    /* Optional: dump decoded body */
    if (g_outFile2[0]) {
        strncpy(outpath, g_outFile2, sizeof(outpath)-1);
        outpath[sizeof(outpath)-1] = '\0';
    } else {
        snprintf(outpath, sizeof(outpath), "%.499s_decoded.bin", g_outFile);
    }

    fout = fopen(outpath, "wb");
    if (!fout) {
        fprintf(stderr, "Cannot write %s\n", outpath);
        free(plain); free(raw); return 1;
    }
    fwrite(plain, 1, plain_len, fout);
    fclose(fout);
    printf("\nDecoded body written to: %s  (0x%lX bytes)\n", outpath, (unsigned long)plain_len);

    free(plain);
    free(raw);
    return 0;
}

/* =========================================================
   CMD_ENCRYPTKERNEL
   Re-encrypt a decoded (plaintext) Pioneer kernel body back
   into a KernelFront-encrypted .100 file ready to flash.

   The header and key table are taken unchanged from the
   original .100 file (--file2).  Only the payload region
   file[0x1200:0x11200] is replaced with the re-encrypted body.

   Encryption is the exact inverse of decryption:
     ciphertext[i] = ROL32(plaintext[i], k & 31) ^ k
   where k = keytable[i % 1024]  (same LE key table).

   Usage:
     drivekit encryptkernel --file decoded_patched.bin --file2 S9331050.100
   Output:
     S9331050_reenc.100   (or --file3 to override)
   ========================================================= */

static DWORD rol32(DWORD v, int shift)
{
    shift &= 31;
    if (shift == 0) return v;
    return (v << shift) | (v >> (32 - shift));
}

static int cmd_encryptkernel(void)
{
    FILE  *fplain = NULL;   /* decoded body (--file)          */
    FILE  *forig  = NULL;   /* original .100 template (--file2) */
    FILE  *fout   = NULL;
    UCHAR *plain  = NULL;
    UCHAR *orig   = NULL;
    long   orig_size;
    DWORD  i;
    char   outpath[512];

    /* --- check args --- */
    if (!g_outFile[0] || !g_outFile2[0]) {
        fprintf(stderr,
            "Usage: drivekit encryptkernel --file decoded.bin --file2 original.100 [--file3 out.100]\n");
        return 1;
    }

    /* --- read decoded body --- */
    fplain = fopen(g_outFile, "rb");
    if (!fplain) { fprintf(stderr, "Cannot open %s\n", g_outFile); return 1; }
    fseek(fplain, 0, SEEK_END);
    {
        long psz = ftell(fplain);
        if (psz < 0x10000) {
            fprintf(stderr, "Decoded body too small (need 0x10000 bytes, got 0x%lX)\n", psz);
            fclose(fplain); return 1;
        }
    }
    fseek(fplain, 0, SEEK_SET);
    plain = (UCHAR*)malloc(0x10000);
    if (!plain) { fclose(fplain); return 1; }
    fread(plain, 1, 0x10000, fplain);
    fclose(fplain); fplain = NULL;

    /* --- read original .100 (header + key table + old payload) --- */
    forig = fopen(g_outFile2, "rb");
    if (!forig) { fprintf(stderr, "Cannot open %s\n", g_outFile2); free(plain); return 1; }
    fseek(forig, 0, SEEK_END); orig_size = ftell(forig); fseek(forig, 0, SEEK_SET);
    if (orig_size < 0x11200) {
        fprintf(stderr, "Original file too small for KernelFront layout (need >= 0x11200, got 0x%lX)\n",
                (DWORD)orig_size);
        fclose(forig); free(plain); return 1;
    }
    orig = (UCHAR*)malloc((DWORD)orig_size);
    if (!orig) { fclose(forig); free(plain); return 1; }
    fread(orig, 1, (DWORD)orig_size, forig);
    fclose(forig); forig = NULL;

    /* --- key table from original: file[0x200..0x1200) --- */
    const UCHAR *key_bytes = orig + 0x200;
    DWORD enc_dwords = 0x10000 / 4;   /* 16384 */

    printf("Re-encrypting KernelFront payload (%u dwords)...\n", enc_dwords);

    /* --- encrypt body in-place into orig[0x1200..0x11200) --- */
    for (i = 0; i < enc_dwords; i++) {
        DWORD ki = i % 1024;
        DWORD k = (DWORD)key_bytes[ki*4 + 0]
                | ((DWORD)key_bytes[ki*4 + 1] <<  8)
                | ((DWORD)key_bytes[ki*4 + 2] << 16)
                | ((DWORD)key_bytes[ki*4 + 3] << 24);

        /* Load plaintext dword (LE) */
        DWORD pt = (DWORD)plain[i*4 + 0]
                 | ((DWORD)plain[i*4 + 1] <<  8)
                 | ((DWORD)plain[i*4 + 2] << 16)
                 | ((DWORD)plain[i*4 + 3] << 24);

        /* Encrypt: ROL32(pt, k & 31) ^ k  (inverse of ROR32(ct^k, k&31)) */
        DWORD ct = rol32(pt, (int)(k & 31)) ^ k;

        /* Store ciphertext LE back into orig payload region */
        orig[0x1200 + i*4 + 0] = (UCHAR)(ct       );
        orig[0x1200 + i*4 + 1] = (UCHAR)(ct >>  8 );
        orig[0x1200 + i*4 + 2] = (UCHAR)(ct >> 16 );
        orig[0x1200 + i*4 + 3] = (UCHAR)(ct >> 24 );
    }

    printf("Encryption complete. Header and key table preserved unchanged.\n");

    /* --- output path --- */
    if (g_outFile3[0]) {
        strncpy(outpath, g_outFile3, sizeof(outpath)-1);
        outpath[sizeof(outpath)-1] = '\0';
    } else {
        /* derive from original filename: strip extension, append _reenc.100 */
        strncpy(outpath, g_outFile2, sizeof(outpath)-1);
        outpath[sizeof(outpath)-1] = '\0';
        {
            char *dot = strrchr(outpath, '.');
            if (dot) *dot = '\0';
        }
        strncat(outpath, "_reenc.100", sizeof(outpath) - strlen(outpath) - 1);
    }

    fout = fopen(outpath, "wb");
    if (!fout) {
        fprintf(stderr, "Cannot write %s\n", outpath);
        free(orig); free(plain); return 1;
    }
    fwrite(orig, 1, (DWORD)orig_size, fout);
    fclose(fout);
    printf("\nRe-encrypted file written to: %s  (%lu bytes)\n", outpath, (unsigned long)orig_size);
    printf("Ready to flash with: drivekit crossflash <drive> --file %s --file2 <normal.100>\n", outpath);

    free(orig);
    free(plain);
    return 0;
}

/* Shared execution trigger — pre-cutoff path, confirmed working.
   Sends WRITE BUFFER mode=0x05 bufID=0xFF len=0x100 with the
   0xA0 session token (or fallback payload) as payload.
   Returns 0 on success. */
static int exec_trigger(const UCHAR *fallback_payload)
{
    UCHAR sense[SENSE_SIZE] = {0};
    UCHAR cdb[10] = {0x3B,0x05,0xFF,0,0,0,0,0x01,0x00,0};
    const UCHAR *payload = g_has_token ? g_a0token : fallback_payload;
    int    st = 0;

    if (g_has_token)
        printf("  Using 0xA0 session token for trigger\n");
    else
        printf("  Using fallback payload for trigger\n");

    send_scsi(g_hDrive, cdb, 10, (UCHAR*)payload, 0x100,
              SCSI_IOCTL_DATA_OUT, sense, &st);

    printf("  Status: %s", st==0 ? "GOOD" : "FAIL");
    if (st != 0)
        printf(" (key=%02X ASC=%02X)", sense[2]&0x0F, sense[12]);
    printf("\n");
    return st;
}

/* Write Buffer helper for crossflash - sends a single chunk */
static int xf_write_buffer(UCHAR mode, UCHAR bufid,
                            DWORD offset, const UCHAR *buf, DWORD len,
                            const char *desc)
{
    /* BDRFlash uses 12-byte CDB for unlock (mode=0x04) and trigger (mode=0x05).
       Confirmed from Wireshark capture: bCBWCBLength=0x0C.
       Other modes (0x07 firmware chunks) use 10-byte CDB. */
    UCHAR cdb[12];
    UCHAR sense[SENSE_SIZE];
    int   st = 0;
    int   cdb_len = (mode == 0x04 || mode == 0x05) ? 12 : 10;

    memset(cdb, 0, sizeof(cdb));
    cdb[0] = 0x3B;              /* WRITE BUFFER */
    cdb[1] = mode;
    cdb[2] = bufid;
    cdb[3] = (UCHAR)(offset >> 16);
    cdb[4] = (UCHAR)(offset >>  8);
    cdb[5] = (UCHAR)(offset      );
    cdb[6] = (UCHAR)(len    >> 16);
    cdb[7] = (UCHAR)(len    >>  8);
    cdb[8] = (UCHAR)(len         );
    cdb[9] = 0x00;
    /* cdb[10] and cdb[11] = 0x00 (already zeroed) */

    send_scsi(g_hDrive, cdb, cdb_len, (UCHAR *)buf, len,
              SCSI_IOCTL_DATA_OUT, sense, &st);
    if (st != 0) {
        fprintf(stderr, "  FAILED: %s (mode=0x%02X bufID=0x%02X off=0x%06X len=0x%06X) "
                        "status=%d sense=%02X/%02X/%02X\n",
                desc, mode, bufid, offset, len,
                st, sense[2]&0x0F, sense[12], sense[13]);
    }
    return st;
}

/* Build the 256-byte trigger/unlock payload.
   Confirmed layout from Pioneer updater analysis:
     [0x00-0x0F]  model string (16 bytes, e.g. "PIONEER BDR-BDS8")
     [0x10-0x13]  unlock key (4 bytes, little-endian)
     [0x14-0xFF]  zeros
*/
static void xf_build_trigger(UCHAR *payload, const char *model, DWORD key_le)
{
    memset(payload, 0, 256);
    /* Model string at [0x00], 16 bytes, space-padded */
    memset(payload, 0x20, 16);  /* pad with spaces first */
    strncpy((char*)payload, model, 16);
    /* Key at [0x10], little-endian */
    payload[0x10] = (UCHAR)(key_le      );
    payload[0x11] = (UCHAR)(key_le >>  8);
    payload[0x12] = (UCHAR)(key_le >> 16);
    payload[0x13] = (UCHAR)(key_le >> 24);
}

/* Send normal firmware in 0x8000 byte chunks.
   BDRFlash USBPcap analysis (XD07 1.05 → XD07U 1.06 crossflash) confirms:
   Pass 1: fw_size - 0x10000 bytes (truncated)
   Pass 2: fw_size bytes (full)
   The 0x10000-byte difference is the ECC/OOB trailer region written last. */
static int xf_send_normal_fw(const UCHAR *fw, DWORD fw_size, int pass)
{
    DWORD   offset;
    DWORD   chunk_sz = 0x8000;
    DWORD   send_size = (pass == 1 && fw_size > 0x10000) ? fw_size - 0x10000 : fw_size;
    DWORD   total_chunks = (send_size + chunk_sz - 1) / chunk_sz;
    DWORD   chunk_num = 0;
    int     st;
    char    desc[64];

    printf("    Sending normal firmware pass %d (%lu bytes in %lu chunks)...\n",
           pass, send_size, total_chunks);

    for (offset = 0; offset < send_size; offset += chunk_sz) {
        DWORD this_sz = send_size - offset;
        if (this_sz > chunk_sz) this_sz = chunk_sz;

        chunk_num++;
        if (chunk_num == 1 || chunk_num == total_chunks ||
            (chunk_num % 16) == 0) {
            printf("    [pass %d] chunk %lu/%lu  offset=0x%06X\r",
                   pass, chunk_num, total_chunks, offset);
            fflush(stdout);
        }

        snprintf(desc, sizeof(desc), "fw_pass%d_chunk@0x%06X", pass, offset);
        st = xf_write_buffer(0x07, 0xF0, offset, fw + offset, this_sz, desc);
        if (st != 0) {
            printf("\n");
            return st;
        }
        Sleep(50); /* match flashfw timing */
    }
    printf("\n    Done - pass %d complete.\n", pass);
    return 0;
}

/* =========================================================
   CMD_FLASHFW_PRECUT
   Pre-cutoff Pioneer flash protocol — exact implementation
   from older DriveKit source confirmed working on BDR-211M
   and pre-cutoff BD drives.

   Protocol:
   1. Unlock: WRITE BUFFER mode=0x04 bufID=0xFF len=0x100
              payload = model string + key from 0xA0
              Failure = abort (no sweep)
   2. Kernel:  WRITE BUFFER mode=0x07 bufID=0xFE
              full file from offset 0, 0x8000 chunks
   3. Normal:  WRITE BUFFER mode=0x07 bufID=0xF0
              full file from offset 0, 0x8000 chunks
   4. Trigger: WRITE BUFFER mode=0x05 bufID=0xFF len=0x100
              same payload as unlock
   ========================================================= */
static int cmd_flashfw_precut(void)
{
    UCHAR  sense[SENSE_SIZE] = {0};
    UCHAR *kdata = NULL;
    UCHAR *fwdata = NULL;
    long   ksize = 0, fwsize = 0;
    DWORD  offset = 0;
    FILE  *fp;
    int    st = 0;

    #define PRECUT_BUSY() do { \
        UCHAR _es[8], _s2[SENSE_SIZE]; int _st2=0; \
        UCHAR _escdb[10]={0x4A,0x01,0,0,0x5A,0,0,0,0x08,0}; \
        send_scsi(g_hDrive,_escdb,10,_es,8,SCSI_IOCTL_DATA_IN,_s2,&_st2); \
        UCHAR _rscdb[6]={0x03,0,0,0,0x12,0}; UCHAR _rb[18]; \
        send_scsi(g_hDrive,_rscdb,6,_rb,18,SCSI_IOCTL_DATA_IN,_s2,&_st2); \
        Sleep(100); \
    } while(0)

    printf("=== FLASH FIRMWARE (PRE-CUTOFF PROTOCOL) ===\n\n");

    if (!g_outFile[0]) {
        fprintf(stderr, "Usage: drivekit flash E --file kernel.bin [--file2 normal.bin]\n");
        return 1;
    }

    /* Load kernel */
    fp = fopen(g_outFile, "rb");
    if (!fp) { fprintf(stderr, "Cannot open kernel: %s\n", g_outFile); return 1; }
    fseek(fp, 0, SEEK_END); ksize = ftell(fp); fseek(fp, 0, SEEK_SET);
    kdata = (UCHAR*)malloc(ksize);
    if (!kdata) { fclose(fp); return 1; }
    fread(kdata, 1, ksize, fp);
    fclose(fp);

    printf("  Kernel : %s (%ld bytes)\n", g_outFile, ksize);

    /* Load normal firmware */
    if (g_outFile2[0]) {
        fp = fopen(g_outFile2, "rb");
        if (!fp) { fprintf(stderr, "Cannot open firmware: %s\n", g_outFile2); free(kdata); return 1; }
        fseek(fp, 0, SEEK_END); fwsize = ftell(fp); fseek(fp, 0, SEEK_SET);
        fwdata = (UCHAR*)malloc(fwsize);
        if (!fwdata) { fclose(fp); free(kdata); return 1; }
        fread(fwdata, 1, fwsize, fp);
        fclose(fp);
        printf("  Normal : %s (%ld bytes)\n", g_outFile2, fwsize);
        /* Pre-cutoff drives reject ECC/OOB trailer with 05/24/00 at 0x1E0000. */
        if (fwsize > 0x1E0000) {
            printf("  Pre-cutoff: truncating fw to 0x1E0000 (dropping 0x%lX ECC bytes)\n",
                   fwsize - 0x1E0000);
            fwsize = 0x1E0000;
        }
    }

    /* Build payload — for pre-cutoff drives 0xA0 returns capability data
       not the unlock string. Override with correct internal model string
       from g_mdl_map using drive ID from 0xF1 */
    build_pioneer_payload_auto(g_payload);
    if (memcmp(g_payload, "PIONEER", 7) != 0) {
        UCHAR f1buf[0x30] = {0}; UCHAR f1s[SENSE_SIZE];
        if (rb_data(0xF1, 0, f1buf, 0x30, f1s) == 0) {
            char plat[16] = {0}; int k; WORD did = 0;
            for (k=0; k<12 && f1buf[0x10+k]>=0x20 && f1buf[0x10+k]<0x7F; k++)
                plat[k] = f1buf[0x10+k];
            const char *p = plat;
            while (*p && (*p < '0' || *p > '9')) p++;
            if (*p) did = (WORD)strtol(p, NULL, 16);
            /* Look up internal model string from g_mdl_map */
            int mi;
            for (mi = 0; g_mdl_map[mi].did; mi++) {
                if (g_mdl_map[mi].did == did) {
                    memset(g_payload, 0x20, 16);
                    strncpy((char*)g_payload, g_mdl_map[mi].str, 16);
                    printf("  [DBG] Model from g_mdl_map[0x%04X]: %.16s\n",
                           did, (char*)g_payload);
                    break;
                }
            }
        }
    }
    /* Use whatever key pioneer_key_lookup() selected — same key for unlock AND trigger.
       The blueprint says trigger payload = same as unlock payload.
       Only override if --key was passed explicitly on the command line. */
    printf("  Payload: %.16s + key %08lX\n\n", (char*)g_payload,
           ((DWORD)g_payload[0x10]) | ((DWORD)g_payload[0x11]<<8) |
           ((DWORD)g_payload[0x12]<<16) | ((DWORD)g_payload[0x13]<<24));

    /* Warning and confirmation */
    {
        char ans[8] = {0};
        printf("  *** THIS WILL REWRITE DRIVE FIRMWARE ***\n");
        printf("  *** Ensure correct drive and firmware files ***\n");
        printf("  *** You have been warned — proceed at your own risk ***\n");
        printf("  Proceed? [y/N]: ");
        fflush(stdout);
        fgets(ans, sizeof(ans), stdin);
        if (ans[0] != 'y' && ans[0] != 'Y') {
            printf("  Cancelled.\n");
            if (kdata)  free(kdata);
            if (fwdata) free(fwdata);
            return 0;
        }
        printf("\n");
    }

    /* Check drive ready */
    {
        int attempt, consecutive = 0;
        printf("[0/4] Checking drive ready...\n");
        for (attempt = 0; attempt < 30; attempt++) {
            UCHAR cdb[6] = {0}; UCHAR s2[SENSE_SIZE]; int st2 = 0;
            send_scsi(g_hDrive, cdb, 6, NULL, 0, SCSI_IOCTL_DATA_UNSPECIFIED, s2, &st2);
            if (st2 == 0 || s2[12] == 0x3A) {
                if (++consecutive >= 3) { printf("  READY\n\n"); Sleep(500); break; }
            } else { consecutive = 0; Sleep(1000); }
        }
    }

    /* Read 0xF1 and 0xA0 to put drive in correct state */
    {
        UCHAR rb[0x30]; UCHAR a0[0x10]; UCHAR rbs[SENSE_SIZE];
        printf("[1/4] Pre-flash state reads...\n");
        rb_data(0xF1, 0,    rb, 0x30, rbs);
        rb_data(0xA0, 0x90, a0, 0x10, rbs);
        Sleep(200);
    }

    /* Unlock: mode=0x04 bufID=0xFF — failure = abort, no sweep */
    if (!g_nounlock) {
        UCHAR wcdb[10] = {0x3B,0x04,0xFF,0,0,0,0,0x01,0,0};
        printf("[2/4] Unlock (mode=0x04 bufID=0xFF)...\n");
        send_scsi(g_hDrive, wcdb, 10, g_payload, PAYLOAD_SIZE,
                  SCSI_IOCTL_DATA_OUT, sense, &st);
        if (st != 0) {
            printf("  FAILED (key=%02X ASC=%02X) — trying without unlock\n",
                   sense[2]&0x0F, sense[12]);
            /* Pre-cutoff drives may not need explicit unlock */
        } else {
            printf("  GOOD\n");
        }
        Sleep(300);
    } else {
        printf("[2/4] Unlock skipped\n");
    }
    printf("\n");

    /* Send kernel — full file from offset 0, chunked to bufID=0xFE */
    printf("[3/4] Sending kernel (%ld bytes)...\n", ksize);
    offset = 0;
    while (offset < (DWORD)ksize) {
        UCHAR cdb[10] = {0};
        DWORD n = (DWORD)ksize - offset;
        if (n > 0x8000) n = 0x8000;
        cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xFE;
        cdb[3]=0; cdb[4]=0; cdb[5]=0; /* pre-cutoff: drive advances offset internally */
        cdb[6]=(UCHAR)(n>>16);      cdb[7]=(UCHAR)(n>>8);      cdb[8]=(UCHAR)(n);
        send_scsi(g_hDrive, cdb, 10, kdata+offset, n, SCSI_IOCTL_DATA_OUT, sense, &st);
        if (st != 0) {
            PRECUT_BUSY();
            send_scsi(g_hDrive, cdb, 10, kdata+offset, n, SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st != 0) {
                printf("\n  FAILED at 0x%06X: key=%02X ASC=%02X\n",
                       offset, sense[2]&0x0F, sense[12]);
                free(kdata); if (fwdata) free(fwdata); return 1;
            }
        }
        offset += n;
        printf("\r  %lu / %lu bytes", offset, (DWORD)ksize);
        fflush(stdout);
        Sleep(50);
    }
    printf("\n  Done.\n\n");
    free(kdata); kdata = NULL;

    /* Send normal firmware — full file from offset 0, chunked to bufID=0xF0 */
    if (fwdata) {
        printf("[3b/4] Sending normal firmware (%ld bytes)...\n", fwsize);
        offset = 0;
        while (offset < (DWORD)fwsize) {
            UCHAR cdb[10] = {0};
            DWORD n = (DWORD)fwsize - offset;
            if (n > 0x8000) n = 0x8000;
            cdb[0]=0x3B; cdb[1]=0x07; cdb[2]=0xF0;
            cdb[3]=0; cdb[4]=0; cdb[5]=0; /* pre-cutoff: drive advances offset internally */
            cdb[6]=(UCHAR)(n>>16);      cdb[7]=(UCHAR)(n>>8);      cdb[8]=(UCHAR)(n);
            send_scsi(g_hDrive, cdb, 10, fwdata+offset, n, SCSI_IOCTL_DATA_OUT, sense, &st);
            if (st != 0) {
                PRECUT_BUSY();
                send_scsi(g_hDrive, cdb, 10, fwdata+offset, n, SCSI_IOCTL_DATA_OUT, sense, &st);
                if (st != 0) {
                    printf("\n  FAILED at 0x%06X: key=%02X ASC=%02X\n",
                           offset, sense[2]&0x0F, sense[12]);
                    free(fwdata); return 1;
                }
            }
            offset += n;
            printf("\r  %lu / %lu bytes", offset, (DWORD)fwsize);
            fflush(stdout);
            Sleep(50);
        }
        printf("\n  Done.\n\n");
        PRECUT_BUSY();
        free(fwdata); fwdata = NULL;
    }

    /* Execution trigger: mode=0x05 bufID=0xFF len=0x100 */
    printf("[4/4] Execution trigger (mode=0x05 bufID=0xFF)...\n");
    {
        UCHAR cdb[10] = {0x3B,0x05,0xFF,0,0,0,0,0x01,0x00,0};
        UCHAR s2[SENSE_SIZE]; int st2 = 0;
        send_scsi(g_hDrive, cdb, 10, g_payload, 0x100,
                  SCSI_IOCTL_DATA_OUT, s2, &st2);
        printf("  Status: %s", st2==0 ? "GOOD" : "FAIL");
        if (st2 != 0) printf(" (key=%02X ASC=%02X)", s2[2]&0x0F, s2[12]);
        printf("\n\n");
    }

    printf("=== FLASH COMPLETE ===\n");
    printf("  Wait 15 seconds then run: drivekit inquiry %s\n\n", g_drivePath);
    Sleep(15000);

    /* Auto verify */
    {
        UCHAR inq[96]={0}; UCHAR inqcdb[6]={0x12,0,0,0,96,0};
        UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
        send_scsi(g_hDrive, inqcdb, 6, inq, 96, SCSI_IOCTL_DATA_IN, inqs, &inqst);
        if (inqst == 0) {
            char vendor[9]={0}, model[17]={0}, fw[5]={0};
            memcpy(vendor, inq+8,  8);
            memcpy(model,  inq+16, 16);
            memcpy(fw,     inq+32, 4);
            printf("  +---------------------------+\n");
            printf("  | Flash verified!           |\n");
            printf("  | Vendor  : %-15s |\n", vendor);
            printf("  | Model   : %-15s |\n", model);
            printf("  | Firmware: %-15s |\n", fw);
            printf("  +---------------------------+\n\n");
        }
    }

    #undef PRECUT_BUSY
    return 0;
}

/* =========================================================
   CMD_FLASH — Smart flash dispatcher
   Probes READ BUFFER 0xB0 to detect pre vs post-cutoff drive,
   then calls cmd_flashfw() or cmd_crossflash() accordingly.

   Usage:
     drivekit flash E --file kernel.bin --file2 normal.bin
   ========================================================= */
static int cmd_flash(void)
{
    UCHAR b0buf[16]      = {0};
    UCHAR b0cdb[10]      = {0x3C,0x02,0xB0,0,0,0,0,0,0x10,0};
    UCHAR b0sense[SENSE_SIZE] = {0};
    int   b0st           = 0;
    int   is_pre_cutoff  = 0;

    printf("=== FLASH (AUTO-DETECT) ===\n\n");

    /* Probe READ BUFFER 0xB0 — readable on pre-cutoff, errors on post-cutoff */
    printf("  [1/2] Probing READ BUFFER 0xB0 to detect drive generation...\n");
    send_scsi(g_hDrive, b0cdb, 10, b0buf, 16,
              SCSI_IOCTL_DATA_IN, b0sense, &b0st);

    if (b0st == 0 && b0buf[0] != 0xFF) {
        /* 0xB0 returned data — but verify with INQUIRY date
           hwdump command can leave post-cutoff drives in a state
           where 0xB0 returns data, fooling the detection */
        int date_confirms_pre = 1;
        {
            UCHAR inq[64]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
            UCHAR inqcdb[6]={0x12,0,0,0,64,0};
            send_scsi(g_hDrive,inqcdb,6,inq,64,SCSI_IOCTL_DATA_IN,inqs,&inqst);
            if (inqst == 0 && inq[0x25] >= 0x20) {
                char date[9]={0}; int di;
                for(di=0;di<8&&inq[0x25+di]>=0x20&&inq[0x25+di]<=0x7E;di++)
                    date[di]=inq[0x25+di];
                date_confirms_pre = (strcmp(date,"22/12/01") < 0);
                printf("        FW Date   : %s\n", date);
            }
        }
        is_pre_cutoff = date_confirms_pre;
        printf("        Response  : %02X %02X %02X %02X %02X %02X %02X %02X"
               " %02X %02X %02X %02X %02X %02X %02X %02X\n",
               b0buf[0],b0buf[1],b0buf[2],b0buf[3],
               b0buf[4],b0buf[5],b0buf[6],b0buf[7],
               b0buf[8],b0buf[9],b0buf[10],b0buf[11],
               b0buf[12],b0buf[13],b0buf[14],b0buf[15]);
        printf("        Result    : DATA RETURNED\n");
        printf("        Generation: PRE-CUTOFF (before 2022-12-27)\n");
        printf("        Protocol  : flashfw (single-pass)\n\n");
    } else {
        is_pre_cutoff = 0;
        printf("        Response  : ERROR (sense key=0x%02X ASC=0x%02X)\n",
               b0sense[2]&0x0F, b0sense[12]);
        printf("        Result    : NOT READABLE\n");
        printf("        Generation: POST-CUTOFF (after 2022-12-27)\n");
        printf("        Protocol  : crossflash (two-pass NAND write)\n\n");
    }

    /* Dispatch */
    if (is_pre_cutoff) {
        printf("  [2/2] Dispatching to flashfw_precut (pre-cutoff protocol)...\n\n");
        g_pre_cutoff  = 1;
        return cmd_flashfw_precut();
    } else {
        printf("  [2/2] Dispatching to crossflash (post-cutoff mode)...\n\n");
        return cmd_crossflash();
    }
}


/* =========================================================
   CMD_CROSSFLASH
   Post-cutoff Pioneer crossflash / downgrade.

   Protocol reverse engineered from official Pioneer updater executables:

   Step 1:  WRITE BUFFER mode=0x04 bufID=0xFF len=0x100
            Unlock trigger payload:
              [0x00-0x78]  zeros / padding
              [0x79-0x88]  model string (16 bytes, e.g. "PIONEER BDR-BDS8")
              [0x89-0x8C]  unlock key (4 bytes little-endian)
              [0x8D-0xFF]  zeros

   Step 2:  WRITE BUFFER mode=0x07 bufID=0xF0, sequential 0x8000 chunks
            First pass: normal firmware (0x1E0000 bytes)

   Step 3:  WRITE BUFFER mode=0x07 bufID=0xFE off=0x0000 len=0x0200
            Token: 512 random bytes

   Step 4:  WRITE BUFFER mode=0x07 bufID=0xFE off=0x1200 len=<kernel_size>
            Kernel binary (written in up to 0x8000 byte chunks)

   Step 5:  WRITE BUFFER mode=0x07 bufID=0xF0, sequential 0x8000 chunks
            Second pass: same normal firmware again

   Step 6:  WRITE BUFFER mode=0x05 bufID=0xFF len=0x100
            Final commit trigger (same payload as step 1)

   Usage:
     drivekit crossflash E --file kernel.bin --file2 normal.bin [--key 0xAA475E15] [--model "PIONEER BDR-BDS8"]

   Key / model defaults by drive SAT:
     SAT 9330  (XD08)   key=0xAA475E15  model="PIONEER BDR-BDS8"
     SAT 9331  (XD08U)  key=0xAA475E15  model="PIONEER BDR-BDS8"
     SAT 8B30  (XD06U)  key=0x08A98AF2  model="PIONEER BDR-XS06"
     Universal fallback  key=0x6123789A  model="PIONEER BDR-BDS8"
   ========================================================= */

/* =========================================================
   Minimal self-contained SHA-256 (FIPS 180-4).
   Used to verify kernel transfer payload before sending to drive.
   ========================================================= */
typedef struct {
    DWORD  state[8];
    DWORD  count[2];   /* bit count lo/hi */
    UCHAR  buf[64];
} SHA256_CTX;

static const DWORD sha256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
    0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
    0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
    0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
    0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
    0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define SHA256_ROR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define SHA256_CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define SHA256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define SHA256_EP0(x) (SHA256_ROR(x,2)^SHA256_ROR(x,13)^SHA256_ROR(x,22))
#define SHA256_EP1(x) (SHA256_ROR(x,6)^SHA256_ROR(x,11)^SHA256_ROR(x,25))
#define SHA256_SIG0(x)(SHA256_ROR(x,7)^SHA256_ROR(x,18)^((x)>>3))
#define SHA256_SIG1(x)(SHA256_ROR(x,17)^SHA256_ROR(x,19)^((x)>>10))

static void sha256_transform(SHA256_CTX *ctx, const UCHAR *data)
{
    DWORD a,b,c,d,e,f,g,h,t1,t2,m[64];
    int i;
    for (i=0;i<16;i++)
        m[i]=((DWORD)data[i*4]<<24)|((DWORD)data[i*4+1]<<16)|
             ((DWORD)data[i*4+2]<<8)|(DWORD)data[i*4+3];
    for (;i<64;i++)
        m[i]=SHA256_SIG1(m[i-2])+m[i-7]+SHA256_SIG0(m[i-15])+m[i-16];
    a=ctx->state[0];b=ctx->state[1];c=ctx->state[2];d=ctx->state[3];
    e=ctx->state[4];f=ctx->state[5];g=ctx->state[6];h=ctx->state[7];
    for (i=0;i<64;i++){
        t1=h+SHA256_EP1(e)+SHA256_CH(e,f,g)+sha256_K[i]+m[i];
        t2=SHA256_EP0(a)+SHA256_MAJ(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;
    ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}

static void sha256_init(SHA256_CTX *ctx)
{
    ctx->count[0]=ctx->count[1]=0;
    ctx->state[0]=0x6a09e667;ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372;ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f;ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab;ctx->state[7]=0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const UCHAR *data, DWORD len)
{
    DWORD i, used, free;
    used = (ctx->count[0] >> 3) & 0x3F;
    free = 64 - used;
    ctx->count[0] += len << 3;
    if (ctx->count[0] < (len << 3)) ctx->count[1]++;
    ctx->count[1] += len >> 29;
    if (len >= free) {
        memcpy(ctx->buf + used, data, free);
        sha256_transform(ctx, ctx->buf);
        for (i = free; i + 64 <= len; i += 64)
            sha256_transform(ctx, data + i);
        used = 0;
        memcpy(ctx->buf, data + i, len - i);
    } else {
        memcpy(ctx->buf + used, data, len);
    }
}

static void sha256_final(SHA256_CTX *ctx, UCHAR digest[32])
{
    DWORD used = (ctx->count[0] >> 3) & 0x3F;
    ctx->buf[used++] = 0x80;
    if (used > 56) {
        memset(ctx->buf + used, 0, 64 - used);
        sha256_transform(ctx, ctx->buf);
        used = 0;
    }
    memset(ctx->buf + used, 0, 56 - used);
    ctx->buf[56]=(UCHAR)(ctx->count[1]>>24);ctx->buf[57]=(UCHAR)(ctx->count[1]>>16);
    ctx->buf[58]=(UCHAR)(ctx->count[1]>>8); ctx->buf[59]=(UCHAR)(ctx->count[1]);
    ctx->buf[60]=(UCHAR)(ctx->count[0]>>24);ctx->buf[61]=(UCHAR)(ctx->count[0]>>16);
    ctx->buf[62]=(UCHAR)(ctx->count[0]>>8); ctx->buf[63]=(UCHAR)(ctx->count[0]);
    sha256_transform(ctx, ctx->buf);
    { int i; for(i=0;i<8;i++){
        digest[i*4]=(UCHAR)(ctx->state[i]>>24);digest[i*4+1]=(UCHAR)(ctx->state[i]>>16);
        digest[i*4+2]=(UCHAR)(ctx->state[i]>>8);digest[i*4+3]=(UCHAR)(ctx->state[i]);
    }}
}

static int cmd_crossflash(void)
{
    UCHAR  trigger[256];
    UCHAR  token[0x200];
    UCHAR  a0token[0x100];      /* session token from READ BUFFER 0xA0 */
    int    has_a0token = 0;
    UCHAR *kernel_data = NULL;
    UCHAR *normal_data = NULL;
    DWORD  kernel_size = 0;
    DWORD  normal_size = 0;
    FILE  *fp;
    int    st = 0;
    DWORD  i;
    int    target_is_postcut = 0;   /* 1 if target firmware Generated Date >= 22/12/27 */
    char   target_fw_version[8] = {0}; /* version string from target firmware header e.g. "1.06" */
    char   target_kern_id[8]    = {0}; /* kernel ID from kernel file header e.g. "ID05" */

    /* Build trigger payload using same auto-detect as flashfw */
    UCHAR auto_payload[256] = {0};
    char  model_str[17]     = {0};
    build_pioneer_payload_auto(auto_payload);
    memcpy(model_str, auto_payload, 16);
    model_str[16] = 0;

    const char *model = model_str;
    /* Key: extract from auto_payload [0x10-0x13] (LE) — this is the platform+kernelID
       specific key returned by pioneer_key_lookup() inside build_pioneer_payload_auto().
       For SAT 9331 / ID05 this is 0x552F4FA4, NOT the universal fallback 0x6123789A.
       Fall back to universal only if lookup returned zero.
       Override with --key if needed. */
    DWORD key_le = ((DWORD)auto_payload[0x10])       |
                   ((DWORD)auto_payload[0x11] <<  8) |
                   ((DWORD)auto_payload[0x12] << 16) |
                   ((DWORD)auto_payload[0x13] << 24);
    if (key_le == 0) key_le = 0x6123789A; /* universal fallback only if lookup missed */
    if (g_key_override) key_le = g_key_override;

    /* TODO: --model override via new global g_model_str if needed */

    printf("=== CROSSFLASH / DOWNGRADE ===\n\n");
    printf("  Protocol: reverse engineered from official Pioneer updater executables\n");
    printf("  Model   : %s\n", model);
    printf("  Key     : 0x%08X\n", key_le);
    printf("\n");

    /* Validate args */
    if (!g_outFile[0] || !g_outFile2[0]) {
        fprintf(stderr,
            "Usage: drivekit crossflash E --file kernel.bin --file2 normal.bin\n"
            "                             [--key 0xAA475E15] [--nounlock]\n\n"
            "  --file     = kernel binary (e.g. 131)\n"
            "  --file2    = normal firmware binary (e.g. 132)\n"
            "  --key      = unlock key override (default 0xAA475E15 for XD08/XD08U)\n"
            "  --nounlock = skip unlock step (drive already in kernel mode)\n\n");
        return 1;
    }

    /* Load kernel file */
    fp = fopen(g_outFile, "rb");
    if (!fp) { fprintf(stderr, "Cannot open kernel: %s\n", g_outFile); return 1; }
    fseek(fp, 0, SEEK_END);
    kernel_size = (DWORD)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    kernel_data = (UCHAR*)malloc(kernel_size);
    if (!kernel_data) { fclose(fp); return 1; }
    fread(kernel_data, 1, kernel_size, fp);
    fclose(fp);
    printf("  Kernel  : %s (%lu bytes = 0x%06X)\n", g_outFile, kernel_size, kernel_size);

    /* Print kernel header info */
    {
        char tmp[64] = {0};
        /* Scan for version strings in first 0x200 bytes */
        const UCHAR *p = kernel_data;
        DWORD scan = (kernel_size < 0x200) ? kernel_size : 0x200;
        for (i = 0; i < scan - 4; i++) {
            if (memcmp(p+i, "ID :", 4) == 0 ||
                memcmp(p+i, "Revi", 4) == 0 ||
                memcmp(p+i, "Hard", 4) == 0 ||
                memcmp(p+i, "Kern", 4) == 0 ||
                memcmp(p+i, "File", 4) == 0 ||
                memcmp(p+i, "Gene", 4) == 0) {
                DWORD j;
                memset(tmp, 0, sizeof(tmp));
                for (j = 0; j < 48 && i+j < scan; j++) {
                    UCHAR c = p[i+j];
                    if (c < 0x20 || c > 0x7E) break;
                    tmp[j] = (char)c;
                }
                if (tmp[0]) {
                    printf("    %s\n", tmp);
                    /* Extract kernel ID (e.g. "ID05") from "Kernel Version : ID05" line */
                    if (strncmp(tmp, "Kernel Version", 14) == 0 && !target_kern_id[0]) {
                        const char *col = strchr(tmp, ':');
                        if (col) {
                            col += 2; /* skip ": " */
                            int ki;
                            for (ki = 0; ki < 7 && col[ki] >= 0x20 && col[ki] != ' '; ki++)
                                target_kern_id[ki] = col[ki];
                        }
                    }
                }
            }
        }
    }

    /* Pre-flash capability snapshot (normal fw not yet loaded — UHD shown after) */
    print_kernel_caps(kernel_data, kernel_size, NULL, 0, "Before:");

    /* -------------------------------------------------------
       KernelFront auto-detect, patch and re-encrypt (in-place)

       A KernelFront file has:
         file[0x000:0x200]   — ASCII envelope header
         file[0x200:0x1200]  — 1024 LE DWORD key table
         file[0x1200:0x11200]— 65536-byte encrypted payload

       Detection heuristic: if the file is >= 0x11200 bytes AND
       the 512-byte envelope header contains only printable ASCII
       (Pioneer always writes readable strings there), AND the
       first dword of the payload region (file[0x1200]) XOR'd with
       the first key (file[0x200]) and ROR'd produces a value whose
       high byte is in 0x00..0x7F (plausible H8S opcode range) —
       then KernelFront is present.

       When detected:
         1. Decrypt payload in a temp buffer
         2. If --patch: flip generation marker 0xFF→0x01, recompute checksum
         3. Re-encrypt back into kernel_data[0x1200..0x11200]
         kernel_data is then used as-is for the NAND write.
       ------------------------------------------------------- */
    {
        int kf_detected = 0;

        if (kernel_size >= 0x11200) {
            /* Check envelope header is printable ASCII (allow CR/LF/NUL — Pioneer
               headers are CRLF-terminated text with embedded nulls for padding) */
            DWORD pi; int printable = 1;
            for (pi = 0; pi < 0x100; pi++) {
                UCHAR c = kernel_data[pi];
                if (c == 0x00 || c == 0x0D || c == 0x0A) continue; /* NUL, CR, LF */
                if (c < 0x20 || c > 0x7E) { printable = 0; break; }
            }
            if (!printable) {
                printf("  KernelFront: header not ASCII (byte 0x%02X at +0x%02X) — raw kernel\n",
                       kernel_data[pi], pi);
            } else {
                /* Test-decrypt first dword to confirm key table is valid */
                DWORD k0 = (DWORD)kernel_data[0x200]        |
                           ((DWORD)kernel_data[0x201] <<  8) |
                           ((DWORD)kernel_data[0x202] << 16) |
                           ((DWORD)kernel_data[0x203] << 24);
                DWORD c0 = (DWORD)kernel_data[0x1200]        |
                           ((DWORD)kernel_data[0x1201] <<  8) |
                           ((DWORD)kernel_data[0x1202] << 16) |
                           ((DWORD)kernel_data[0x1203] << 24);
                DWORD p0 = ror32(c0 ^ k0, (int)(k0 & 31));
                /* H8S/2600 instructions: high byte typically 0x00-0x7F */
                printf("  KernelFront: header ASCII OK, test-decrypt p0=0x%08X (high=0x%02X)\n",
                       p0, p0 >> 24);
                if ((p0 >> 24) <= 0x7F)
                    kf_detected = 1;
            }
        }

        if (kf_detected && !g_patch_flag) {
            /* KernelFront detected but --patch not requested.
               No need to decrypt/re-encrypt — send the file as-is.
               Decrypting without patching and re-encrypting would be a
               no-op only if the key table is used identically in both
               directions; any asymmetry corrupts the kernel silently. */
            UCHAR marker_disp = 0xFF;
            {
                /* Peek at the generation marker for display only — decrypt
                   just the one dword containing plain[0xFE] (body dword 63,
                   file offset 0x1200 + 63*4 = 0x12FC). */
                DWORD ki = 63 % 1024;
                DWORD k  = (DWORD)(kernel_data + 0x200)[ki*4    ]        |
                           ((DWORD)(kernel_data + 0x200)[ki*4 + 1] <<  8) |
                           ((DWORD)(kernel_data + 0x200)[ki*4 + 2] << 16) |
                           ((DWORD)(kernel_data + 0x200)[ki*4 + 3] << 24);
                DWORD c  = (DWORD)(kernel_data + 0x1200)[63*4    ]        |
                           ((DWORD)(kernel_data + 0x1200)[63*4 + 1] <<  8) |
                           ((DWORD)(kernel_data + 0x1200)[63*4 + 2] << 16) |
                           ((DWORD)(kernel_data + 0x1200)[63*4 + 3] << 24);
                DWORD p  = ror32(c ^ k, (int)(k & 31));
                /* plain[0xFE] is byte 2 of this dword (LE: byte0=plain[0xFC]) */
                marker_disp = (UCHAR)(p >> 16);
            }
            printf("  KernelFront: --patch not set — sending as-is (marker peek: 0x%02X = %s)\n\n",
                   marker_disp,
                   (marker_disp == 0x01) ? "post-cutoff" :
                   (marker_disp == 0xFF || marker_disp == 0x00) ? "pre-cutoff" : "unknown");
        } else if (kf_detected) {
            printf("  KernelFront: detected — decrypting in-place");
            printf(" + patching generation marker");
            printf("...\n");

            const UCHAR *key_bytes = kernel_data + 0x200;
            UCHAR *enc_bytes       = kernel_data + 0x1200;
            DWORD  enc_dwords      = 0x10000 / 4;  /* 16384 */
            UCHAR *plain           = (UCHAR*)malloc(0x10000);
            if (!plain) { free(kernel_data); return 1; }

            /* Decrypt via shared helper */
            DWORD di;
            kf_decrypt_body(key_bytes, enc_bytes, plain);

            /* Patch generation marker at body byte 0xFE (runtime addr 0x4000FE).
               Valid old-gen values: 0xFF or 0x00.  New-gen value: 0x01.
               Checksum compensation mirrors the source exactly:
                 marker_delta = (0x01 - marker) * 0x100   (wrapping u32)
                 compensation = -marker_delta              (wrapping u32)
               Add compensation to the existing BE32 word at body offset 0x1020.
               Only two locations in the body change; the additive BE32 sum
               over the full 64 KiB body remains zero. */
            if (g_patch_flag) {
                UCHAR marker = plain[0xFE];
                if (marker == 0x01) {
                    printf("  KernelFront: generation marker already 0x01 — no patch needed\n");
                } else if (marker == 0xFF || marker == 0x00) {
                    plain[0xFE] = 0x01;
                    printf("  KernelFront: generation marker patched 0x%02X -> 0x01\n", marker);

                    /* Delta-adjust the checksum word at body offset 0x1020 */
                    {
                        DWORD marker_delta = ((DWORD)0x01 - (DWORD)marker) * (DWORD)0x100;
                        DWORD compensation = (DWORD)(-(int)marker_delta);
                        DWORD old_word = ((DWORD)plain[0x1020] << 24) |
                                         ((DWORD)plain[0x1021] << 16) |
                                         ((DWORD)plain[0x1022] <<  8) |
                                          (DWORD)plain[0x1023];
                        DWORD new_word = old_word + compensation;
                        plain[0x1020] = (UCHAR)(new_word >> 24);
                        plain[0x1021] = (UCHAR)(new_word >> 16);
                        plain[0x1022] = (UCHAR)(new_word >>  8);
                        plain[0x1023] = (UCHAR)(new_word      );
                        printf("  KernelFront: checksum word 0x%08X -> 0x%08X\n",
                               old_word, new_word);

                        /* Verify patch correctness from actual patched buffer */
                        {
                            DWORD be_sum = 0, vi;
                            for (vi = 0; vi < 0x10000/4; vi++) {
                                DWORD w = ((DWORD)plain[vi*4  ] << 24) |
                                          ((DWORD)plain[vi*4+1] << 16) |
                                          ((DWORD)plain[vi*4+2] <<  8) |
                                           (DWORD)plain[vi*4+3];
                                be_sum += w;
                            }
                            DWORD cw = ((DWORD)plain[0x1020]<<24)|((DWORD)plain[0x1021]<<16)|
                                       ((DWORD)plain[0x1022]<< 8)| (DWORD)plain[0x1023];
                            printf("  KernelFront: patch verify:\n");
                            printf("    plain[0xFE]        = %02X\n", plain[0xFE]);
                            printf("    BE32(plain+0x1020) = %08X\n", cw);
                            printf("    BE32 body sum      = %08X  (%s)\n",
                                   be_sum, be_sum == 0 ? "OK" : "CHECKSUM ERROR");
                        }
                    }
                } else {
                    printf("  KernelFront: unknown generation marker 0x%02X — skipping patch\n",
                           marker);
                }
            }

            /* Re-encrypt back into kernel_data payload region */
            for (di = 0; di < enc_dwords; di++) {
                DWORD ki = di % 1024;
                DWORD k  = (DWORD)key_bytes[ki*4    ]        |
                           ((DWORD)key_bytes[ki*4 + 1] <<  8) |
                           ((DWORD)key_bytes[ki*4 + 2] << 16) |
                           ((DWORD)key_bytes[ki*4 + 3] << 24);
                DWORD pt = (DWORD)plain[di*4    ]        |
                           ((DWORD)plain[di*4 + 1] <<  8) |
                           ((DWORD)plain[di*4 + 2] << 16) |
                           ((DWORD)plain[di*4 + 3] << 24);
                DWORD ct = rol32(pt, (int)(k & 31)) ^ k;
                enc_bytes[di*4    ] = (UCHAR)(ct      );
                enc_bytes[di*4 + 1] = (UCHAR)(ct >>  8);
                enc_bytes[di*4 + 2] = (UCHAR)(ct >> 16);
                enc_bytes[di*4 + 3] = (UCHAR)(ct >> 24);
            }
            free(plain);
            printf("  KernelFront: re-encrypted OK\n\n");
        } else {
            printf("  KernelFront: not detected — kernel sent as-is\n\n");
        }
    }

    /* Load normal firmware file */
    fp = fopen(g_outFile2, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open normal fw: %s\n", g_outFile2);
        free(kernel_data);
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    normal_size = (DWORD)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    normal_data = (UCHAR*)malloc(normal_size);
    if (!normal_data) { fclose(fp); free(kernel_data); return 1; }
    fread(normal_data, 1, normal_size, fp);
    fclose(fp);
    printf("  Normal  : %s (%lu bytes = 0x%06X)\n",
           g_outFile2, normal_size, normal_size);

    /* Parse target firmware version and Generated Date from normal_data header.
       Pioneer .153 header layout (binary, fixed offsets):
         0x90: firmware version string  e.g. "1.06"
         0xB0: hardware/platform string e.g. "SAT 8D31"
       "Generated Date" is in the human-readable text block near offset 0x00-0x200.
       Version and date are both used to select the correct commit trigger key. */
    {
        UCHAR *p = normal_data;
        DWORD  scan = (normal_size < 0x300) ? normal_size : 0x300;
        int k;

        /* Version at fixed offset 0x90 */
        if (normal_size > 0x90 + 8) {
            for (k = 0; k < 7 && p[0x90+k] >= 0x20 && p[0x90+k] < 0x7F; k++)
                target_fw_version[k] = (char)p[0x90+k];
            target_fw_version[k] = 0;
        }

        /* Generated Date: text-search in header block */
        UCHAR *gd = (UCHAR*)memmem_win(p, scan, "Generated Date", 14);
        if (gd) {
            UCHAR *col = (UCHAR*)memchr(gd, ':', 32);
            if (col) {
                char fw_date[12] = {0};
                col += 2;
                for (k = 0; k < 10 && col[k] >= 0x20 && col[k] != 0x0D; k++)
                    fw_date[k] = col[k];
                for (k = 9; k >= 0 && fw_date[k] == ' '; k--) fw_date[k] = 0;
                target_is_postcut = (strcmp(fw_date, "22/12/27") >= 0);
                printf("  Target FW   : version=%s  Generated Date=%s → %s\n",
                       target_fw_version[0] ? target_fw_version : "?",
                       fw_date,
                       target_is_postcut ? "POST-CUTOFF" : "PRE-CUTOFF");
            }
        }
    }
    printf("\n");

    /* -------------------------------------------------------
       DETECT PRE-CUTOFF: attempt READ BUFFER 0xB0.
       Pre-cutoff drives respond with data; post-cutoff drives
       return check condition. Pre-cutoff drives reject the 0x6600-byte
       ECC/OOB trailer (bytes past 0x1E0000) with 05/24/00 — truncate to
       0x1E0000 for them.  Post-cutoff drives accept the full 0x1E6600 file.

       SPECIAL CASE — drive in kernel mode (--nounlock):
       In kernel mode, READ BUFFER 0xB0 is always accessible regardless of
       the drive's actual era — the kernel exposes it unconditionally.
       Using 0xB0 probe result here would misclassify a post-cutoff drive
       stuck in kernel mode as pre-cutoff, causing the normal FW to be
       truncated and the flash to fail.  When --nounlock is set, infer era
       from the TARGET firmware date instead (same logic, reliable source).
       ------------------------------------------------------- */
    {
        UCHAR b0_probe[16] = {0};
        UCHAR b0_sense[SENSE_SIZE] = {0};
        UCHAR b0_cdb[10] = {0x3C,0x02,0xB0,0x00,0x00,0x00,0x00,0x00,0x10,0x00};
        int   b0_st = 0;
        int   is_precut = 0;
        if (g_nounlock) {
            /* Drive is in kernel mode — 0xB0 is always open but unreliable here.
               Read the drive's current firmware date via INQUIRY to classify the DRIVE era.
               The kernel layout to send depends on the DRIVE's era, not the target fw era:
                 pre-cutoff drive → upgrade layout (4-xfer NAND-mapped)
                 post-cutoff drive → downgrade layout (flat 3-chunk)
               Fallback: infer from target fw date if INQUIRY fails. */
            {
                UCHAR inq[64]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
                UCHAR inqcdb[6]={0x12,0,0,0,64,0};
                send_scsi(g_hDrive, inqcdb, 6, inq, 64,
                          SCSI_IOCTL_DATA_IN, inqs, &inqst);
                if (inqst == 0 && inq[0x25] >= 0x20) {
                    char date[9]={0}; int di;
                    for (di=0; di<8 && inq[0x25+di]>=0x20 && inq[0x25+di]<=0x7E; di++)
                        date[di] = inq[0x25+di];
                    is_precut = (strcmp(date,"22/12/01") < 0);
                    printf("  Drive detection: --nounlock (kernel mode), drive FW date %s → %s\n",
                           date, is_precut ? "PRE-CUTOFF drive" : "POST-CUTOFF drive");
                } else {
                    /* INQUIRY failed — fall back to inferring from target fw direction */
                    is_precut = !target_is_postcut;
                    printf("  Drive detection: --nounlock, INQUIRY failed → inferring from target FW date → %s\n",
                           is_precut ? "PRE-CUTOFF" : "POST-CUTOFF");
                }
            }
        } else {
        send_scsi(g_hDrive, b0_cdb, 10, b0_probe, 0x10,
                  SCSI_IOCTL_DATA_IN, b0_sense, &b0_st);
        if (b0_st == 0 && b0_probe[0] != 0xFF) {
            UCHAR inq[64]={0}; UCHAR inqs[SENSE_SIZE]={0}; int inqst=0;
            UCHAR inqcdb[6]={0x12,0,0,0,64,0};
            send_scsi(g_hDrive, inqcdb, 6, inq, 64,
                      SCSI_IOCTL_DATA_IN, inqs, &inqst);
            if (inqst == 0 && inq[0x25] >= 0x20) {
                char date[9]={0}; int di;
                for (di=0; di<8 && inq[0x25+di]>=0x20 && inq[0x25+di]<=0x7E; di++)
                    date[di] = inq[0x25+di];
                is_precut = (strcmp(date,"22/12/01") < 0);
                printf("  Drive detection: FW date %s → %s\n", date,
                       is_precut ? "PRE-CUTOFF" : "POST-CUTOFF (B0 open, date late)");
            } else {
                is_precut = 1;
                printf("  Drive detection: PRE-CUTOFF (READ BUFFER 0xB0 accessible)\n");
            }
        } else {
            printf("  Drive detection: POST-CUTOFF (READ BUFFER 0xB0 not accessible)\n");
        }
        } /* end !g_nounlock */
        if (is_precut) {
            g_pre_cutoff = 1;
            /* For upgrade (pre→post): capture confirms full file sent in step 4.
               Truncation only applies to the prefix (step 2) and downgrade path. */
            printf("  Pre-cutoff drive detected (full normal fw file will be sent in step 4)\n");
        } else {
            printf("  Sending full firmware file including ECC/OOB trailer\n");
        }
        printf("\n");
    }

    /* Cross-era notice: pre-cutoff drive + post-cutoff target firmware.
       Confirmed from USBPcap of BDRFlash (Generated Date: 24/10/09):
       The commit key (mode=0x05) is IDENTICAL to the unlock key — no tkey needed.
       The two-pass normal-FW protocol (pass1 before kernel, pass2 after) handles
       the era difference.  No user action needed. */
    if (g_pre_cutoff && target_is_postcut) {
        printf("  Cross-era flash: PRE-CUTOFF drive → POST-CUTOFF firmware\n");
        printf("  Commit trigger uses unlock key=0x%08lX (confirmed by pcapng)\n", key_le);
        printf("  (BDRFlash confirmed: this combination works)\n");
        printf("\n");
    }

    /* Sanity checks on file headers */
    if (kernel_size < 0x1200) {
        fprintf(stderr, "  ERROR: Kernel file too small (expected >= 0x1200)\n");
        goto fail;
    }
    if (normal_size < 0x100000) {
        fprintf(stderr, "  ERROR: Normal firmware too small (expected ~0x1E0000)\n");
        goto fail;
    }
    /* Warn if hardware version mismatch vs drive */
    {
        char hw_in_file[16] = {0};
        UCHAR *p = normal_data;
        DWORD  scan = (normal_size < 0x200) ? normal_size : 0x200;
        for (i = 0; i < scan - 8; i++) {
            if (memcmp(p+i, "SAT ", 4) == 0) {
                DWORD j;
                for (j = 0; j < 12 && i+j < scan; j++) {
                    UCHAR c = p[i+j];
                    if (c < 0x20 || c > 0x7E) break;
                    hw_in_file[j] = (char)c;
                }
                break;
            }
        }
        if (hw_in_file[0]) {
            printf("  Normal fw header:\n");
            /* reuse earlier scan to print all header strings */
            for (i = 0; i < scan - 4; i++) {
                if (memcmp(p+i, "ID :", 4) == 0 ||
                    memcmp(p+i, "Revi", 4) == 0 ||
                    memcmp(p+i, "Hard", 4) == 0 ||
                    memcmp(p+i, "Kern", 4) == 0 ||
                    memcmp(p+i, "File", 4) == 0 ||
                    memcmp(p+i, "Gene", 4) == 0) {
                    char tmp[64] = {0};
                    DWORD j;
                    for (j = 0; j < 48 && i+j < scan; j++) {
                        UCHAR c = p[i+j];
                        if (c < 0x20 || c > 0x7E) break;
                        tmp[j] = (char)c;
                    }
                    if (tmp[0]) printf("    %s\n", tmp);
                }
            }
            printf("\n");
        }
    }

    /* Check no disc inserted */
    {
        UCHAR cdb[10] = {0x46,0x00,0,0,0,0,0,0x01,0x00,0};
        UCHAR buf[256];
        UCHAR sense2[SENSE_SIZE];
        int   st2 = 0;
        WORD  profile;
        memset(buf, 0, sizeof(buf));
        send_scsi(g_hDrive, cdb, 10, buf, 256, SCSI_IOCTL_DATA_IN, sense2, &st2);
        profile = ((WORD)buf[6]<<8)|buf[7];
        if (profile != 0x0000) {
            printf("  WARNING: Disc detected (profile=0x%04X).\n", profile);
            printf("  Eject disc before crossflashing!\n");
            if (!g_force) { st = 1; goto fail; }
            printf("  --force: continuing anyway.\n\n");
        } else {
            printf("  No disc - OK\n");
        }
    }

    /* Final confirmation */
    {
        char ans[8] = {0};
        printf("\n  *** THIS WILL REWRITE DRIVE FIRMWARE ***\n");
        printf("  *** Ensure correct drive and firmware files ***\n");
        printf("  *** You have been warned — proceed at your own risk ***\n");
        printf("  Proceed? [y/N]: ");
        fflush(stdout);
        fgets(ans, sizeof(ans), stdin);
        if (ans[0] != 'y' && ans[0] != 'Y') {
            printf("  Cancelled.\n");
            st = 0;
            goto fail;
        }
        printf("\n");
    }

    /* -------------------------------------------------------
       PRE-STEP: Read session token from READ BUFFER 0xA0
       This token is used as the commit trigger payload.
       Must be read BEFORE unlock (0xA0 may become inaccessible after).
       ------------------------------------------------------- */
    printf("[0/5] Reading session token (READ BUFFER 0xA0)...\n");
    {
        UCHAR sense0[SENSE_SIZE] = {0};
        memset(a0token, 0, sizeof(a0token));
        memset(g_a0token, 0, sizeof(g_a0token));
        rb_data(0xA0, 0x90, a0token, 0x10, sense0);
        if (a0token[0] != 0) {
            has_a0token = 1;
            memcpy(g_a0token, a0token, 0x10);
            g_has_token = 1;
            printf("      Token: %02X %02X %02X %02X %02X %02X %02X %02X"
                   " %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   a0token[0],a0token[1],a0token[2],a0token[3],
                   a0token[4],a0token[5],a0token[6],a0token[7],
                   a0token[8],a0token[9],a0token[10],a0token[11],
                   a0token[12],a0token[13],a0token[14],a0token[15]);
        } else {
            printf("      (0xA0 returned zeros - will use model+key for commit)\n");
        }
    }
    printf("\n");

    /* -------------------------------------------------------
       PRE-STEP E5: ENGINEERING MODE ENABLE (optional, --e5)
       WRITE BUFFER mode=0x04 bufID=0xE5 len=2 payload=0x01
       From MrPenguin's H8S/2600 disassembly of XD08U:
         Sets flag @0xA0CE7E = 1, enabling "engineering mode"
         which may bypass the firmware version downgrade check.
       Send BEFORE unlock. Non-fatal if rejected (older firmware
       may not implement this; failure means guard stays active).
       ------------------------------------------------------- */
    if (g_e5eng) {
        UCHAR e5cdb[10] = {0x3B, 0x04, 0xE5, 0, 0, 0, 0, 0x00, 0x02, 0};
        UCHAR e5payload[2] = {0x01, 0x00};
        UCHAR e5sense[SENSE_SIZE] = {0};
        int e5st = 0;
        printf("[E5] Engineering mode enable (WRITE BUFFER 0xE5 len=2 payload=0x01)...\n");
        send_scsi(g_hDrive, e5cdb, 10, e5payload, 2, SCSI_IOCTL_DATA_OUT, e5sense, &e5st);
        if (e5st == 0 || (e5sense[2] & 0x0F) == 0) {
            printf("      OK — engineering mode enabled (version check may be bypassed)\n\n");
        } else {
            printf("      SOFT FAIL sense=%02X/%02X/%02X — drive may not support 0xE5; continuing\n\n",
                   e5sense[2]&0x0F, e5sense[12], e5sense[13]);
        }
        Sleep(50);
    }

    /* -------------------------------------------------------
       STEP 1: UNLOCK TRIGGER
       mode=0x04 bufID=0xFF len=0x100
       Payload: model string at [0x79] + key at [0x89]
       ------------------------------------------------------- */
    if (g_nounlock) {
        printf("[1/5] Unlock trigger SKIPPED (--nounlock — drive already in kernel mode)\n\n");
    } else {
    printf("[1/5] Unlock trigger (mode=0x04 bufID=0xFF)...\n");
    xf_build_trigger(trigger, model, key_le);
    printf("      payload[0x00]='%.16s' key@[0x10]=0x%08X\n", model, key_le);
    st = xf_write_buffer(0x04, 0xFF, 0, trigger, 0x100, "unlock_trigger");
    if (st != 0) {
        fprintf(stderr, "  FAILED: Unlock trigger rejected by drive!\n");
        fprintf(stderr, "  Check that key and model string are correct.\n");
        goto fail;
    }
    printf("      OK\n\n");
    Sleep(200);
    } /* end !g_nounlock */

    if (kernel_size < 0x11200) {
        fprintf(stderr, "  FAILED: kernel file too small (0x%lX < 0x11200)\n", kernel_size);
        goto fail;
    }

    if (g_pre_cutoff) {
        /* =============================================================
           PRE-CUTOFF DRIVE → POST-CUTOFF FW  (upgrade, e.g. pre-1.06)
           Confirmed from Joni's 1.04→1.06 pcapng:
             [2] Normal prefix:  F0, 0x1D6600 bytes
             [3] Kernel:         FE, NAND-mapped 4 transfers
             [4] Normal full:    F0, full normal_size bytes
             [5] Commit immediately
           ============================================================= */

        /* [2] Normal firmware prefix */
        {
            DWORD prefix_size = (normal_size > 0x1D6600) ? 0x1D6600 : normal_size;
            DWORD chunk_sz = 0x8000, chunk_num = 0, offset;
            DWORD total_chunks = (prefix_size + chunk_sz - 1) / chunk_sz;
            printf("[2/5] Normal firmware prefix (%lu bytes = 0x%lX, %lu chunks)...\n",
                   prefix_size, prefix_size, total_chunks);
            for (offset = 0; offset < prefix_size; offset += chunk_sz) {
                DWORD this_sz = prefix_size - offset;
                if (this_sz > chunk_sz) this_sz = chunk_sz;
                chunk_num++;
                if (chunk_num == 1 || chunk_num == total_chunks || (chunk_num % 16) == 0) {
                    printf("    chunk %lu/%lu  offset=0x%06lX\r", chunk_num, total_chunks, offset);
                    fflush(stdout);
                }
                { char desc[64]; snprintf(desc, sizeof(desc), "nfw_pfx@0x%06lX", offset);
                  st = xf_write_buffer(0x07, 0xF0, offset, normal_data + offset, this_sz, desc); }
                if (st != 0) { printf("\n"); goto fail; }
                Sleep(50);
            }
            printf("\n    Normal prefix done.\n\n");
        }
        Sleep(200);

        /* [3] Kernel — upgrade era, confirmed from Joni's ID05 capture (8D31/ID05).
               File layout (flat binary, NOT KernelFront):
                 file[0x000000:0x000200]  ASCII header  (transformation unknown; try plain)
                 file[0x000200:0x008200]  body1  (32 KiB)
                 file[0x008200:0x010200]  body2  (32 KiB)
                 file[0x010200:0x011200]  tail   (4 KiB)
               4-transfer layout confirmed by CDB analysis:
                 hdr:   3B 07 FE 00 00 00 00 02 00 ...  NAND 0x000000 len=0x0200
                 body1: 3B 07 FE 00 12 00 00 80 00 ...  NAND 0x001200 len=0x8000
                 body2: 3B 07 FE 00 92 00 00 80 00 ...  NAND 0x009200 len=0x8000
                 tail:  3B 07 FE 01 12 00 00 10 00 ...  NAND 0x011200 len=0x1000
               body1/body2/tail SHA-256 verified against ID05 Wireshark capture.
               Header: updater sends a transformed 0x200 bytes (session-specific?),
               but drive accepts the plain ASCII header from the file unchanged.
               Confirmed working: plain header → SCSI GOOD → commit GOOD. */
        printf("[3/5] Kernel transfer (4-xfer upgrade layout, ID05 confirmed)...\n");
        {
            SHA256_CTX sha_ctx; UCHAR sha_digest[32]; int sha_i;
            sha256_init(&sha_ctx);
            sha256_update(&sha_ctx, kernel_data + 0x000000, 0x0200);  /* hdr   file[0x0000] */
            sha256_update(&sha_ctx, kernel_data + 0x000200, 0x8000);  /* body1 file[0x0200] */
            sha256_update(&sha_ctx, kernel_data + 0x008200, 0x8000);  /* body2 file[0x8200] */
            sha256_update(&sha_ctx, kernel_data + 0x010200, 0x1000);  /* tail  file[0x10200] */
            sha256_final(&sha_ctx, sha_digest);
            printf("      SHA-256 (hdr+body1+body2+tail as sent):\n        ");
            for (sha_i=0; sha_i<32; sha_i++) printf("%02x", sha_digest[sha_i]);
            printf("\n\n");
        }
        printf("      hdr:   FE off=0x000000 len=0x0200 (file[0x000000] — plain header)\n");
        st = xf_write_buffer(0x07, 0xFE, 0x000000, kernel_data + 0x000000, 0x0200, "kernel_hdr");
        if (st != 0) goto fail; Sleep(2);
        printf("      body1: FE off=0x001200 len=0x8000 (file[0x000200])\n");
        st = xf_write_buffer(0x07, 0xFE, 0x001200, kernel_data + 0x000200, 0x8000, "kernel_body1");
        if (st != 0) goto fail; Sleep(2);
        printf("      body2: FE off=0x009200 len=0x8000 (file[0x008200])\n");
        st = xf_write_buffer(0x07, 0xFE, 0x009200, kernel_data + 0x008200, 0x8000, "kernel_body2");
        if (st != 0) goto fail; Sleep(2);
        printf("      tail:  FE off=0x011200 len=0x1000 (file[0x010200])\n");
        st = xf_write_buffer(0x07, 0xFE, 0x011200, kernel_data + 0x010200, 0x1000, "kernel_tail");
        if (st != 0) goto fail;
        printf("      OK\n\n");
        Sleep(200);

        /* [4] Normal firmware full upload */
        {
            DWORD chunk_sz = 0x8000, chunk_num = 0, offset;
            DWORD total_chunks = (normal_size + chunk_sz - 1) / chunk_sz;
            printf("[4/5] Normal firmware full upload (%lu bytes = 0x%lX, %lu chunks)...\n",
                   normal_size, normal_size, total_chunks);
            for (offset = 0; offset < normal_size; offset += chunk_sz) {
                DWORD this_sz = normal_size - offset;
                if (this_sz > chunk_sz) this_sz = chunk_sz;
                chunk_num++;
                if (chunk_num == 1 || chunk_num == total_chunks || (chunk_num % 16) == 0) {
                    printf("    chunk %lu/%lu  offset=0x%06lX\r", chunk_num, total_chunks, offset);
                    fflush(stdout);
                }
                { char desc[64]; snprintf(desc, sizeof(desc), "nfw_full@0x%06lX", offset);
                  st = xf_write_buffer(0x07, 0xF0, offset, normal_data + offset, this_sz, desc); }
                if (st != 0) { printf("\n"); goto fail; }
                Sleep(50);
            }
            printf("\n    Normal full upload done.\n\n");
        }

    } else {
        /* =============================================================
           POST-CUTOFF DRIVE → PRE-CUTOFF FW  (downgrade, --patch)
           Confirmed from Joni's 1.05→1.04 pcapng:
             [2] Kernel:      FE, flat 3-chunk layout
             [3] Normal:      F0, single pass (0x1D6500 bytes)
             [4] (no step)
             [5] Commit immediately
           ============================================================= */

        /* [2] Kernel — flat 3-chunk layout (downgrade era)
               chunk1: FE off=0x000000 len=0x8000
               chunk2: FE off=0x008000 len=0x8000
               chunk3: FE off=0x010000 len=0x1200
               Total: 0x11200 bytes, sent in file order */
        printf("[2/5] Kernel transfer (flat 3-chunk, downgrade layout)...\n");
        {
            SHA256_CTX sha_ctx; UCHAR sha_digest[32]; int sha_i;
            sha256_init(&sha_ctx);
            sha256_update(&sha_ctx, kernel_data + 0x00000, 0x8000);
            sha256_update(&sha_ctx, kernel_data + 0x08000, 0x8000);
            sha256_update(&sha_ctx, kernel_data + 0x10000, 0x1200);
            sha256_final(&sha_ctx, sha_digest);
            printf("      SHA-256 (flat 0x11200 bytes):\n        ");
            for (sha_i=0; sha_i<32; sha_i++) printf("%02x", sha_digest[sha_i]);
            printf("\n\n");
        }
        printf("      chunk1: FE off=0x000000 len=0x8000\n");
        st = xf_write_buffer(0x07, 0xFE, 0x000000, kernel_data + 0x00000, 0x8000, "kernel_c1");
        if (st != 0) goto fail; Sleep(2);
        printf("      chunk2: FE off=0x008000 len=0x8000\n");
        st = xf_write_buffer(0x07, 0xFE, 0x008000, kernel_data + 0x08000, 0x8000, "kernel_c2");
        if (st != 0) goto fail; Sleep(2);
        printf("      chunk3: FE off=0x010000 len=0x1200\n");
        st = xf_write_buffer(0x07, 0xFE, 0x010000, kernel_data + 0x10000, 0x1200, "kernel_c3");
        if (st != 0) goto fail;
        printf("      OK\n\n");
        Sleep(200);

        /* [3] Normal firmware — single pass */
        {
            DWORD chunk_sz = 0x8000, chunk_num = 0, offset;
            DWORD total_chunks = (normal_size + chunk_sz - 1) / chunk_sz;
            printf("[3/5] Normal firmware (%lu bytes = 0x%lX, %lu chunks)...\n",
                   normal_size, normal_size, total_chunks);
            for (offset = 0; offset < normal_size; offset += chunk_sz) {
                DWORD this_sz = normal_size - offset;
                if (this_sz > chunk_sz) this_sz = chunk_sz;
                chunk_num++;
                if (chunk_num == 1 || chunk_num == total_chunks || (chunk_num % 16) == 0) {
                    printf("    chunk %lu/%lu  offset=0x%06lX\r", chunk_num, total_chunks, offset);
                    fflush(stdout);
                }
                { char desc[64]; snprintf(desc, sizeof(desc), "nfw@0x%06lX", offset);
                  st = xf_write_buffer(0x07, 0xF0, offset, normal_data + offset, this_sz, desc); }
                if (st != 0) { printf("\n"); goto fail; }
                Sleep(50);
            }
            printf("\n    Normal firmware done.\n\n");
        }
        printf("[4/5] (no extra pass for downgrade)\n\n");
    }

    /* -------------------------------------------------------
       STEP 5: COMMIT TRIGGER — immediately after last normal transfer
       Joni's capture: commit fires 62.5ms after final firmware chunk.
       The ~13s wait comes AFTER commit GOOD, as the drive reflashes internally.
       mode=0x05 bufID=0xFF len=0x100 — 12-byte CDB required.
       Key = unlock key (confirmed identical in Joni's unlock + commit payloads).
       ------------------------------------------------------- */
    printf("[5/5] Commit trigger (mode=0x05, immediate after firmware)...\n");
    Sleep(100); /* ~62.5ms in Joni's capture; 100ms is safe */
    {
        UCHAR commit_trigger[256];
        DWORD commit_key = key_le;

        if (g_pre_cutoff && target_is_postcut) {
            /* pre→post upgrade: commit key = unlock key (same key_le).
               Confirmed by Joni's pcapng: unlock and commit payloads are identical. */
            printf("      Cross-era (pre→post): commit key = unlock key 0x%08lX\n", commit_key);
        } else if (!g_pre_cutoff && !target_is_postcut && target_kern_id[0]) {
            /* post→pre downgrade: use target (pre-cutoff) kernel key for commit.
               The drive finalizes with the key matching the newly-written firmware era. */
            DWORD tgt_key = pioneer_key_lookup(g_driveID, target_kern_id);
            if (tgt_key) {
                commit_key = tgt_key;
                printf("      Downgrade (post→pre): commit key = target key 0x%08lX (kernelID=%s)\n",
                       commit_key, target_kern_id);
            } else {
                printf("      Downgrade (post→pre): no key for kernelID=%s — falling back to unlock key 0x%08lX\n",
                       target_kern_id, commit_key);
            }
            /* Rebuild commit trigger with target-era key */
            {
                const PIONEER_DRIVE *drv = pioneer_lookup(g_driveID);
                if (drv && drv->model && drv->model[0]) {
                    memset(commit_trigger, 0, 256);
                    memset(commit_trigger, 0x20, 16);
                    strncpy((char*)commit_trigger, drv->model, 16);
                    commit_trigger[0x10] = (UCHAR)(commit_key      );
                    commit_trigger[0x11] = (UCHAR)(commit_key >>  8);
                    commit_trigger[0x12] = (UCHAR)(commit_key >> 16);
                    commit_trigger[0x13] = (UCHAR)(commit_key >> 24);
                    goto commit_trigger_built;
                }
            }
        }
        xf_build_trigger(commit_trigger, model, commit_key);
        commit_trigger_built:;
        printf("      CDB: 3B 05 FF 00 00 00 00 01 00 00 00 00  (12-byte)\n");
        printf("      Payload[0x00]: %.16s  Key@[0x10]: 0x%08lX\n",
               (char*)commit_trigger, commit_key);
        printf("      Payload hex[0x00..0x1F]: ");
        { int _pi; for (_pi=0;_pi<0x20;_pi++) printf("%02X ",commit_trigger[_pi]); printf("\n"); }
        st = xf_write_buffer(0x05, 0xFF, 0x000000, commit_trigger, 0x100, "commit_trigger");
        printf("      Status: %s\n\n", st == 0 ? "GOOD" : "FAIL");
        if (st == 0) {
            printf("      Drive is now performing internal reflash (~13-20s).\n");
            printf("      Wait for drive LED activity to stop before reconnecting.\n\n");
        }
    }

    /* Post-flash capability summary */
    {
        UCHAR after_marker = 0xFF;
        int   after_uhd    = 0;

        /* Generation marker comes from the kernel body */
        if (kernel_size >= 0x11200) {
            UCHAR *plain = (UCHAR*)malloc(0x10000);
            if (plain) {
                /* Scan what we actually sent (already patched + re-encrypted
                   in kernel_data if --patch was used) */
                int dummy_uhd = 0;
                kf_decrypt_body(kernel_data + 0x200, kernel_data + 0x1200, plain);
                scan_kernel_body(plain, 0x10000, &after_marker, &dummy_uhd);
                free(plain);
            }
        }

        /* UHD capability is in the normal firmware body, not the kernel */
        after_uhd = scan_normal_fw_uhd(normal_data, normal_size);

        printf("  After:   Gen: %s (0x%02X)  UHD: %s\n",
               (after_marker == 0x01) ? "New" : "Old",
               after_marker,
               after_uhd ? "Yes" : "No");
        printf("\n");

        if (after_uhd)
            printf("  → Drive is now UHD compatible.\n");
        else
            printf("  → Drive does not have UHD capability in this firmware.\n");
        printf("\n");
    }

    printf("=== CROSSFLASH COMPLETE ===\n\n");
    printf("  Drive is now rebooting with new firmware.\n");
    printf("  Wait 10-15 seconds then reconnect.\n");
    printf("  Verify with: drivekit inquiry E\n\n");
    free(kernel_data);
    free(normal_data);
    return 0;

fail:
    free(kernel_data);
    free(normal_data);
    return st;
}
