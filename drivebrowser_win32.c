/*
 * drivebrowser_win32.c
 * Pioneer BD Drive Database - Native Windows GUI
 *
 * Compile:
 *   cl drivebrowser_win32.c /Fe:drivebrowser.exe /utf-8 ^
 *       user32.lib gdi32.lib comctl32.lib comdlg32.lib shell32.lib ole32.lib winhttp.lib
 *
 * cPix / Razor 1911 (c) 2026
 */

#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#define _WIN32_IE    0x0601
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib,"user32.lib")
#pragma comment(lib,"gdi32.lib")
#pragma comment(lib,"comctl32.lib")
#pragma comment(lib,"comdlg32.lib")
#pragma comment(lib,"shell32.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"winhttp.lib")
#include <winhttp.h>

/* =========================================================
   CONSTANTS
   ========================================================= */
#define MAX_FW      800
#define MAX_COMPAT  300
#define MAX_LINE    512
#define APP_TITLE   "Pioneer BD Drive Database"

#define DLGW 360
#define DLGH 440

/* Control IDs - main window */
#define IDC_SEARCH      101
#define IDC_LIST        102
#define IDC_COMBO_FAM   103
#define IDC_BTN_ADD     104
#define IDC_BTN_EDIT    105
#define IDC_BTN_DEL     106
#define IDC_BTN_SAVE    107
#define IDC_BTN_SCAN    108
#define IDC_DETAIL      109
#define IDC_COMPAT      110
#define IDC_STATUS      111
#define IDC_RADIO_ALL   112
#define IDC_RADIO_LIB   113
#define IDC_RADIO_REC   114
#define IDC_RADIO_POST  115
#define IDC_RADIO_UHD   116
#define IDC_LBL_COMPAT  117
#define IDM_SYNC        200
#define IDM_OPEN_FW     201
#define IDM_OPEN_COMPAT 202
#define IDM_SAVE        203
#define IDM_EXIT        204
#define IDM_ABOUT       205

/* Edit dialog IDs */
#define IDE_MODEL       201
#define IDE_FW          202
#define IDE_DID         203
#define IDE_KERNEL      204
#define IDE_DATE        205
#define IDE_PNAME       206
#define IDE_NOTES       207
#define IDE_XFLASH_TO   208
#define IDC_CHK_LIBRE   209
#define IDC_CHK_REC     210
#define IDC_CHK_POST    211
#define IDC_RAD_UHD_Y   212
#define IDC_RAD_UHD_N   213
#define IDC_RAD_UHD_U   214

/* Column indices */
#define COL_MODEL   0
#define COL_DID     1
#define COL_FW      2
#define COL_KERNEL  3
#define COL_DATE    4
#define COL_PNAME   5
#define COL_FLAGS   6
#define COL_COUNT   7

/* =========================================================
   SUPABASE CONFIG
   ========================================================= */
#define SB_HOST    L"eehuzsmqkqphsrpgxgkh.supabase.co"
#define SB_KEY     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVlaHV6c21xa3FwaHNycGd4Z2toIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg4Njk0NDksImV4cCI6MjEwNDQ0NTQ0OX0.FvD1LHy_3GIYPcKxFu8A8Y8zYXf_QlObvp2F-v3EVPI"
#define SB_KEYW    L"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVlaHV6c21xa3FwaHNycGd4Z2toIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg4Njk0NDksImV4cCI6MjEwNDQ0NTQ0OX0.FvD1LHy_3GIYPcKxFu8A8Y8zYXf_QlObvp2F-v3EVPI"
#define SB_FW_URL  L"/rest/v1/firmwares?select=*&limit=1000&order=model.asc"
#define SB_CO_URL  L"/rest/v1/compat_files?select=*&limit=500"

/* HTTP fetch  -  returns malloc'd buffer, caller must free, sets *len */
static char *http_get(const wchar_t *host, const wchar_t *path, int *len)
{
    HINTERNET hSes=NULL,hCon=NULL,hReq=NULL;
    char *buf=NULL; DWORD sz=0,total=0,read=0;
    wchar_t headers[512];
    *len=0;

    hSes=WinHttpOpen(L"DriveKit/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                     WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!hSes) goto done;
    hCon=WinHttpConnect(hSes,host,INTERNET_DEFAULT_HTTPS_PORT,0);
    if(!hCon) goto done;
    hReq=WinHttpOpenRequest(hCon,L"GET",path,NULL,WINHTTP_NO_REFERER,
                            WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if(!hReq) goto done;

    swprintf(headers,512,
        L"apikey: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json",
        SB_KEYW,SB_KEYW);
    WinHttpAddRequestHeaders(hReq,headers,(DWORD)-1,WINHTTP_ADDREQ_FLAG_ADD);

    if(!WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,
                           WINHTTP_NO_REQUEST_DATA,0,0,0)) goto done;
    if(!WinHttpReceiveResponse(hReq,NULL)) goto done;

    /* Read response */
    buf=(char*)malloc(1); buf[0]=0;
    do {
        sz=0;
        WinHttpQueryDataAvailable(hReq,&sz);
        if(!sz) break;
        buf=(char*)realloc(buf,total+sz+1);
        WinHttpReadData(hReq,buf+total,sz,&read);
        total+=read; buf[total]=0;
    } while(sz>0);
    *len=total;

done:
    if(hReq) WinHttpCloseHandle(hReq);
    if(hCon) WinHttpCloseHandle(hCon);
    if(hSes) WinHttpCloseHandle(hSes);
    return buf;
}

/* =========================================================
   DATA MODEL
   ========================================================= */
typedef struct {
    char model[64];
    char fw[16];
    char checksum[16];
    char drive_id[16];
    char kernel[16];
    char date[16];
    char platform_name[32];
    int  libredrive;
    int  recommended;
    int  post_cutoff;
    int  uhd_capable;   /* -1=unknown 0=no 1=yes */
    char crossflash_to[16];
    char crossflash_notes[256];
    char notes[512];
    int  deleted;
} FwEntry;

typedef struct {
    char filename[128];
    char model[64];
    char version[16];
    char file_type[16];
    char platform[16];
    char platform_id[16];
    char platform_name[32];
    char kernel[16];
    char checksum[16];
} CompatEntry;

static FwEntry     g_fw[MAX_FW];
static int         g_fw_count    = 0;
static CompatEntry g_compat[MAX_COMPAT];
static int         g_compat_count = 0;
static char        g_fw_file[MAX_PATH]     = "drives.json";
static char        g_compat_file[MAX_PATH] = "compatibility.json";
static int         g_dirty = 0;

/* Forward declarations for Supabase functions */
static void supabase_upsert(FwEntry *e);
static void supabase_delete(const char *checksum);

static int  g_view[MAX_FW];
static int  g_nview    = 0;
static int  g_sort_col = COL_MODEL;
static int  g_sort_asc = 1;
static int  g_filter   = 0;
static int  g_edit_idx = -1;

static const unsigned int g_groups[][6] = {
    {0x8231,0x8232,0x8B30,0,0,0},
    {0x8301,0x8600,0x8800,0,0,0},
    {0x8410,0x8510,0x8511,0x8A10,0,0},
    {0x8490,0x8590,0x8591,0,0,0},
    {0x8601,0x8801,0,0,0,0},
    {0x8721,0x8722,0,0,0,0},
    {0x8D30,0x8D31,0,0,0,0},
    {0x8E20,0x8E21,0,0,0,0},
    {0x8F00,0x8F01,0,0,0,0},
    {0x9330,0x9331,0,0,0,0},
    {0,0,0,0,0,0}
};

/* =========================================================
   GLOBALS
   ========================================================= */
static HWND g_hwnd;
static HWND g_hList, g_hSearch, g_hCombo, g_hDetail, g_hCompat;
static HWND g_hStatus;
static HWND g_hRadAll,g_hRadLib,g_hRadRec,g_hRadPost,g_hRadUhd;
static HFONT g_hFont, g_hFontMono, g_hFontBold;
static HINSTANCE g_hInst;
static WNDPROC g_origSearchProc;

/* =========================================================
   JSON HELPERS
   ========================================================= */
static void jstr(const char *ln, const char *key, char *out, int max)
{
    const char *p = strstr(ln,key);
    const char *q;
    int n;
    if(!p) return;
    p = strchr(p,':'); if(!p) return;
    p = strchr(p,'"'); if(!p) return; p++;
    q = strchr(p,'"'); if(!q) return;
    n = (int)(q-p);
    if(n >= max) n = max-1;
    memcpy(out,p,n);
    out[n] = 0;
}

static int jbool(const char *ln, const char *key)
{
    const char *p = strstr(ln,key);
    if(!p) return -1;
    p = strchr(p,':'); if(!p) return -1;
    while(*p==':'||*p==' ') p++;
    if(!strncmp(p,"true",4))  return 1;
    if(!strncmp(p,"false",5)) return 0;
    return -1;
}

static unsigned int hexid(const char *s)
{
    unsigned int v = 0;
    if(!s||!*s) return 0;
    if(s[0]=='0'&&(s[1]=='x'||s[1]=='X')) s += 2;
    sscanf(s,"%x",&v);
    return v;
}

/* =========================================================
   LOAD
   ========================================================= */
static int load_fw(const char *fn)
{
    FILE *fp = fopen(fn,"r");
    char ln[MAX_LINE];
    FwEntry cur;
    int in = 0;
    if(!fp) return 0;
    memset(&cur,0,sizeof(cur)); cur.uhd_capable=-1;
    g_fw_count = 0;
    while(fgets(ln,sizeof(ln),fp) && g_fw_count<MAX_FW) {
        if(strstr(ln,"\"model\"") && !strstr(ln,"firmwares") && !strstr(ln,"source")) {
            if(in && cur.model[0]) g_fw[g_fw_count++] = cur;
            memset(&cur,0,sizeof(cur)); cur.uhd_capable=-1; in=1;
            jstr(ln,"\"model\"",cur.model,sizeof(cur.model));
        } else if(in) {
            if     (strstr(ln,"\"fw\""))             jstr(ln,"\"fw\"",cur.fw,sizeof(cur.fw));
            else if(strstr(ln,"\"checksum\""))       jstr(ln,"\"checksum\"",cur.checksum,sizeof(cur.checksum));
            else if(strstr(ln,"\"drive_id\""))       jstr(ln,"\"drive_id\"",cur.drive_id,sizeof(cur.drive_id));
            else if(strstr(ln,"\"kernel\""))         jstr(ln,"\"kernel\"",cur.kernel,sizeof(cur.kernel));
            else if(strstr(ln,"\"date\""))           jstr(ln,"\"date\"",cur.date,sizeof(cur.date));
            else if(strstr(ln,"\"platform_name\""))  jstr(ln,"\"platform_name\"",cur.platform_name,sizeof(cur.platform_name));
            else if(strstr(ln,"\"crossflash_to\"")&&!strstr(ln,"notes"))
                                                     jstr(ln,"\"crossflash_to\"",cur.crossflash_to,sizeof(cur.crossflash_to));
            else if(strstr(ln,"\"crossflash_notes\""))
                                                     jstr(ln,"\"crossflash_notes\"",cur.crossflash_notes,sizeof(cur.crossflash_notes));
            else if(strstr(ln,"\"notes\"")&&!strstr(ln,"crossflash"))
                                                     jstr(ln,"\"notes\"",cur.notes,sizeof(cur.notes));
            else if(strstr(ln,"\"libredrive\""))     cur.libredrive  = jbool(ln,"\"libredrive\"");
            else if(strstr(ln,"\"recommended\""))    cur.recommended = jbool(ln,"\"recommended\"");
            else if(strstr(ln,"\"post_cutoff\""))    cur.post_cutoff = jbool(ln,"\"post_cutoff\"");
            else if(strstr(ln,"\"uhd_capable\""))    cur.uhd_capable = jbool(ln,"\"uhd_capable\"");
        }
    }
    if(in && cur.model[0] && g_fw_count<MAX_FW) g_fw[g_fw_count++] = cur;
    fclose(fp);
    return g_fw_count;
}

static int load_compat(const char *fn)
{
    FILE *fp = fopen(fn,"r");
    char ln[MAX_LINE];
    CompatEntry cur;
    int in = 0;
    if(!fp) return 0;
    memset(&cur,0,sizeof(cur));
    g_compat_count = 0;
    while(fgets(ln,sizeof(ln),fp) && g_compat_count<MAX_COMPAT) {
        if(strstr(ln,"\"filename\"")) {
            if(in && cur.filename[0]) g_compat[g_compat_count++] = cur;
            memset(&cur,0,sizeof(cur)); in=1;
            jstr(ln,"\"filename\"",cur.filename,sizeof(cur.filename));
        } else if(in) {
            if     (strstr(ln,"\"version\""))       jstr(ln,"\"version\"",cur.version,sizeof(cur.version));
            else if(strstr(ln,"\"model\""))         jstr(ln,"\"model\"",cur.model,sizeof(cur.model));
            else if(strstr(ln,"\"file_type\""))     jstr(ln,"\"file_type\"",cur.file_type,sizeof(cur.file_type));
            else if(strstr(ln,"\"platform_id\""))   jstr(ln,"\"platform_id\"",cur.platform_id,sizeof(cur.platform_id));
            else if(strstr(ln,"\"platform_name\"")) jstr(ln,"\"platform_name\"",cur.platform_name,sizeof(cur.platform_name));
            else if(strstr(ln,"\"kernel\""))        jstr(ln,"\"kernel\"",cur.kernel,sizeof(cur.kernel));
            else if(strstr(ln,"\"checksum\""))      jstr(ln,"\"checksum\"",cur.checksum,sizeof(cur.checksum));
        }
    }
    if(in && cur.filename[0] && g_compat_count<MAX_COMPAT) g_compat[g_compat_count++] = cur;
    fclose(fp);
    return g_compat_count;
}

/* =========================================================
   SAVE
   ========================================================= */
static void save_fw(void)
{
    FILE *fp = fopen(g_fw_file,"w");
    int i, cnt = 0;
    char s[200];
    if(!fp) { MessageBoxA(g_hwnd,"Cannot write drives.json","Error",MB_ICONERROR); return; }
    for(i=0;i<g_fw_count;i++) if(!g_fw[i].deleted) cnt++;
    fprintf(fp,"{\n  \"version\": 1,\n");
    fprintf(fp,"  \"source\": \"LibreDrive firmware list + DriveKit research\",\n");
    fprintf(fp,"  \"count\": %d,\n  \"schema_version\": 3,\n  \"firmwares\": [\n",cnt);
    { int first=1;
      for(i=0;i<g_fw_count;i++) {
        FwEntry *e=&g_fw[i]; if(e->deleted) continue;
        if(!first) fprintf(fp,",\n"); first=0;
        fprintf(fp,"  {\n");
        fprintf(fp,"    \"model\": \"%s\",\n",e->model);
        fprintf(fp,"    \"fw\": \"%s\",\n",e->fw);
        fprintf(fp,"    \"checksum\": \"%s\",\n",e->checksum);
        fprintf(fp,"    \"drive_id\": \"%s\",\n",e->drive_id);
        fprintf(fp,"    \"kernel\": \"%s\",\n",e->kernel);
        fprintf(fp,"    \"date\": \"%s\",\n",e->date);
        fprintf(fp,"    \"platform_name\": \"%s\",\n",e->platform_name);
        fprintf(fp,"    \"libredrive\": %s,\n",e->libredrive?"true":"false");
        fprintf(fp,"    \"recommended\": %s,\n",e->recommended?"true":"false");
        fprintf(fp,"    \"post_cutoff\": %s,\n",e->post_cutoff?"true":"false");
        if(e->uhd_capable<0) fprintf(fp,"    \"uhd_capable\": null,\n");
        else fprintf(fp,"    \"uhd_capable\": %s,\n",e->uhd_capable?"true":"false");
        fprintf(fp,"    \"crossflash_to\": \"%s\",\n",e->crossflash_to);
        fprintf(fp,"    \"crossflash_notes\": \"%s\",\n",e->crossflash_notes);
        fprintf(fp,"    \"notes\": \"%s\"\n",e->notes);
        fprintf(fp,"  }");
      }
    }
    fprintf(fp,"\n  ]\n}\n");
    fclose(fp);
    g_dirty = 0;
    sprintf(s,"Saved %d entries to %s  -  syncing to Supabase...",cnt,g_fw_file);
    SetWindowTextA(g_hStatus,s);
    /* Push all non-deleted entries to Supabase */
    { int i2,pushed=0;
      for(i2=0;i2<g_fw_count;i2++){
          if(!g_fw[i2].deleted) {
              supabase_upsert(&g_fw[i2]);
              pushed++;
          }
      }
      sprintf(s,"Saved %d entries locally + pushed %d to Supabase",cnt,pushed);
      SetWindowTextA(g_hStatus,s);
    }
}

/* =========================================================
   SORT
   ========================================================= */
static int g_sc, g_sa;
static int sortcmp(const void *a, const void *b)
{
    const FwEntry *ea=&g_fw[*(int*)a], *eb=&g_fw[*(int*)b];
    const char *sa="", *sb="";
    switch(g_sc) {
        case COL_MODEL:  sa=ea->model;  sb=eb->model;  break;
        case COL_DID:    sa=ea->drive_id; sb=eb->drive_id; break;
        case COL_FW:     sa=ea->fw;     sb=eb->fw;     break;
        case COL_KERNEL: sa=ea->kernel; sb=eb->kernel; break;
        case COL_DATE:   sa=ea->date;   sb=eb->date;   break;
        case COL_PNAME:  sa=ea->platform_name; sb=eb->platform_name; break;
        default:         sa=ea->model;  sb=eb->model;  break;
    }
    return g_sa ? _stricmp(sa,sb) : _stricmp(sb,sa);
}

/* =========================================================
   POPULATE LISTVIEW
   ========================================================= */
static void populate_list(void)
{
    char query[256]={0}, fam[64]={0}, buf[128], flags[8];
    int i, fi;
    LVITEMA item;

    GetWindowTextA(g_hSearch,query,sizeof(query));
    { int n=(int)strlen(query); while(n>0&&(query[n-1]==' '||query[n-1]=='\r'||query[n-1]=='\n'))query[--n]=0; }
    for(i=0;query[i];i++) query[i]=(char)tolower((unsigned char)query[i]);

    fi = (int)SendMessageA(g_hCombo,CB_GETCURSEL,0,0);
    if(fi>0) SendMessageA(g_hCombo,CB_GETLBTEXT,fi,(LPARAM)fam);

    g_nview = 0;
    for(i=0;i<g_fw_count;i++) {
        FwEntry *e=&g_fw[i];
        if(e->deleted) continue;
        if(query[0]) {
            char lb[512], b[512];
            int k;
            sprintf(b,"%s %s %s %s %s %s",e->model,e->fw,e->drive_id,e->kernel,e->platform_name,e->notes);
            for(k=0;b[k];k++) lb[k]=(char)tolower((unsigned char)b[k]); lb[k]=0;
            if(!strstr(lb,query)) continue;
        }
        if(fam[0]&&strcmp(fam,"All families")!=0)
            if(!strstr(e->platform_name,fam)&&!strstr(e->model,fam)) continue;
        if(g_filter==1&&!e->libredrive)   continue;
        if(g_filter==2&&!e->recommended)  continue;
        if(g_filter==3&&!e->post_cutoff)  continue;
        if(g_filter==4&&e->uhd_capable!=1) continue;
        g_view[g_nview++] = i;
    }

    g_sc=g_sort_col; g_sa=g_sort_asc;
    qsort(g_view,g_nview,sizeof(int),sortcmp);

    SendMessageA(g_hList,WM_SETREDRAW,FALSE,0);
    ListView_DeleteAllItems(g_hList);

    memset(&item,0,sizeof(item));
    for(i=0;i<g_nview;i++) {
        FwEntry *e=&g_fw[g_view[i]];
        item.mask    = LVIF_TEXT|LVIF_PARAM;
        item.iItem   = i;
        item.iSubItem= 0;
        item.pszText = e->model;
        item.lParam  = (LPARAM)g_view[i];
        ListView_InsertItem(g_hList,&item);
        ListView_SetItemText(g_hList,i,COL_DID,   e->drive_id);
        ListView_SetItemText(g_hList,i,COL_FW,    e->fw);
        ListView_SetItemText(g_hList,i,COL_KERNEL, e->kernel);
        ListView_SetItemText(g_hList,i,COL_DATE,   e->date);
        ListView_SetItemText(g_hList,i,COL_PNAME,  e->platform_name);
        flags[0]=0;
        if(e->libredrive)    strcat(flags,"L");
        if(e->recommended)   strcat(flags,"R");
        if(e->post_cutoff)   strcat(flags,"!");
        if(e->uhd_capable==1)strcat(flags,"U");
        ListView_SetItemText(g_hList,i,COL_FLAGS,flags);
    }
    SendMessageA(g_hList,WM_SETREDRAW,TRUE,0);
    InvalidateRect(g_hList,NULL,TRUE);

    { int total=0; for(i=0;i<g_fw_count;i++) if(!g_fw[i].deleted) total++;
      { char fw_short[64]="",co_short[64]="";
        const char *fs=strrchr(g_fw_file,'\\'); strncpy(fw_short,fs?fs+1:g_fw_file,63);
        const char *cs=strrchr(g_compat_file,'\\'); strncpy(co_short,cs?cs+1:g_compat_file,63);
        sprintf(buf,"Total: %d  |  Shown: %d  |  %s%s  |  compat: %s",
                total,g_nview,fw_short,g_dirty?"*":"",co_short);
      }
      SetWindowTextA(g_hStatus,buf); }
}

/* =========================================================
   DETAIL + COMPAT PANEL
   ========================================================= */
static void show_detail(int idx)
{
    FwEntry *e;
    unsigned int did;
    char text[2048]={0}, buf[300];
    int gi, gj, row;

    if(idx<0||idx>=g_fw_count) return;
    e   = &g_fw[idx];
    did = hexid(e->drive_id);

    sprintf(buf,"Model         : %s\r\n",e->model);         strcat(text,buf);
    sprintf(buf,"Drive ID      : %s  (%s)\r\n",e->drive_id,e->platform_name); strcat(text,buf);
    sprintf(buf,"Firmware      : %s\r\n",e->fw);            strcat(text,buf);
    sprintf(buf,"Kernel        : %s\r\n",e->kernel);        strcat(text,buf);
    sprintf(buf,"Date          : %s\r\n",e->date);          strcat(text,buf);
    sprintf(buf,"Checksum      : %s\r\n",e->checksum);      strcat(text,buf);
    strcat(text,"---\r\n");
    sprintf(buf,"LibreDrive    : %s\r\n",e->libredrive?"Yes":"No");  strcat(text,buf);
    sprintf(buf,"Recommended   : %s\r\n",e->recommended?"Yes":"No"); strcat(text,buf);
    sprintf(buf,"Post-cutoff   : %s\r\n",e->post_cutoff?"YES - cannot downgrade!":"No"); strcat(text,buf);
    sprintf(buf,"UHD capable   : %s\r\n",e->uhd_capable<0?"Unknown":e->uhd_capable?"Yes":"No"); strcat(text,buf);
    if(e->crossflash_to[0]) { sprintf(buf,"Crossflash to : %s\r\n",e->crossflash_to); strcat(text,buf); }
    if(e->notes[0])         { strcat(text,"---\r\n"); strncat(text,e->notes,400); strcat(text,"\r\n"); }
    SetWindowTextA(g_hDetail,text);

    ListView_DeleteAllItems(g_hCompat);
    if(!did) return;
    row = 0;
    for(gi=0;g_groups[gi][0];gi++) {
        int found=0;
        for(gj=0;gj<6&&g_groups[gi][gj];gj++) if(g_groups[gi][gj]==did){found=1;break;}
        if(!found) continue;
        for(gj=0;gj<6&&g_groups[gi][gj];gj++) {
            unsigned int cid = g_groups[gi][gj];
            int k;
            if(cid==did) continue;
            for(k=0;k<g_compat_count;k++) {
                LVITEMA it;
                char did_str[16];
                unsigned int kid = hexid(g_compat[k].platform_id);
                if(kid!=cid) continue;
                sprintf(did_str,"0x%04X",cid);
                memset(&it,0,sizeof(it));
                it.mask=LVIF_TEXT; it.iItem=row; it.iSubItem=0;
                it.pszText=g_compat[k].filename;
                ListView_InsertItem(g_hCompat,&it);
                ListView_SetItemText(g_hCompat,row,1,g_compat[k].version);
                ListView_SetItemText(g_hCompat,row,2,g_compat[k].file_type);
                ListView_SetItemText(g_hCompat,row,3,did_str);
                row++;
            }
        }
    }
    if(!row) {
        LVITEMA it; memset(&it,0,sizeof(it));
        it.mask=LVIF_TEXT; it.iItem=0; it.iSubItem=0;
        it.pszText="No compatible files in compatibility.json";
        ListView_InsertItem(g_hCompat,&it);
    }
}

/* =========================================================
   SUPABASE SYNC
   ========================================================= */

/* Extract string value from JSON like "key":"value" */
static void json_val(const char *json, const char *key, char *out, int max)
{
    char search[64]; int n;
    const char *p, *q;
    snprintf(search,sizeof(search),"\"%s\":",key);
    p=strstr(json,search); if(!p) return;
    p+=strlen(search);
    while(*p==' ')p++;
    if(*p=='"') {
        p++;
        q=p;
        while(*q&&!(*q=='"'&&*(q-1)!='\\'))q++;
        n=(int)(q-p); if(n>=max)n=max-1;
        memcpy(out,p,n); out[n]=0;
    } else if(*p=='n'&&!strncmp(p,"null",4)) {
        out[0]=0;
    } else {
        q=p; while(*q&&*q!=','&&*q!='}'&&*q!=']')q++;
        n=(int)(q-p); if(n>=max)n=max-1;
        memcpy(out,p,n); out[n]=0;
    }
}

static int json_bool(const char *json, const char *key)
{
    char search[64], val[16]={0};
    const char *p;
    snprintf(search,sizeof(search),"\"%s\":",key);
    p=strstr(json,search); if(!p) return 0;
    p+=strlen(search);
    while(*p==' ')p++;
    if(!strncmp(p,"true",4))  return 1;
    if(!strncmp(p,"false",5)) return 0;
    return 0;
}

static int sync_from_supabase(void)
{
    char *fw_json=NULL, *co_json=NULL;
    int fw_len=0, co_len=0;
    const char *p, *obj_end;
    int count=0;

    SetWindowTextA(g_hStatus,"Connecting to Supabase...");
    UpdateWindow(g_hwnd);

    fw_json = http_get(SB_HOST, SB_FW_URL, &fw_len);
    if(!fw_json||fw_len<10||fw_json[0]!='[') {
        if(fw_json) free(fw_json);
        MessageBoxA(g_hwnd,
            "Could not connect to the remote database.\n\n"
            "You did not connect to the remote SQL.\n"
            "Choose local files instead using File menu.",
            "No connection",MB_ICONWARNING|MB_OK);
        return 0;
    }

    /* Parse firmware JSON array */
    g_fw_count=0;
    p=fw_json+1; /* skip [ */
    while(*p&&g_fw_count<MAX_FW) {
        FwEntry e; char tmp[16];
        while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r'||*p==',')p++;
        if(*p!='{') break;
        /* find end of this object */
        { int d=0; const char *q=p;
          while(*q){if(*q=='{')d++;else if(*q=='}'){d--;if(!d){obj_end=q+1;break;}}q++;}
        }
        memset(&e,0,sizeof(e)); e.uhd_capable=-1;
        { char obj[2048]={0}; int n=(int)(obj_end-p);
          if(n>=2048)n=2047; memcpy(obj,p,n);
          json_val(obj,"model",e.model,sizeof(e.model));
          json_val(obj,"fw",e.fw,sizeof(e.fw));
          json_val(obj,"checksum",e.checksum,sizeof(e.checksum));
          json_val(obj,"drive_id",e.drive_id,sizeof(e.drive_id));
          json_val(obj,"kernel",e.kernel,sizeof(e.kernel));
          json_val(obj,"date",e.date,sizeof(e.date));
          json_val(obj,"platform_name",e.platform_name,sizeof(e.platform_name));
          json_val(obj,"crossflash_to",e.crossflash_to,sizeof(e.crossflash_to));
          json_val(obj,"crossflash_notes",e.crossflash_notes,sizeof(e.crossflash_notes));
          json_val(obj,"notes",e.notes,sizeof(e.notes));
          e.libredrive  =json_bool(obj,"libredrive");
          e.recommended =json_bool(obj,"recommended");
          e.post_cutoff =json_bool(obj,"post_cutoff");
          json_val(obj,"uhd_capable",tmp,sizeof(tmp));
          if(!strcmp(tmp,"true"))  e.uhd_capable=1;
          else if(!strcmp(tmp,"false")) e.uhd_capable=0;
          if(e.model[0]) g_fw[g_fw_count++]=e;
        }
        p=obj_end; count++;
    }
    free(fw_json);

    /* Parse compat JSON */
    co_json = http_get(SB_HOST, SB_CO_URL, &co_len);
    if(co_json&&co_len>10&&co_json[0]=='[') {
        g_compat_count=0;
        p=co_json+1;
        while(*p&&g_compat_count<MAX_COMPAT) {
            CompatEntry c;
            while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r'||*p==',')p++;
            if(*p!='{') break;
            { int d=0; const char *q=p;
              while(*q){if(*q=='{')d++;else if(*q=='}'){d--;if(!d){obj_end=q+1;break;}}q++;}
            }
            memset(&c,0,sizeof(c));
            { char obj[1024]={0}; int n=(int)(obj_end-p);
              if(n>=1024)n=1023; memcpy(obj,p,n);
              json_val(obj,"filename",c.filename,sizeof(c.filename));
              json_val(obj,"model",c.model,sizeof(c.model));
              json_val(obj,"version",c.version,sizeof(c.version));
              json_val(obj,"file_type",c.file_type,sizeof(c.file_type));
              json_val(obj,"platform",c.platform,sizeof(c.platform));
              json_val(obj,"platform_id",c.platform_id,sizeof(c.platform_id));
              json_val(obj,"platform_name",c.platform_name,sizeof(c.platform_name));
              json_val(obj,"kernel",c.kernel,sizeof(c.kernel));
              json_val(obj,"checksum",c.checksum,sizeof(c.checksum));
              if(c.filename[0]) g_compat[g_compat_count++]=c;
            }
            p=obj_end;
        }
        free(co_json);
    }

    { char s[128]; sprintf(s,"Loaded %d entries from Supabase + %d compat files",
                           g_fw_count,g_compat_count);
      SetWindowTextA(g_hStatus,s); }
    return 1;
}

/* =========================================================
   BUILD FAMILY COMBO
   ========================================================= *//* =========================================================
   BUILD FAMILY COMBO
   ========================================================= */
static void build_combo(void)
{
    char seen[80][32];
    int ns=0, i, j;
    SendMessageA(g_hCombo,CB_RESETCONTENT,0,0);
    SendMessageA(g_hCombo,CB_ADDSTRING,0,(LPARAM)"All families");
    for(i=0;i<g_fw_count;i++) {
        const char *pn=g_fw[i].platform_name;
        if(!pn[0]) continue;
        for(j=0;j<ns;j++) if(!strcmp(seen[j],pn)) break;
        if(j==ns&&ns<80) { strncpy(seen[ns++],pn,31); SendMessageA(g_hCombo,CB_ADDSTRING,0,(LPARAM)pn); }
    }
    SendMessageA(g_hCombo,CB_SETCURSEL,0,0);
}

/* =========================================================
   EDIT DIALOG - simple child window
   ========================================================= */
static HWND g_hEditWnd = NULL;

/* Edit window controls */
static HWND g_eModel, g_eFw, g_eDid, g_eKernel, g_eDate;
static HWND g_ePname, g_eNotes, g_eXto;
static HWND g_eCkLib, g_eCkRec, g_eCkPost;
static HWND g_eUhdY, g_eUhdN, g_eUhdU;
static HWND g_eBtnOK, g_eBtnCancel;
static int  g_edit_result = 0;

#define EW_ID_OK      1
#define EW_ID_CANCEL  2

static LRESULT CALLBACK EditWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch(msg) {
    case WM_COMMAND:
        if(LOWORD(wp)==EW_ID_OK) {
            FwEntry tmp;
            memset(&tmp,0,sizeof(tmp)); tmp.uhd_capable=-1;
            GetWindowTextA(g_eModel,  tmp.model,   sizeof(tmp.model));
            if(!tmp.model[0]){MessageBoxA(h,"Model is required","Error",MB_ICONERROR);break;}
            GetWindowTextA(g_eFw,     tmp.fw,      sizeof(tmp.fw));
            GetWindowTextA(g_eDid,    tmp.drive_id,sizeof(tmp.drive_id));
            GetWindowTextA(g_eKernel, tmp.kernel,  sizeof(tmp.kernel));
            GetWindowTextA(g_eDate,   tmp.date,    sizeof(tmp.date));
            GetWindowTextA(g_ePname,  tmp.platform_name,sizeof(tmp.platform_name));
            GetWindowTextA(g_eNotes,  tmp.notes,   sizeof(tmp.notes));
            GetWindowTextA(g_eXto,    tmp.crossflash_to,sizeof(tmp.crossflash_to));
            tmp.libredrive  = SendMessageA(g_eCkLib, BM_GETCHECK,0,0)==BST_CHECKED;
            tmp.recommended = SendMessageA(g_eCkRec, BM_GETCHECK,0,0)==BST_CHECKED;
            tmp.post_cutoff = SendMessageA(g_eCkPost,BM_GETCHECK,0,0)==BST_CHECKED;
            if(SendMessageA(g_eUhdY,BM_GETCHECK,0,0)==BST_CHECKED) tmp.uhd_capable=1;
            else if(SendMessageA(g_eUhdN,BM_GETCHECK,0,0)==BST_CHECKED) tmp.uhd_capable=0;
            if(g_edit_idx>=0) {
                char ck[16]; memcpy(ck,g_fw[g_edit_idx].checksum,16);
                g_fw[g_edit_idx]=tmp;
                memcpy(g_fw[g_edit_idx].checksum,ck,16);
            } else {
                if(g_fw_count>=MAX_FW){MessageBoxA(h,"Database full","Error",MB_ICONERROR);break;}
                g_fw[g_fw_count++]=tmp;
            }
            g_dirty=1; g_edit_result=1;
            DestroyWindow(h);
        } else if(LOWORD(wp)==EW_ID_CANCEL) {
            g_edit_result=0;
            DestroyWindow(h);
        }
        break;
    case WM_DESTROY:
        g_hEditWnd=NULL;
        break;
    }
    return DefWindowProcA(h,msg,wp,lp);
}

static HWND make_label(HWND p, const char *t, int x, int y, int w, int h)
{
    HWND hw=CreateWindowA("STATIC",t,WS_CHILD|WS_VISIBLE|SS_LEFT,x,y,w,h,p,0,g_hInst,0);
    SendMessageA(hw,WM_SETFONT,(WPARAM)g_hFont,0); return hw;
}
static HWND make_edit(HWND p, int id, int x, int y, int w, int h, int ml)
{
    DWORD sty=WS_CHILD|WS_VISIBLE|WS_BORDER|WS_TABSTOP|ES_AUTOHSCROLL|(ml?(ES_MULTILINE|WS_VSCROLL):0);
    HWND hw=CreateWindowA("EDIT","",sty,x,y,w,h,p,(HMENU)(UINT_PTR)id,g_hInst,0);
    SendMessageA(hw,WM_SETFONT,(WPARAM)g_hFont,0); return hw;
}
static HWND make_check(HWND p, const char *t, int id, int x, int y, int w, int h)
{
    HWND hw=CreateWindowA("BUTTON",t,WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX|WS_TABSTOP,x,y,w,h,p,(HMENU)(UINT_PTR)id,g_hInst,0);
    SendMessageA(hw,WM_SETFONT,(WPARAM)g_hFont,0); return hw;
}
static HWND make_radio(HWND p, const char *t, int id, int x, int y, int w, int h, int grp)
{
    DWORD sty=WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_TABSTOP|(grp?WS_GROUP:0);
    HWND hw=CreateWindowA("BUTTON",t,sty,x,y,w,h,p,(HMENU)(UINT_PTR)id,g_hInst,0);
    SendMessageA(hw,WM_SETFONT,(WPARAM)g_hFont,0); return hw;
}
static HWND make_button(HWND p, const char *t, int id, int x, int y, int w, int h)
{
    HWND hw=CreateWindowA("BUTTON",t,WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,x,y,w,h,p,(HMENU)(UINT_PTR)id,g_hInst,0);
    SendMessageA(hw,WM_SETFONT,(WPARAM)g_hFont,0); return hw;
}

/* =========================================================
   SUPABASE WRITE FUNCTIONS
   ========================================================= */
static int http_post(const wchar_t *path, const char *method, const char *body)
{
    HINTERNET hSes=NULL,hCon=NULL,hReq=NULL;
    wchar_t headers[1024];
    wchar_t wmethod[16];
    int ok=0;
    hSes=WinHttpOpen(L"DriveKit/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                     WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!hSes) goto done;
    hCon=WinHttpConnect(hSes,SB_HOST,INTERNET_DEFAULT_HTTPS_PORT,0);
    if(!hCon) goto done;
    MultiByteToWideChar(CP_ACP,0,method,-1,wmethod,16);
    hReq=WinHttpOpenRequest(hCon,wmethod,path,NULL,WINHTTP_NO_REFERER,
                            WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if(!hReq) goto done;
    swprintf(headers,1024,
        L"apikey: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nPrefer: resolution=merge-duplicates,return=minimal",
        SB_KEYW,SB_KEYW);
    WinHttpAddRequestHeaders(hReq,headers,(DWORD)-1,WINHTTP_ADDREQ_FLAG_ADD);
    if(!WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,
                           (LPVOID)body,(DWORD)strlen(body),(DWORD)strlen(body),0)) goto done;
    if(!WinHttpReceiveResponse(hReq,NULL)) goto done;
    { DWORD status=0,statusSz=sizeof(DWORD);
      WinHttpQueryHeaders(hReq,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                          NULL,&status,&statusSz,NULL);
      ok=(int)status; }
done:
    if(hReq) WinHttpCloseHandle(hReq);
    if(hCon) WinHttpCloseHandle(hCon);
    if(hSes) WinHttpCloseHandle(hSes);
    return ok;
}

static void esc_json(const char *s, char *buf, int max)
{
    int i=0,j=0;
    while(s[i]&&j<max-2){
        if(s[i]=='"'||s[i]=='\\') buf[j++]='\\';
        buf[j++]=s[i++];
    }
    buf[j]=0;
}

static void supabase_upsert(FwEntry *e)
{
    char body[2048];
    char m[64],fw[16],cs[16],did[16],k[16],dt[16],pn[32],xto[16],xn[256],notes[512];
    const char *uhd=e->uhd_capable<0?"null":e->uhd_capable?"true":"false";
    esc_json(e->model,           m,    sizeof(m));
    esc_json(e->fw,              fw,   sizeof(fw));
    esc_json(e->checksum,        cs,   sizeof(cs));
    esc_json(e->drive_id,        did,  sizeof(did));
    esc_json(e->kernel,          k,    sizeof(k));
    esc_json(e->date,            dt,   sizeof(dt));
    esc_json(e->platform_name,   pn,   sizeof(pn));
    esc_json(e->crossflash_to,   xto,  sizeof(xto));
    esc_json(e->crossflash_notes,xn,   sizeof(xn));
    esc_json(e->notes,           notes,sizeof(notes));
    snprintf(body,sizeof(body),
        "{\"model\":\"%s\",\"fw\":\"%s\",\"checksum\":\"%s\","
        "\"drive_id\":\"%s\",\"kernel\":\"%s\",\"date\":\"%s\","
        "\"platform_name\":\"%s\",\"libredrive\":%s,\"recommended\":%s,"
        "\"post_cutoff\":%s,\"uhd_capable\":%s,"
        "\"crossflash_to\":\"%s\",\"crossflash_notes\":\"%s\",\"notes\":\"%s\"}",
        m,fw,cs,did,k,dt,pn,
        e->libredrive?"true":"false",
        e->recommended?"true":"false",
        e->post_cutoff?"true":"false",
        uhd,xto,xn,notes);
    { int r=http_post(L"/rest/v1/firmwares?on_conflict=checksum","POST",body);
      char s[128]; 
      if(r>=200&&r<300) sprintf(s,"Saved to Supabase! (HTTP %d)",r);
      else sprintf(s,"Supabase failed (HTTP %d) - saved locally only",r);
      SetWindowTextA(g_hStatus,s); }
}

static void supabase_delete(const char *checksum)
{
    wchar_t path[256];
    char cs[32];
    esc_json(checksum,cs,sizeof(cs));
    swprintf(path,256,L"/rest/v1/firmwares?checksum=eq.%S",cs);
    http_post(path,"DELETE","");
}

static void do_edit(int fw_idx)
{
    WNDCLASSEXA wc;
    FwEntry *e;
    int row=10,gap=26,lw=90,ew=240,lx=8,ex=100;
    MSG m;

    g_edit_idx=fw_idx;
    g_edit_result=0;

    /* Register edit window class */
    memset(&wc,0,sizeof(wc));
    wc.cbSize=sizeof(wc);
    wc.lpfnWndProc=EditWndProc;
    wc.hInstance=g_hInst;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszClassName="DriveEditWnd";
    wc.hIcon=LoadIcon(NULL,IDI_APPLICATION);
    RegisterClassExA(&wc);

    g_hEditWnd=CreateWindowExA(WS_EX_DLGMODALFRAME,"DriveEditWnd",
        fw_idx>=0?"Edit Entry":"Add Entry",
        WS_POPUP|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
        0,0,360,440,g_hwnd,NULL,g_hInst,NULL);

    /* Centre over parent */
    { RECT pr,wr; GetWindowRect(g_hwnd,&pr); GetWindowRect(g_hEditWnd,&wr);
      int pw=pr.right-pr.left, ph=pr.bottom-pr.top;
      int ww=wr.right-wr.left, wh=wr.bottom-wr.top;
      SetWindowPos(g_hEditWnd,NULL,pr.left+(pw-ww)/2,pr.top+(ph-wh)/2,0,0,SWP_NOSIZE|SWP_NOZORDER); }

    /* Create controls */
    make_label(g_hEditWnd,"Model *",    lx,row,lw,18);
    g_eModel =make_edit(g_hEditWnd,IDE_MODEL,   ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Firmware",   lx,row,lw,18);
    g_eFw    =make_edit(g_hEditWnd,IDE_FW,      ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Drive ID",   lx,row,lw,18);
    g_eDid   =make_edit(g_hEditWnd,IDE_DID,     ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Kernel",     lx,row,lw,18);
    g_eKernel=make_edit(g_hEditWnd,IDE_KERNEL,  ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Date",       lx,row,lw,18);
    g_eDate  =make_edit(g_hEditWnd,IDE_DATE,    ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Platform",   lx,row,lw,18);
    g_ePname =make_edit(g_hEditWnd,IDE_PNAME,   ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Xflash to",  lx,row,lw,18);
    g_eXto   =make_edit(g_hEditWnd,IDE_XFLASH_TO,ex,row,ew,20,0); row+=gap;
    make_label(g_hEditWnd,"Notes",      lx,row,lw,18);
    g_eNotes =make_edit(g_hEditWnd,IDE_NOTES,   ex,row,ew,56,1); row+=62;

    g_eCkLib =make_check(g_hEditWnd,"LibreDrive", IDC_CHK_LIBRE,lx, row,90,18);
    g_eCkRec =make_check(g_hEditWnd,"Recommended",IDC_CHK_REC,  104,row,100,18);
    g_eCkPost=make_check(g_hEditWnd,"Post-cutoff", IDC_CHK_POST,210,row,100,18); row+=24;

    make_label(g_hEditWnd,"UHD:",lx,row,35,18);
    g_eUhdY=make_radio(g_hEditWnd,"Yes",    IDC_RAD_UHD_Y,48, row,46,18,1);
    g_eUhdN=make_radio(g_hEditWnd,"No",     IDC_RAD_UHD_N,98, row,40,18,0);
    g_eUhdU=make_radio(g_hEditWnd,"Unknown",IDC_RAD_UHD_U,142,row,70,18,0); row+=30;

    g_eBtnOK    =make_button(g_hEditWnd,"OK",    EW_ID_OK,    200,row,70,24);
    g_eBtnCancel=make_button(g_hEditWnd,"Cancel",EW_ID_CANCEL,278,row,70,24);

    /* Populate fields if editing */
    e=(fw_idx>=0)?&g_fw[fw_idx]:NULL;
    if(e) {
        SetWindowTextA(g_eModel,  e->model);
        SetWindowTextA(g_eFw,     e->fw);
        SetWindowTextA(g_eDid,    e->drive_id);
        SetWindowTextA(g_eKernel, e->kernel);
        SetWindowTextA(g_eDate,   e->date);
        SetWindowTextA(g_ePname,  e->platform_name);
        SetWindowTextA(g_eNotes,  e->notes);
        SetWindowTextA(g_eXto,    e->crossflash_to);
        SendMessageA(g_eCkLib, BM_SETCHECK,e->libredrive ?BST_CHECKED:BST_UNCHECKED,0);
        SendMessageA(g_eCkRec, BM_SETCHECK,e->recommended?BST_CHECKED:BST_UNCHECKED,0);
        SendMessageA(g_eCkPost,BM_SETCHECK,e->post_cutoff?BST_CHECKED:BST_UNCHECKED,0);
        SendMessageA(e->uhd_capable==1?g_eUhdY:e->uhd_capable==0?g_eUhdN:g_eUhdU,
                     BM_SETCHECK,BST_CHECKED,0);
    } else {
        SendMessageA(g_eUhdU,BM_SETCHECK,BST_CHECKED,0);
    }

    SetFocus(g_eModel);

    /* Modal message loop */
    EnableWindow(g_hwnd,FALSE);
    while(g_hEditWnd&&GetMessageA(&m,NULL,0,0)) {
        if(!IsDialogMessageA(g_hEditWnd,&m)) {
            TranslateMessage(&m);
            DispatchMessageA(&m);
        }
    }
    EnableWindow(g_hwnd,TRUE);
    SetForegroundWindow(g_hwnd);

    if(g_edit_result) {
        build_combo(); populate_list();
        { FwEntry *e2=(g_edit_idx>=0)?&g_fw[g_edit_idx]:&g_fw[g_fw_count-1];
          supabase_upsert(e2); }
    }

    UnregisterClassA("DriveEditWnd",g_hInst);
}

/* =========================================================
   SEARCH SUBCLASS
   ========================================================= */
static LRESULT CALLBACK SearchSubclass(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    if(msg==WM_KEYUP) populate_list();
    return CallWindowProcA(g_origSearchProc,h,msg,wp,lp);
}

/* =========================================================
   SCAN FOLDER
   ========================================================= */
static void scan_folder(void)
{
    char folder[MAX_PATH]="";
    char pat[MAX_PATH], fpath[MAX_PATH], msg[128];
    WIN32_FIND_DATAA fd;
    HANDLE hf;
    BROWSEINFOA bi;
    LPITEMIDLIST pid;
    int added=0, skipped=0;

    memset(&bi,0,sizeof(bi));
    bi.hwndOwner = g_hwnd;
    bi.lpszTitle = "Select firmware folder";
    bi.ulFlags   = BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    pid = SHBrowseForFolderA(&bi);
    if(!pid) return;
    SHGetPathFromIDListA(pid,folder);
    CoTaskMemFree(pid);

    sprintf(pat,"%s\\*",folder);
    hf = FindFirstFileA(pat,&fd);
    if(hf==INVALID_HANDLE_VALUE) { MessageBoxA(g_hwnd,"Cannot open folder","Error",MB_ICONERROR); return; }

    do {
        FILE *fp;
        unsigned char hdr[512];
        int hn, dup=0, k;
        CompatEntry ce;

        if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) continue;
        sprintf(fpath,"%s\\%s",folder,fd.cFileName);
        fp = fopen(fpath,"rb"); if(!fp) continue;
        hn = (int)fread(hdr,1,sizeof(hdr),fp); fclose(fp);
        if(hn<16||hdr[0]!='*') continue;

        for(k=0;k<g_compat_count;k++) if(!strcmp(g_compat[k].filename,fd.cFileName)){dup=1;break;}
        if(dup){skipped++;continue;}
        if(g_compat_count>=MAX_COMPAT) break;

        memset(&ce,0,sizeof(ce));
        strncpy(ce.filename,fd.cFileName,sizeof(ce.filename)-1);
        {
            char hs[600]={0}; int j,k2=0;
            for(j=0;j<hn&&hdr[j]!=0x1A&&k2<599;j++)
                if(hdr[j]>=0x20||hdr[j]=='\r'||hdr[j]=='\n') hs[k2++]=(char)hdr[j];
            #define HG(tag,f) {char *pp=strstr(hs,tag);if(pp){char *q;pp+=strlen(tag);while(*pp==' ')pp++;q=pp;while(*q&&*q!='\r'&&*q!='\n')q++;while(q>pp&&*(q-1)==' ')q--;{int n=(int)(q-pp);if(n>0&&n<(int)sizeof(f)){memcpy(f,pp,n);f[n]=0;}}}}
            HG("ID : ",            ce.model);
            HG("Revision Level : ",ce.version);
            HG("Hardware Version : ",ce.platform);
            HG("Kernel Version : ", ce.kernel);
            HG("File Type : ",      ce.file_type);
            #undef HG
        }
        if(ce.platform[0]) {
            const char *pp=ce.platform;
            while(*pp) {
                if(((pp[0]>='0'&&pp[0]<='9')||(pp[0]>='A'&&pp[0]<='F'))&&
                   ((pp[1]>='0'&&pp[1]<='9')||(pp[1]>='A'&&pp[1]<='F'))&&
                   ((pp[2]>='0'&&pp[2]<='9')||(pp[2]>='A'&&pp[2]<='F'))&&
                   ((pp[3]>='0'&&pp[3]<='9')||(pp[3]>='A'&&pp[3]<='F'))) {
                    sprintf(ce.platform_id,"0x%.4s",pp); break;
                }
                pp++;
            }
        }
        g_compat[g_compat_count++] = ce;
        added++;

    } while(FindNextFileA(hf,&fd));
    FindClose(hf);

    if(added>0) {
        FILE *fp = fopen(g_compat_file,"w");
        if(fp) {
            int i;
            fprintf(fp,"{\n  \"version\": 1,\n  \"count\": %d,\n  \"firmware\": [\n",g_compat_count);
            for(i=0;i<g_compat_count;i++) {
                CompatEntry *c=&g_compat[i];
                fprintf(fp,"  {\n");
                fprintf(fp,"    \"filename\": \"%s\",\n",c->filename);
                fprintf(fp,"    \"model\": \"%s\",\n",c->model);
                fprintf(fp,"    \"version\": \"%s\",\n",c->version);
                fprintf(fp,"    \"file_type\": \"%s\",\n",c->file_type);
                fprintf(fp,"    \"platform\": \"%s\",\n",c->platform);
                fprintf(fp,"    \"platform_id\": \"%s\",\n",c->platform_id);
                fprintf(fp,"    \"kernel\": \"%s\",\n",c->kernel);
                fprintf(fp,"    \"checksum\": \"%s\"\n",c->checksum);
                fprintf(fp,"  }%s\n",i<g_compat_count-1?",":"");
            }
            fprintf(fp,"  ]\n}\n");
            fclose(fp);
        }
    }
    sprintf(msg,"Scan: %d new, %d already known",added,skipped);
    MessageBoxA(g_hwnd,msg,"Scan complete",MB_OK|MB_ICONINFORMATION);
    SetWindowTextA(g_hStatus,msg);
}

/* =========================================================
   CREATE LISTVIEW COLUMNS
   ========================================================= */
static void create_columns(HWND lv)
{
    LVCOLUMNA col;
    int i;
    struct { char *t; int w; } cols[COL_COUNT] = {
        {"Model",200},{"Drive ID",75},{"Version",65},
        {"Kernel",60},{"Date",80},{"Platform",90},{"Flags",46}
    };
    memset(&col,0,sizeof(col));
    col.mask = LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
    for(i=0;i<COL_COUNT;i++) {
        col.iSubItem=i; col.pszText=cols[i].t; col.cx=cols[i].w;
        ListView_InsertColumn(lv,i,&col);
    }
}

/* =========================================================
   MAIN WINDOW PROCEDURE
   ========================================================= */

/* =========================================================
   OPEN FILE DIALOGS
   ========================================================= */
static void open_fw_file(void)
{
    OPENFILENAMEA ofn;
    char path[MAX_PATH]="";
    memset(&ofn,0,sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = "Open drives.json";
    ofn.Flags       = OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(GetOpenFileNameA(&ofn)) {
        strncpy(g_fw_file,path,MAX_PATH-1);
        g_fw_count = 0;
        load_fw(g_fw_file);
        build_combo();
        populate_list();
        { char t[128]; sprintf(t,"%s   -   %d entries",APP_TITLE,g_fw_count);
          SetWindowTextA(g_hwnd,t); }
    }
}

static void open_compat_file(void)
{
    OPENFILENAMEA ofn;
    char path[MAX_PATH]="";
    memset(&ofn,0,sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hwnd;
    ofn.lpstrFilter = "JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = path;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = "Open compatibility.json";
    ofn.Flags       = OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST;
    if(GetOpenFileNameA(&ofn)) {
        strncpy(g_compat_file,path,MAX_PATH-1);
        g_compat_count = 0;
        load_compat(g_compat_file);
        populate_list();
        { char s[200]; sprintf(s,"Loaded %d compatibility entries from %s",g_compat_count,g_compat_file);
          SetWindowTextA(g_hStatus,s); }
    }
}

static HMENU build_menu(void)
{
    HMENU hMenu  = CreateMenu();
    HMENU hFile  = CreatePopupMenu();
    AppendMenuA(hFile,MF_STRING,IDM_SYNC,       "Sync from Supabase");
    AppendMenuA(hFile,MF_SEPARATOR,0,NULL);
    AppendMenuA(hFile,MF_STRING,IDM_OPEN_FW,    "Open local drives.json...");
    AppendMenuA(hFile,MF_STRING,IDM_OPEN_COMPAT,"Open local compatibility.json...");
    AppendMenuA(hFile,MF_SEPARATOR,0,NULL);
    AppendMenuA(hFile,MF_STRING,IDM_SAVE,       "Save drives.json");
    AppendMenuA(hFile,MF_SEPARATOR,0,NULL);
    AppendMenuA(hFile,MF_STRING,IDM_EXIT,       "Exit");
    AppendMenuA(hMenu,MF_POPUP,(UINT_PTR)hFile, "File");
    HMENU hHelp = CreatePopupMenu();
    AppendMenuA(hHelp,MF_STRING,IDM_ABOUT,"About DriveBrowser...");
    AppendMenuA(hMenu,MF_POPUP,(UINT_PTR)hHelp,"Help");
    return hMenu;
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch(msg) {
    case WM_CREATE: {
        int k;
        HWND lbl, b;
        LVCOLUMNA cc;
        struct { char *t; int id; } btns[] = {
            {"Add",IDC_BTN_ADD},{"Edit",IDC_BTN_EDIT},{"Delete",IDC_BTN_DEL},
            {"Save",IDC_BTN_SAVE},{"Scan folder",IDC_BTN_SCAN}
        };
        HWND rbs[5];
        int bx;

        g_hFont     = CreateFontA(15,0,0,0,400,0,0,0,ANSI_CHARSET,0,0,0,0,"Segoe UI");
        g_hFontBold = CreateFontA(15,0,0,0,700,0,0,0,ANSI_CHARSET,0,0,0,0,"Segoe UI");
        g_hFontMono = CreateFontA(14,0,0,0,400,0,0,0,ANSI_CHARSET,0,0,0,0,"Consolas");

        /* Search row */
        lbl = CreateWindowA("STATIC","Search:",WS_CHILD|WS_VISIBLE,6,8,50,18,hwnd,0,0,0);
        SendMessageA(lbl,WM_SETFONT,(WPARAM)g_hFont,0);
        g_hSearch = CreateWindowA("EDIT","",WS_CHILD|WS_VISIBLE|WS_BORDER|ES_AUTOHSCROLL,
                                   58,6,220,22,hwnd,(HMENU)IDC_SEARCH,0,0);
        SendMessageA(g_hSearch,WM_SETFONT,(WPARAM)g_hFont,0);
        g_origSearchProc = (WNDPROC)SetWindowLongPtrA(g_hSearch,GWLP_WNDPROC,(LONG_PTR)SearchSubclass);

        lbl = CreateWindowA("STATIC","Family:",WS_CHILD|WS_VISIBLE,286,8,46,18,hwnd,0,0,0);
        SendMessageA(lbl,WM_SETFONT,(WPARAM)g_hFont,0);
        g_hCombo = CreateWindowA("COMBOBOX","",WS_CHILD|WS_VISIBLE|CBS_DROPDOWNLIST|WS_VSCROLL,
                                  334,5,160,220,hwnd,(HMENU)IDC_COMBO_FAM,0,0);
        SendMessageA(g_hCombo,WM_SETFONT,(WPARAM)g_hFont,0);

        /* Filter radio buttons */
        g_hRadAll  = CreateWindowA("BUTTON","All",      WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON|WS_GROUP|WS_TABSTOP,6,33,40,16,hwnd,(HMENU)IDC_RADIO_ALL,0,0);
        g_hRadLib  = CreateWindowA("BUTTON","LibreDrive",WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,50,33,80,16,hwnd,(HMENU)IDC_RADIO_LIB,0,0);
        g_hRadRec  = CreateWindowA("BUTTON","Recommended",WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,134,33,100,16,hwnd,(HMENU)IDC_RADIO_REC,0,0);
        g_hRadPost = CreateWindowA("BUTTON","Post-cutoff",WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,238,33,90,16,hwnd,(HMENU)IDC_RADIO_POST,0,0);
        g_hRadUhd  = CreateWindowA("BUTTON","UHD",       WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,332,33,50,16,hwnd,(HMENU)IDC_RADIO_UHD,0,0);
        SendMessageA(g_hRadAll,BM_SETCHECK,BST_CHECKED,0);
        rbs[0]=g_hRadAll; rbs[1]=g_hRadLib; rbs[2]=g_hRadRec; rbs[3]=g_hRadPost; rbs[4]=g_hRadUhd;
        for(k=0;k<5;k++) SendMessageA(rbs[k],WM_SETFONT,(WPARAM)g_hFont,0);

        /* Main ListView */
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE,"SysListView32","",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS|WS_TABSTOP,
            6,54,770,280,hwnd,(HMENU)IDC_LIST,g_hInst,0);
        SendMessageA(g_hList,WM_SETFONT,(WPARAM)g_hFontMono,0);
        ListView_SetExtendedListViewStyle(g_hList,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES|LVS_EX_HEADERDRAGDROP);
        create_columns(g_hList);

        /* Buttons */
        bx = 6;
        for(k=0;k<5;k++) {
            int bw = (k==4) ? 110 : 80;
            b = CreateWindowA("BUTTON",btns[k].t,WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON|WS_TABSTOP,
                               bx,340,bw,24,hwnd,(HMENU)(UINT_PTR)btns[k].id,0,0);
            SendMessageA(b,WM_SETFONT,(WPARAM)g_hFont,0);
            bx += bw + 6;
        }

        /* Detail panel */
        lbl = CreateWindowA("STATIC","Entry details:",WS_CHILD|WS_VISIBLE,6,372,120,16,hwnd,0,0,0);
        SendMessageA(lbl,WM_SETFONT,(WPARAM)g_hFontBold,0);
        g_hDetail = CreateWindowExA(WS_EX_CLIENTEDGE,"EDIT","",
            WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY|WS_VSCROLL|ES_AUTOVSCROLL,
            6,390,390,170,hwnd,(HMENU)IDC_DETAIL,0,0);
        SendMessageA(g_hDetail,WM_SETFONT,(WPARAM)g_hFontMono,0);

        /* Compatible files panel */
        lbl = CreateWindowA("STATIC","Compatible firmware (same crossflash group):",WS_CHILD|WS_VISIBLE,
                             400,372,380,16,hwnd,(HMENU)IDC_LBL_COMPAT,0,0);
        SendMessageA(lbl,WM_SETFONT,(WPARAM)g_hFontBold,0);
        g_hCompat = CreateWindowExA(WS_EX_CLIENTEDGE,"SysListView32","",
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SHOWSELALWAYS,
            400,390,382,170,hwnd,(HMENU)IDC_COMPAT,g_hInst,0);
        SendMessageA(g_hCompat,WM_SETFONT,(WPARAM)g_hFontMono,0);
        ListView_SetExtendedListViewStyle(g_hCompat,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        memset(&cc,0,sizeof(cc));
        cc.mask=LVCF_TEXT|LVCF_WIDTH|LVCF_SUBITEM;
        { struct{char *t;int w;}c2[]={"Filename",160,"Version",56,"Type",54,"Drive ID",60};
          for(k=0;k<4;k++){cc.iSubItem=k;cc.pszText=c2[k].t;cc.cx=c2[k].w;ListView_InsertColumn(g_hCompat,k,&cc);} }

        /* Status bar */
        g_hStatus = CreateWindowA("msctls_statusbar32","",WS_CHILD|WS_VISIBLE,0,0,0,0,hwnd,(HMENU)IDC_STATUS,g_hInst,0);
        SendMessageA(g_hStatus,WM_SETFONT,(WPARAM)g_hFont,0);

        build_combo();
        populate_list();
        break;
    }

    case WM_SIZE: {
        int W=LOWORD(lp), H=HIWORD(lp);
        int half;
        if(!g_hList) break;
        half = (W-16)/2;
        SetWindowPos(g_hList,  0, 6,54,W-12,280,SWP_NOZORDER);
        SetWindowPos(g_hDetail,0, 6,390,half,H-410,SWP_NOZORDER);
        SetWindowPos(g_hCompat,0, half+10,390,W-half-16,H-410,SWP_NOZORDER);
        SetWindowPos(GetDlgItem(hwnd,IDC_LBL_COMPAT),0,half+10,372,W-half-16,16,SWP_NOZORDER);
        SendMessageA(g_hStatus,WM_SIZE,0,0);
        break;
    }

    case WM_COMMAND:
        switch(LOWORD(wp)) {
        case IDC_COMBO_FAM:
            if(HIWORD(wp)==CBN_SELCHANGE) populate_list();
            break;
        case IDC_RADIO_ALL:  g_filter=0; populate_list(); break;
        case IDC_RADIO_LIB:  g_filter=1; populate_list(); break;
        case IDC_RADIO_REC:  g_filter=2; populate_list(); break;
        case IDC_RADIO_POST: g_filter=3; populate_list(); break;
        case IDC_RADIO_UHD:  g_filter=4; populate_list(); break;
        case IDC_BTN_ADD:
            do_edit(-1);
            break;
        case IDC_BTN_EDIT: {
            int sel = ListView_GetNextItem(g_hList,-1,LVNI_SELECTED);
            LVITEMA it;
            if(sel<0){MessageBoxA(hwnd,"Select an entry first","Edit",MB_ICONINFORMATION);break;}
            memset(&it,0,sizeof(it)); it.mask=LVIF_PARAM; it.iItem=sel;
            ListView_GetItem(g_hList,&it);
            do_edit((int)it.lParam);
            break;
        }
        case IDC_BTN_DEL: {
            int sel = ListView_GetNextItem(g_hList,-1,LVNI_SELECTED);
            LVITEMA it;
            char m[128];
            if(sel<0){MessageBoxA(hwnd,"Select an entry first","Delete",MB_ICONINFORMATION);break;}
            memset(&it,0,sizeof(it)); it.mask=LVIF_PARAM; it.iItem=sel;
            ListView_GetItem(g_hList,&it);
            { int idx=(int)it.lParam;
              sprintf(m,"Delete '%s v%s'?",g_fw[idx].model,g_fw[idx].fw);
              if(MessageBoxA(hwnd,m,"Confirm",MB_YESNO|MB_ICONQUESTION)==IDYES){
                  supabase_delete(g_fw[idx].checksum);
                  g_fw[idx].deleted=1; g_dirty=1; populate_list();
              }
            }
            break;
        }
        case IDC_BTN_SAVE:
        case IDM_SAVE:
            save_fw();
            break;
        case IDC_BTN_SCAN:
            scan_folder();
            break;
        case IDM_SYNC:
            if(sync_from_supabase()){
                char t[128];
                build_combo(); populate_list();
                sprintf(t,"%s  \x97  %d entries (Supabase)",APP_TITLE,g_fw_count);
                SetWindowTextA(g_hwnd,t);
            }
            break;
        case IDM_OPEN_FW:
            open_fw_file();
            break;
        case IDM_OPEN_COMPAT:
            open_compat_file();
            break;
        case IDM_ABOUT:
            MessageBoxA(hwnd,
                "Razor 1911 presents..\r\n"
                "DriveBrowser v1.0\r\n"
                "Pioneer BD Drive Firmware Database Browser\r\n"
                "\r\n"
                "By BabaYaga / Razor 1911\r\n"
                "\r\n"
                "Companion tool to DriveKit v1.0\r\n"
                "\r\n"
                "Thank you for the inspiration and help from:\r\n"
                "MrPenguin, cxplay, Sayaka, Coppervid,\r\n"
                "blackened2687, MakeMKV Forum and cdrinfo.pl\r\n"
                "\r\n"
                "Database powered by Supabase",
                "About DriveBrowser",
                MB_OK|MB_ICONINFORMATION);
            break;
            SendMessageA(hwnd,WM_CLOSE,0,0);
            break;
        }
        break;

    case WM_NOTIFY: {
        NMHDR *nm = (NMHDR*)lp;
        if(nm->hwndFrom==g_hList) {
            if(nm->code==LVN_ITEMCHANGED) {
                NMLISTVIEW *nml=(NMLISTVIEW*)lp;
                if((nml->uNewState&LVIS_SELECTED)&&nml->iItem>=0) {
                    LVITEMA it; memset(&it,0,sizeof(it));
                    it.mask=LVIF_PARAM; it.iItem=nml->iItem;
                    ListView_GetItem(g_hList,&it);
                    show_detail((int)it.lParam);
                }
            }
            if(nm->code==LVN_COLUMNCLICK) {
                NMLISTVIEW *nml=(NMLISTVIEW*)lp;
                if(nml->iSubItem==g_sort_col) g_sort_asc=!g_sort_asc;
                else { g_sort_col=nml->iSubItem; g_sort_asc=1; }
                populate_list();
            }
            if(nm->code==NM_DBLCLK) {
                NMITEMACTIVATE *nma=(NMITEMACTIVATE*)lp;
                if(nma->iItem>=0) {
                    LVITEMA it; memset(&it,0,sizeof(it));
                    it.mask=LVIF_PARAM; it.iItem=nma->iItem;
                    ListView_GetItem(g_hList,&it);
                    do_edit((int)it.lParam);
                }
            }
        }
        break;
    }

    case WM_CLOSE:
        if(g_dirty) {
            int r=MessageBoxA(hwnd,"Save changes to drives.json?","Unsaved Changes",MB_YESNOCANCEL|MB_ICONQUESTION);
            if(r==IDYES) save_fw();
            else if(r==IDCANCEL) return 0;
        }
        DestroyWindow(hwnd);
        break;

    case WM_DESTROY:
        DeleteObject(g_hFont);
        DeleteObject(g_hFontBold);
        DeleteObject(g_hFontMono);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcA(hwnd,msg,wp,lp);
}

/* =========================================================
   WINMAIN
   ========================================================= */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nShow)
{
    WNDCLASSEXA wc;
    INITCOMMONCONTROLSEX icc;
    char title[128];
    MSG m;
    char exepath[MAX_PATH];
    char *sep;

    (void)hPrev; (void)cmd;
    g_hInst = hInst;
    CoInitialize(NULL);

    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_WIN95_CLASSES|ICC_LISTVIEW_CLASSES|ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    /* Try to load from exe folder if files exist there */
    GetModuleFileNameA(NULL,exepath,MAX_PATH);
    sep = strrchr(exepath,'\\');
    if(sep) {
        char try_fw[MAX_PATH], try_compat[MAX_PATH];
        *sep = 0;
        sprintf(try_fw,    "%s\\drives.json",       exepath);
        sprintf(try_compat,"%s\\compatibility.json", exepath);
        if(GetFileAttributesA(try_fw)!=INVALID_FILE_ATTRIBUTES) {
            strncpy(g_fw_file,try_fw,MAX_PATH-1);
            load_fw(g_fw_file);
        }
        if(GetFileAttributesA(try_compat)!=INVALID_FILE_ATTRIBUTES) {
            strncpy(g_compat_file,try_compat,MAX_PATH-1);
            load_compat(g_compat_file);
        }
    }

    memset(&wc,0,sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW|CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE+1);
    wc.lpszClassName = "DriveBrowser";
    wc.hIcon         = LoadIcon(NULL,IDI_APPLICATION);
    RegisterClassExA(&wc);

    sprintf(title,"%s   -   %d entries",APP_TITLE,g_fw_count);
    g_hwnd = CreateWindowExA(0,"DriveBrowser",title,
        WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,820,620,NULL,build_menu(),hInst,NULL);

    ShowWindow(g_hwnd,nShow);
    UpdateWindow(g_hwnd);

    while(GetMessageA(&m,NULL,0,0)) {
        TranslateMessage(&m);
        DispatchMessageA(&m);
    }
    CoUninitialize();
    return (int)m.wParam;
}
