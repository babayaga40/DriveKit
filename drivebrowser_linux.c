/*
 * drivebrowser_linux.c
 * Pioneer BD Drive Database Browser - Linux GTK3
 *
 * Compile:
 *   gcc drivebrowser_linux.c -o drivebrowser \
 *       $(pkg-config --cflags --libs gtk+-3.0) -lcurl -lm
 *
 * Install dependencies (Ubuntu/Debian):
 *   sudo apt install libgtk-3-dev libcurl4-openssl-dev
 *
 * Install dependencies (Fedora):
 *   sudo dnf install gtk3-devel libcurl-devel
 *
 * cPix / Razor 1911 (c) 2026
 */

#include <gtk/gtk.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* =========================================================
   SUPABASE CONFIG
   ========================================================= */
#define SB_URL     "https://eehuzsmqkqphsrpgxgkh.supabase.co"
#define SB_KEY     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVlaHV6c21xa3FwaHNycGd4Z2toIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg4Njk0NDksImV4cCI6MjEwNDQ0NTQ0OX0.FvD1LHy_3GIYPcKxFu8A8Y8zYXf_QlObvp2F-v3EVPI"
#define SB_FW_URL  SB_URL "/rest/v1/firmwares?select=*&limit=1000&order=model.asc"
#define SB_CO_URL  SB_URL "/rest/v1/compat_files?select=*&limit=500"

/* =========================================================
   DATA MODEL
   ========================================================= */
#define MAX_FW     800
#define MAX_COMPAT 300
#define MAX_LINE   512

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
static char        g_fw_file[512]     = "drives.json";
static char        g_compat_file[512] = "compatibility.json";
static int         g_dirty = 0;
static int         g_filter = 0;
static int         g_sort_col = 0;
static int         g_sort_asc = 1;

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
   GLOBALS - GTK widgets
   ========================================================= */
static GtkWidget *g_window;
static GtkWidget *g_tree;
static GtkListStore *g_store;
static GtkWidget *g_search;
static GtkWidget *g_combo_fam;
static GtkWidget *g_detail;
static GtkWidget *g_compat_tree;
static GtkListStore *g_compat_store;
static GtkWidget *g_statusbar;
static guint g_status_ctx;

/* List store columns */
enum {
    COL_MODEL=0, COL_DID, COL_FW, COL_KERNEL,
    COL_DATE, COL_PNAME, COL_FLAGS, COL_IDX,
    N_COLS
};

/* =========================================================
   JSON HELPERS
   ========================================================= */
static void jstr(const char *ln, const char *key, char *out, int max)
{
    const char *p=strstr(ln,key), *q; int n;
    if(!p) return;
    p=strchr(p,':'); if(!p) return;
    p=strchr(p,'"'); if(!p) return; p++;
    q=strchr(p,'"'); if(!q) return;
    n=(int)(q-p); if(n>=max)n=max-1;
    memcpy(out,p,n); out[n]=0;
}

static int jbool(const char *ln, const char *key)
{
    const char *p=strstr(ln,key); if(!p) return -1;
    p=strchr(p,':'); if(!p) return -1;
    while(*p==':'||*p==' ')p++;
    if(!strncmp(p,"true",4))  return 1;
    if(!strncmp(p,"false",5)) return 0;
    return -1;
}

static unsigned int hexid(const char *s)
{
    unsigned int v=0;
    if(!s||!*s) return 0;
    if(s[0]=='0'&&(s[1]=='x'||s[1]=='X')) s+=2;
    sscanf(s,"%x",&v);
    return v;
}

/* =========================================================
   JSON VALUE EXTRACTION (for Supabase response)
   ========================================================= */
static void json_val(const char *json, const char *key, char *out, int max)
{
    char search[64]; const char *p,*q; int n;
    snprintf(search,sizeof(search),"\"%s\":",key);
    p=strstr(json,search); if(!p) return;
    p+=strlen(search);
    while(*p==' ')p++;
    if(*p=='"') {
        p++; q=p;
        while(*q&&!(*q=='"'&&*(q-1)!='\\'))q++;
        n=(int)(q-p); if(n>=max)n=max-1;
        memcpy(out,p,n); out[n]=0;
    } else if(!strncmp(p,"null",4)) {
        out[0]=0;
    } else {
        q=p; while(*q&&*q!=','&&*q!='}'&&*q!=']')q++;
        n=(int)(q-p); if(n>=max)n=max-1;
        memcpy(out,p,n); out[n]=0;
    }
}

static int json_bool2(const char *json, const char *key)
{
    char search[64],val[16]={0};
    const char *p;
    snprintf(search,sizeof(search),"\"%s\":",key);
    p=strstr(json,search); if(!p) return 0;
    p+=strlen(search);
    while(*p==' ')p++;
    if(!strncmp(p,"true",4))  return 1;
    if(!strncmp(p,"false",5)) return 0;
    return 0;
}

/* =========================================================
   LOAD / SAVE
   ========================================================= */
static int load_fw(const char *fn)
{
    FILE *fp=fopen(fn,"r"); char ln[MAX_LINE];
    FwEntry cur; int in=0;
    if(!fp) return 0;
    memset(&cur,0,sizeof(cur)); cur.uhd_capable=-1;
    g_fw_count=0;
    while(fgets(ln,sizeof(ln),fp)&&g_fw_count<MAX_FW){
        if(strstr(ln,"\"model\"")&&!strstr(ln,"firmwares")&&!strstr(ln,"source")){
            if(in&&cur.model[0]) g_fw[g_fw_count++]=cur;
            memset(&cur,0,sizeof(cur)); cur.uhd_capable=-1; in=1;
            jstr(ln,"\"model\"",cur.model,sizeof(cur.model));
        } else if(in){
            if     (strstr(ln,"\"fw\""))            jstr(ln,"\"fw\"",cur.fw,sizeof(cur.fw));
            else if(strstr(ln,"\"checksum\""))      jstr(ln,"\"checksum\"",cur.checksum,sizeof(cur.checksum));
            else if(strstr(ln,"\"drive_id\""))      jstr(ln,"\"drive_id\"",cur.drive_id,sizeof(cur.drive_id));
            else if(strstr(ln,"\"kernel\""))        jstr(ln,"\"kernel\"",cur.kernel,sizeof(cur.kernel));
            else if(strstr(ln,"\"date\""))          jstr(ln,"\"date\"",cur.date,sizeof(cur.date));
            else if(strstr(ln,"\"platform_name\"")) jstr(ln,"\"platform_name\"",cur.platform_name,sizeof(cur.platform_name));
            else if(strstr(ln,"\"crossflash_to\"")&&!strstr(ln,"notes"))
                                                    jstr(ln,"\"crossflash_to\"",cur.crossflash_to,sizeof(cur.crossflash_to));
            else if(strstr(ln,"\"crossflash_notes\""))
                                                    jstr(ln,"\"crossflash_notes\"",cur.crossflash_notes,sizeof(cur.crossflash_notes));
            else if(strstr(ln,"\"notes\"")&&!strstr(ln,"crossflash"))
                                                    jstr(ln,"\"notes\"",cur.notes,sizeof(cur.notes));
            else if(strstr(ln,"\"libredrive\""))    cur.libredrive  =jbool(ln,"\"libredrive\"");
            else if(strstr(ln,"\"recommended\""))   cur.recommended =jbool(ln,"\"recommended\"");
            else if(strstr(ln,"\"post_cutoff\""))   cur.post_cutoff =jbool(ln,"\"post_cutoff\"");
            else if(strstr(ln,"\"uhd_capable\""))   cur.uhd_capable =jbool(ln,"\"uhd_capable\"");
        }
    }
    if(in&&cur.model[0]&&g_fw_count<MAX_FW) g_fw[g_fw_count++]=cur;
    fclose(fp); return g_fw_count;
}

static int load_compat(const char *fn)
{
    FILE *fp=fopen(fn,"r"); char ln[MAX_LINE];
    CompatEntry cur; int in=0;
    if(!fp) return 0;
    memset(&cur,0,sizeof(cur)); g_compat_count=0;
    while(fgets(ln,sizeof(ln),fp)&&g_compat_count<MAX_COMPAT){
        if(strstr(ln,"\"filename\"")){
            if(in&&cur.filename[0]) g_compat[g_compat_count++]=cur;
            memset(&cur,0,sizeof(cur)); in=1;
            jstr(ln,"\"filename\"",cur.filename,sizeof(cur.filename));
        } else if(in){
            if     (strstr(ln,"\"version\""))      jstr(ln,"\"version\"",cur.version,sizeof(cur.version));
            else if(strstr(ln,"\"model\""))        jstr(ln,"\"model\"",cur.model,sizeof(cur.model));
            else if(strstr(ln,"\"file_type\""))    jstr(ln,"\"file_type\"",cur.file_type,sizeof(cur.file_type));
            else if(strstr(ln,"\"platform_id\""))  jstr(ln,"\"platform_id\"",cur.platform_id,sizeof(cur.platform_id));
            else if(strstr(ln,"\"platform_name\""))jstr(ln,"\"platform_name\"",cur.platform_name,sizeof(cur.platform_name));
            else if(strstr(ln,"\"kernel\""))       jstr(ln,"\"kernel\"",cur.kernel,sizeof(cur.kernel));
            else if(strstr(ln,"\"checksum\""))     jstr(ln,"\"checksum\"",cur.checksum,sizeof(cur.checksum));
        }
    }
    if(in&&cur.filename[0]&&g_compat_count<MAX_COMPAT) g_compat[g_compat_count++]=cur;
    fclose(fp); return g_compat_count;
}

static void save_fw(void)
{
    FILE *fp=fopen(g_fw_file,"w"); int i,cnt=0;
    if(!fp){
        GtkWidget *d=gtk_message_dialog_new(GTK_WINDOW(g_window),
            GTK_DIALOG_MODAL,GTK_MESSAGE_ERROR,GTK_BUTTONS_OK,
            "Cannot write %s",g_fw_file);
        gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d); return;
    }
    for(i=0;i<g_fw_count;i++) if(!g_fw[i].deleted) cnt++;
    fprintf(fp,"{\n  \"version\": 1,\n");
    fprintf(fp,"  \"source\": \"LibreDrive firmware list + DriveKit research\",\n");
    fprintf(fp,"  \"count\": %d,\n  \"schema_version\": 3,\n  \"firmwares\": [\n",cnt);
    { int first=1;
      for(i=0;i<g_fw_count;i++){
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
    fclose(fp); g_dirty=0;
    char msg[128]; snprintf(msg,sizeof(msg),"Saved %d entries to %s",cnt,g_fw_file);
    gtk_statusbar_push(GTK_STATUSBAR(g_statusbar),g_status_ctx,msg);
}

/* =========================================================
   CURL HTTP
   ========================================================= */
typedef struct { char *data; size_t size; } CurlBuf;

static size_t curl_write(void *ptr, size_t sz, size_t nm, void *ud)
{
    CurlBuf *b=(CurlBuf*)ud;
    size_t n=sz*nm;
    b->data=realloc(b->data,b->size+n+1);
    memcpy(b->data+b->size,ptr,n);
    b->size+=n; b->data[b->size]=0;
    return n;
}

static char *http_get_curl(const char *url, long *status)
{
    CURL *curl=curl_easy_init(); CurlBuf buf={0};
    struct curl_slist *hdrs=NULL;
    char auth[512],apikey[512];
    if(!curl) return NULL;
    snprintf(auth,  sizeof(auth),  "Authorization: Bearer %s",SB_KEY);
    snprintf(apikey,sizeof(apikey),"apikey: %s",SB_KEY);
    hdrs=curl_slist_append(hdrs,auth);
    hdrs=curl_slist_append(hdrs,apikey);
    hdrs=curl_slist_append(hdrs,"Content-Type: application/json");
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,hdrs);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_write);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buf);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,15L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_perform(curl);
    if(status) curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return buf.data;
}

static long http_post_curl(const char *url, const char *method, const char *body)
{
    CURL *curl=curl_easy_init();
    struct curl_slist *hdrs=NULL;
    char auth[512],apikey[512]; long status=0;
    if(!curl) return 0;
    snprintf(auth,  sizeof(auth),  "Authorization: Bearer %s",SB_KEY);
    snprintf(apikey,sizeof(apikey),"apikey: %s",SB_KEY);
    hdrs=curl_slist_append(hdrs,auth);
    hdrs=curl_slist_append(hdrs,apikey);
    hdrs=curl_slist_append(hdrs,"Content-Type: application/json");
    hdrs=curl_slist_append(hdrs,"Prefer: resolution=merge-duplicates,return=minimal");
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,hdrs);
    curl_easy_setopt(curl,CURLOPT_CUSTOMREQUEST,method);
    if(body&&strlen(body)>0) {
        curl_easy_setopt(curl,CURLOPT_POSTFIELDS,body);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDSIZE,(long)strlen(body));
    }
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,15L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1L);
    curl_easy_perform(curl);
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return status;
}

/* =========================================================
   SUPABASE SYNC
   ========================================================= */
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
    char url[256];
    long status;
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
    snprintf(url,sizeof(url),"%s/rest/v1/firmwares?on_conflict=checksum",SB_URL);
    status=http_post_curl(url,"POST",body);
    { char msg[128];
      if(status>=200&&status<300) snprintf(msg,sizeof(msg),"Saved to Supabase! (HTTP %ld)",status);
      else snprintf(msg,sizeof(msg),"Supabase failed (HTTP %ld) - saved locally only",status);
      gtk_statusbar_push(GTK_STATUSBAR(g_statusbar),g_status_ctx,msg); }
}

static void supabase_delete(const char *checksum)
{
    char url[256], cs[32];
    esc_json(checksum,cs,sizeof(cs));
    snprintf(url,sizeof(url),"%s/rest/v1/firmwares?checksum=eq.%s",SB_URL,cs);
    http_post_curl(url,"DELETE","");
}

static int sync_from_supabase(void)
{
    char *fw_json=NULL, *co_json=NULL;
    long status=0;
    const char *p, *obj_end;

    gtk_statusbar_push(GTK_STATUSBAR(g_statusbar),g_status_ctx,"Connecting to Supabase...");
    while(gtk_events_pending()) gtk_main_iteration();

    fw_json=http_get_curl(SB_FW_URL,&status);
    if(!fw_json||status<200||status>=300||fw_json[0]!='[') {
        if(fw_json) free(fw_json);
        GtkWidget *d=gtk_message_dialog_new(GTK_WINDOW(g_window),
            GTK_DIALOG_MODAL,GTK_MESSAGE_WARNING,GTK_BUTTONS_OK,
            "Could not connect to the remote database.\n\n"
            "You did not connect to the remote SQL.\n"
            "Choose local files instead using File menu.");
        gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d);
        return 0;
    }

    g_fw_count=0;
    p=fw_json+1;
    while(*p&&g_fw_count<MAX_FW) {
        FwEntry e; char tmp[16];
        while(*p==' '||*p=='\t'||*p=='\n'||*p=='\r'||*p==',')p++;
        if(*p!='{') break;
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
          e.libredrive  =json_bool2(obj,"libredrive");
          e.recommended =json_bool2(obj,"recommended");
          e.post_cutoff =json_bool2(obj,"post_cutoff");
          json_val(obj,"uhd_capable",tmp,sizeof(tmp));
          if(!strcmp(tmp,"true"))  e.uhd_capable=1;
          else if(!strcmp(tmp,"false")) e.uhd_capable=0;
          if(e.model[0]) g_fw[g_fw_count++]=e;
        }
        p=obj_end;
    }
    free(fw_json);

    co_json=http_get_curl(SB_CO_URL,&status);
    if(co_json&&status>=200&&status<300&&co_json[0]=='[') {
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

    { char msg[128];
      snprintf(msg,sizeof(msg),"Loaded %d entries from Supabase + %d compat files",
               g_fw_count,g_compat_count);
      gtk_statusbar_push(GTK_STATUSBAR(g_statusbar),g_status_ctx,msg); }
    return 1;
}

/* =========================================================
   POPULATE LIST
   ========================================================= */
static void populate_list(void)
{
    const char *query=gtk_entry_get_text(GTK_ENTRY(g_search));
    char lquery[256]; int i;
    strncpy(lquery,query,sizeof(lquery)-1);
    for(i=0;lquery[i];i++) lquery[i]=(char)tolower((unsigned char)lquery[i]);

    const char *fam=gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(g_combo_fam));

    gtk_list_store_clear(g_store);

    int shown=0;
    for(i=0;i<g_fw_count;i++) {
        FwEntry *e=&g_fw[i];
        if(e->deleted) continue;
        if(lquery[0]) {
            char buf[512],lb[512]; int k;
            snprintf(buf,sizeof(buf),"%s %s %s %s %s %s",
                     e->model,e->fw,e->drive_id,e->kernel,e->platform_name,e->notes);
            for(k=0;buf[k];k++) lb[k]=(char)tolower((unsigned char)buf[k]); lb[k]=0;
            if(!strstr(lb,lquery)) continue;
        }
        if(fam&&strcmp(fam,"All families")!=0)
            if(!strstr(e->platform_name,fam)&&!strstr(e->model,fam)) continue;
        if(g_filter==1&&!e->libredrive)    continue;
        if(g_filter==2&&!e->recommended)   continue;
        if(g_filter==3&&!e->post_cutoff)   continue;
        if(g_filter==4&&e->uhd_capable!=1) continue;

        char flags[8]="";
        if(e->libredrive)    strcat(flags,"L");
        if(e->recommended)   strcat(flags,"R");
        if(e->post_cutoff)   strcat(flags,"!");
        if(e->uhd_capable==1)strcat(flags,"U");

        GtkTreeIter iter;
        gtk_list_store_append(g_store,&iter);
        gtk_list_store_set(g_store,&iter,
            COL_MODEL, e->model,
            COL_DID,   e->drive_id,
            COL_FW,    e->fw,
            COL_KERNEL,e->kernel,
            COL_DATE,  e->date,
            COL_PNAME, e->platform_name,
            COL_FLAGS, flags,
            COL_IDX,   i,
            -1);
        shown++;
    }

    int total=0; for(i=0;i<g_fw_count;i++) if(!g_fw[i].deleted) total++;
    char msg[200];
    snprintf(msg,sizeof(msg),"Total: %d  |  Shown: %d  |  %s%s",
             total,shown,g_fw_file,g_dirty?"  *unsaved":"");
    gtk_statusbar_push(GTK_STATUSBAR(g_statusbar),g_status_ctx,msg);
}

/* =========================================================
   DETAIL + COMPAT PANEL
   ========================================================= */
static void show_detail(int fw_idx)
{
    FwEntry *e; unsigned int did;
    char text[2048]={0},buf[300];
    int gi,gj,row=0;

    if(fw_idx<0||fw_idx>=g_fw_count) return;
    e=&g_fw[fw_idx]; did=hexid(e->drive_id);

    snprintf(buf,sizeof(buf),"Model         : %s\n",e->model);         strcat(text,buf);
    snprintf(buf,sizeof(buf),"Drive ID      : %s  (%s)\n",e->drive_id,e->platform_name); strcat(text,buf);
    snprintf(buf,sizeof(buf),"Firmware      : %s\n",e->fw);            strcat(text,buf);
    snprintf(buf,sizeof(buf),"Kernel        : %s\n",e->kernel);        strcat(text,buf);
    snprintf(buf,sizeof(buf),"Date          : %s\n",e->date);          strcat(text,buf);
    snprintf(buf,sizeof(buf),"Checksum      : %s\n",e->checksum);      strcat(text,buf);
    strcat(text,"---\n");
    snprintf(buf,sizeof(buf),"LibreDrive    : %s\n",e->libredrive?"Yes":"No");   strcat(text,buf);
    snprintf(buf,sizeof(buf),"Recommended   : %s\n",e->recommended?"Yes":"No");  strcat(text,buf);
    snprintf(buf,sizeof(buf),"Post-cutoff   : %s\n",e->post_cutoff?"YES - cannot downgrade!":"No"); strcat(text,buf);
    snprintf(buf,sizeof(buf),"UHD capable   : %s\n",e->uhd_capable<0?"Unknown":e->uhd_capable?"Yes":"No"); strcat(text,buf);
    if(e->crossflash_to[0]){snprintf(buf,sizeof(buf),"Crossflash to : %s\n",e->crossflash_to);strcat(text,buf);}
    if(e->notes[0]){strcat(text,"---\n");strncat(text,e->notes,400);strcat(text,"\n");}

    GtkTextBuffer *tb=gtk_text_view_get_buffer(GTK_TEXT_VIEW(g_detail));
    gtk_text_buffer_set_text(tb,text,-1);

    gtk_list_store_clear(g_compat_store);
    if(!did) return;
    for(gi=0;g_groups[gi][0];gi++) {
        int found=0;
        for(gj=0;gj<6&&g_groups[gi][gj];gj++) if(g_groups[gi][gj]==did){found=1;break;}
        if(!found) continue;
        for(gj=0;gj<6&&g_groups[gi][gj];gj++) {
            unsigned int cid=g_groups[gi][gj]; int k;
            if(cid==did) continue;
            for(k=0;k<g_compat_count;k++) {
                char did_str[16];
                GtkTreeIter iter;
                if(hexid(g_compat[k].platform_id)!=cid) continue;
                snprintf(did_str,sizeof(did_str),"0x%04X",cid);
                gtk_list_store_append(g_compat_store,&iter);
                gtk_list_store_set(g_compat_store,&iter,
                    0,g_compat[k].filename,
                    1,g_compat[k].version,
                    2,g_compat[k].file_type,
                    3,did_str,-1);
                row++;
            }
        }
    }
    if(!row) {
        GtkTreeIter iter;
        gtk_list_store_append(g_compat_store,&iter);
        gtk_list_store_set(g_compat_store,&iter,0,"No compatible files in compatibility.json",1,"",2,"",3,"",-1);
    }
}

/* =========================================================
   EDIT DIALOG
   ========================================================= */
static void show_edit_dialog(GtkWindow *parent, int fw_idx)
{
    GtkWidget *dlg=gtk_dialog_new_with_buttons(
        fw_idx>=0?"Edit Entry":"Add Entry",
        parent, GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
        "_Cancel", GTK_RESPONSE_CANCEL,
        "_Save",   GTK_RESPONSE_ACCEPT,
        NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg),400,520);

    GtkWidget *grid=gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid),6);
    gtk_grid_set_column_spacing(GTK_GRID(grid),8);
    gtk_container_set_border_width(GTK_CONTAINER(grid),12);

    GtkWidget *content=gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_add(GTK_CONTAINER(content),grid);

    /* Create fields */
    struct { const char *label; GtkWidget *entry; int multiline; } fields[9];
    const char *labels[]={"Model *","Firmware","Drive ID","Kernel","Date","Platform","Crossflash to","Notes",NULL};
    int r;
    for(r=0;labels[r];r++) {
        GtkWidget *lbl=gtk_label_new(labels[r]);
        gtk_label_set_xalign(GTK_LABEL(lbl),1.0);
        gtk_grid_attach(GTK_GRID(grid),lbl,0,r,1,1);
        fields[r].label=labels[r];
        fields[r].multiline=(r==7);
        if(r==7) {
            GtkWidget *sw=gtk_scrolled_window_new(NULL,NULL);
            gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),GTK_POLICY_AUTOMATIC,GTK_POLICY_AUTOMATIC);
            gtk_widget_set_size_request(sw,250,80);
            fields[r].entry=gtk_text_view_new();
            gtk_container_add(GTK_CONTAINER(sw),fields[r].entry);
            gtk_grid_attach(GTK_GRID(grid),sw,1,r,1,1);
        } else {
            fields[r].entry=gtk_entry_new();
            gtk_widget_set_hexpand(fields[r].entry,TRUE);
            gtk_grid_attach(GTK_GRID(grid),fields[r].entry,1,r,1,1);
        }
    }

    /* Checkboxes */
    GtkWidget *ck_lib =gtk_check_button_new_with_label("LibreDrive");
    GtkWidget *ck_rec =gtk_check_button_new_with_label("Recommended");
    GtkWidget *ck_post=gtk_check_button_new_with_label("Post-cutoff");
    GtkWidget *hbox=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,8);
    gtk_box_pack_start(GTK_BOX(hbox),ck_lib, FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(hbox),ck_rec, FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(hbox),ck_post,FALSE,FALSE,0);
    gtk_grid_attach(GTK_GRID(grid),hbox,0,r,2,1); r++;

    /* UHD radio */
    GtkWidget *uhd_lbl=gtk_label_new("UHD:");
    gtk_label_set_xalign(GTK_LABEL(uhd_lbl),1.0);
    GtkWidget *rb_yes=gtk_radio_button_new_with_label(NULL,"Yes");
    GtkWidget *rb_no =gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(rb_yes),"No");
    GtkWidget *rb_unk=gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(rb_yes),"Unknown");
    GtkWidget *rbox=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,4);
    gtk_box_pack_start(GTK_BOX(rbox),rb_yes,FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(rbox),rb_no, FALSE,FALSE,0);
    gtk_box_pack_start(GTK_BOX(rbox),rb_unk,FALSE,FALSE,0);
    gtk_grid_attach(GTK_GRID(grid),uhd_lbl,0,r,1,1);
    gtk_grid_attach(GTK_GRID(grid),rbox,   1,r,1,1);

    /* Populate if editing */
    FwEntry *e=(fw_idx>=0)?&g_fw[fw_idx]:NULL;
    if(e) {
        gtk_entry_set_text(GTK_ENTRY(fields[0].entry),e->model);
        gtk_entry_set_text(GTK_ENTRY(fields[1].entry),e->fw);
        gtk_entry_set_text(GTK_ENTRY(fields[2].entry),e->drive_id);
        gtk_entry_set_text(GTK_ENTRY(fields[3].entry),e->kernel);
        gtk_entry_set_text(GTK_ENTRY(fields[4].entry),e->date);
        gtk_entry_set_text(GTK_ENTRY(fields[5].entry),e->platform_name);
        gtk_entry_set_text(GTK_ENTRY(fields[6].entry),e->crossflash_to);
        GtkTextBuffer *tb=gtk_text_view_get_buffer(GTK_TEXT_VIEW(fields[7].entry));
        gtk_text_buffer_set_text(tb,e->notes,-1);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ck_lib), e->libredrive);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ck_rec), e->recommended);
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ck_post),e->post_cutoff);
        if(e->uhd_capable==1)       gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_yes),TRUE);
        else if(e->uhd_capable==0)  gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_no), TRUE);
        else                        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_unk),TRUE);
    } else {
        gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rb_unk),TRUE);
    }

    gtk_widget_show_all(dlg);

    if(gtk_dialog_run(GTK_DIALOG(dlg))==GTK_RESPONSE_ACCEPT) {
        FwEntry tmp; memset(&tmp,0,sizeof(tmp)); tmp.uhd_capable=-1;
        strncpy(tmp.model,        gtk_entry_get_text(GTK_ENTRY(fields[0].entry)),sizeof(tmp.model)-1);
        if(!tmp.model[0]) {
            GtkWidget *err=gtk_message_dialog_new(GTK_WINDOW(dlg),GTK_DIALOG_MODAL,
                GTK_MESSAGE_ERROR,GTK_BUTTONS_OK,"Model is required!");
            gtk_dialog_run(GTK_DIALOG(err)); gtk_widget_destroy(err);
        } else {
            strncpy(tmp.fw,           gtk_entry_get_text(GTK_ENTRY(fields[1].entry)),sizeof(tmp.fw)-1);
            strncpy(tmp.drive_id,     gtk_entry_get_text(GTK_ENTRY(fields[2].entry)),sizeof(tmp.drive_id)-1);
            strncpy(tmp.kernel,       gtk_entry_get_text(GTK_ENTRY(fields[3].entry)),sizeof(tmp.kernel)-1);
            strncpy(tmp.date,         gtk_entry_get_text(GTK_ENTRY(fields[4].entry)),sizeof(tmp.date)-1);
            strncpy(tmp.platform_name,gtk_entry_get_text(GTK_ENTRY(fields[5].entry)),sizeof(tmp.platform_name)-1);
            strncpy(tmp.crossflash_to,gtk_entry_get_text(GTK_ENTRY(fields[6].entry)),sizeof(tmp.crossflash_to)-1);
            { GtkTextBuffer *tb=gtk_text_view_get_buffer(GTK_TEXT_VIEW(fields[7].entry));
              GtkTextIter s2,e2; gtk_text_buffer_get_bounds(tb,&s2,&e2);
              char *t=gtk_text_buffer_get_text(tb,&s2,&e2,FALSE);
              strncpy(tmp.notes,t,sizeof(tmp.notes)-1); g_free(t); }
            tmp.libredrive  =gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ck_lib));
            tmp.recommended =gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ck_rec));
            tmp.post_cutoff =gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ck_post));
            if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb_yes))) tmp.uhd_capable=1;
            else if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb_no))) tmp.uhd_capable=0;

            if(fw_idx>=0) {
                char ck[16]; memcpy(ck,g_fw[fw_idx].checksum,16);
                g_fw[fw_idx]=tmp;
                memcpy(g_fw[fw_idx].checksum,ck,16);
            } else {
                if(g_fw_count<MAX_FW) g_fw[g_fw_count++]=tmp;
            }
            g_dirty=1;
            populate_list();
            { FwEntry *e2=(fw_idx>=0)?&g_fw[fw_idx]:&g_fw[g_fw_count-1];
              supabase_upsert(e2); }
        }
    }
    gtk_widget_destroy(dlg);
}

/* =========================================================
   CALLBACKS
   ========================================================= */
static void on_search_changed(GtkEntry *e, gpointer data)
{
    (void)e; (void)data;
    populate_list();
}

static void on_family_changed(GtkComboBox *cb, gpointer data)
{
    (void)cb; (void)data;
    populate_list();
}

static void on_filter_toggled(GtkToggleButton *btn, gpointer data)
{
    if(!gtk_toggle_button_get_active(btn)) return;
    g_filter=GPOINTER_TO_INT(data);
    populate_list();
}

static void on_row_selected(GtkTreeSelection *sel, gpointer data)
{
    GtkTreeModel *model; GtkTreeIter iter;
    (void)data;
    if(gtk_tree_selection_get_selected(sel,&model,&iter)) {
        gint idx;
        gtk_tree_model_get(model,&iter,COL_IDX,&idx,-1);
        show_detail(idx);
    }
}

static void on_row_activated(GtkTreeView *tv, GtkTreePath *path,
                              GtkTreeViewColumn *col, gpointer data)
{
    GtkTreeModel *model=gtk_tree_view_get_model(tv);
    GtkTreeIter iter;
    (void)col; (void)data;
    if(gtk_tree_model_get_iter(model,&iter,path)) {
        gint idx;
        gtk_tree_model_get(model,&iter,COL_IDX,&idx,-1);
        show_edit_dialog(GTK_WINDOW(g_window),idx);
    }
}

static void on_col_clicked(GtkTreeViewColumn *col, gpointer data)
{
    int c=GPOINTER_TO_INT(data);
    if(c==g_sort_col) g_sort_asc=!g_sort_asc;
    else { g_sort_col=c; g_sort_asc=1; }
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(g_store),c,
        g_sort_asc?GTK_SORT_ASCENDING:GTK_SORT_DESCENDING);
}

/* =========================================================
   MENU CALLBACKS
   ========================================================= */
static void on_about(GtkMenuItem *mi, gpointer data)
{
    static const char *about_text =
        "Razor 1911 presents..\n"
        "DriveBrowser v1.0\n"
        "Pioneer BD Drive Firmware Database Browser\n"
        "\n"
        "By BabaYaga / Razor 1911\n"
        "\n"
        "Companion tool to DriveKit v1.0\n"
        "\n"
        "Thank you for the inspiration and help from:\n"
        "MrPenguin, cxplay, Sayaka, Coppervid,\n"
        "blackened2687, MakeMKV Forum and cdrinfo.pl\n"
        "\n"
        "Database powered by Supabase";

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        "About DriveBrowser",
        GTK_WINDOW(g_window),
        GTK_DIALOG_MODAL|GTK_DIALOG_DESTROY_WITH_PARENT,
        "OK", GTK_RESPONSE_OK,
        NULL);

    GtkWidget *label = gtk_label_new(about_text);
    gtk_label_set_justify(GTK_LABEL(label), GTK_JUSTIFY_CENTER);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    gtk_container_add(GTK_CONTAINER(content), label);
    gtk_container_set_border_width(GTK_CONTAINER(content), 16);
    gtk_widget_show_all(dlg);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

static void on_sync(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    if(sync_from_supabase()) {
        populate_list();
        char title[128];
        snprintf(title,sizeof(title),"Pioneer BD Drive Database - %d entries (Supabase)",g_fw_count);
        gtk_window_set_title(GTK_WINDOW(g_window),title);
    }
}

static void on_open_fw(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    GtkWidget *dlg=gtk_file_chooser_dialog_new("Open drives.json",
        GTK_WINDOW(g_window),GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel",GTK_RESPONSE_CANCEL,"_Open",GTK_RESPONSE_ACCEPT,NULL);
    GtkFileFilter *ff=gtk_file_filter_new();
    gtk_file_filter_add_pattern(ff,"*.json");
    gtk_file_filter_set_name(ff,"JSON files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg),ff);
    if(gtk_dialog_run(GTK_DIALOG(dlg))==GTK_RESPONSE_ACCEPT) {
        char *fn=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        strncpy(g_fw_file,fn,sizeof(g_fw_file)-1);
        g_free(fn);
        g_fw_count=0; load_fw(g_fw_file);
        populate_list();
    }
    gtk_widget_destroy(dlg);
}

static void on_open_compat(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    GtkWidget *dlg=gtk_file_chooser_dialog_new("Open compatibility.json",
        GTK_WINDOW(g_window),GTK_FILE_CHOOSER_ACTION_OPEN,
        "_Cancel",GTK_RESPONSE_CANCEL,"_Open",GTK_RESPONSE_ACCEPT,NULL);
    GtkFileFilter *ff=gtk_file_filter_new();
    gtk_file_filter_add_pattern(ff,"*.json");
    gtk_file_filter_set_name(ff,"JSON files");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dlg),ff);
    if(gtk_dialog_run(GTK_DIALOG(dlg))==GTK_RESPONSE_ACCEPT) {
        char *fn=gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
        strncpy(g_compat_file,fn,sizeof(g_compat_file)-1);
        g_free(fn);
        g_compat_count=0; load_compat(g_compat_file);
        populate_list();
    }
    gtk_widget_destroy(dlg);
}

static void on_save(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    save_fw();
}

static void on_add(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    show_edit_dialog(GTK_WINDOW(g_window),-1);
}

static void on_edit(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(g_tree));
    GtkTreeModel *model; GtkTreeIter iter;
    if(gtk_tree_selection_get_selected(sel,&model,&iter)) {
        gint idx;
        gtk_tree_model_get(model,&iter,COL_IDX,&idx,-1);
        show_edit_dialog(GTK_WINDOW(g_window),idx);
    } else {
        GtkWidget *d=gtk_message_dialog_new(GTK_WINDOW(g_window),GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO,GTK_BUTTONS_OK,"Select an entry first");
        gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d);
    }
}

static void on_delete(GtkMenuItem *mi, gpointer data)
{
    (void)mi; (void)data;
    GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(g_tree));
    GtkTreeModel *model; GtkTreeIter iter;
    if(gtk_tree_selection_get_selected(sel,&model,&iter)) {
        gint idx;
        gtk_tree_model_get(model,&iter,COL_IDX,&idx,-1);
        char msg[128];
        snprintf(msg,sizeof(msg),"Delete '%s v%s'?",g_fw[idx].model,g_fw[idx].fw);
        GtkWidget *d=gtk_message_dialog_new(GTK_WINDOW(g_window),GTK_DIALOG_MODAL,
            GTK_MESSAGE_QUESTION,GTK_BUTTONS_YES_NO,"%s",msg);
        if(gtk_dialog_run(GTK_DIALOG(d))==GTK_RESPONSE_YES) {
            supabase_delete(g_fw[idx].checksum);
            g_fw[idx].deleted=1; g_dirty=1;
            populate_list();
        }
        gtk_widget_destroy(d);
    }
}

static gboolean on_delete_event(GtkWidget *w, GdkEvent *ev, gpointer data)
{
    (void)w; (void)ev; (void)data;
    if(g_dirty) {
        GtkWidget *d=gtk_message_dialog_new(GTK_WINDOW(g_window),GTK_DIALOG_MODAL,
            GTK_MESSAGE_QUESTION,GTK_BUTTONS_NONE,
            "Save changes to drives.json before quitting?");
        gtk_dialog_add_buttons(GTK_DIALOG(d),"_Save",GTK_RESPONSE_YES,
            "_Discard",GTK_RESPONSE_NO,"_Cancel",GTK_RESPONSE_CANCEL,NULL);
        int r=gtk_dialog_run(GTK_DIALOG(d)); gtk_widget_destroy(d);
        if(r==GTK_RESPONSE_YES) save_fw();
        else if(r==GTK_RESPONSE_CANCEL) return TRUE;
    }
    gtk_main_quit();
    return FALSE;
}

/* =========================================================
   BUILD FAMILY COMBO
   ========================================================= */
static void build_family_combo(void)
{
    char seen[80][32]; int ns=0,i,j;
    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(g_combo_fam));
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(g_combo_fam),"All families");
    for(i=0;i<g_fw_count;i++) {
        const char *pn=g_fw[i].platform_name; if(!pn[0]) continue;
        for(j=0;j<ns;j++) if(!strcmp(seen[j],pn)) break;
        if(j==ns&&ns<80) {
            strncpy(seen[ns++],pn,31);
            gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(g_combo_fam),pn);
        }
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(g_combo_fam),0);
}

/* =========================================================
   BUILD UI
   ========================================================= */
static GtkWidget *add_col(GtkWidget *tv, const char *title, int col_id, int width)
{
    GtkCellRenderer *r=gtk_cell_renderer_text_new();
    GtkTreeViewColumn *col=gtk_tree_view_column_new_with_attributes(title,r,"text",col_id,NULL);
    gtk_tree_view_column_set_resizable(col,TRUE);
    gtk_tree_view_column_set_min_width(col,width);
    gtk_tree_view_column_set_clickable(col,TRUE);
    gtk_tree_view_column_set_sort_column_id(col,col_id);
    g_signal_connect(col,"clicked",G_CALLBACK(on_col_clicked),GINT_TO_POINTER(col_id));
    gtk_tree_view_append_column(GTK_TREE_VIEW(tv),col);
    return (GtkWidget*)col;
}

static void build_ui(void)
{
    /* Main window */
    g_window=gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(g_window),"Pioneer BD Drive Database");
    gtk_window_set_default_size(GTK_WINDOW(g_window),1000,700);
    g_signal_connect(g_window,"delete-event",G_CALLBACK(on_delete_event),NULL);

    GtkWidget *vbox=gtk_box_new(GTK_ORIENTATION_VERTICAL,0);
    gtk_container_add(GTK_CONTAINER(g_window),vbox);

    /* Menu bar */
    GtkWidget *menubar=gtk_menu_bar_new();

    GtkWidget *file_menu=gtk_menu_new();
    GtkWidget *file_item=gtk_menu_item_new_with_mnemonic("_File");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(file_item),file_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar),file_item);

    struct { const char *label; GCallback cb; } file_items[]={
        {"_Sync from Supabase", G_CALLBACK(on_sync)},
        {NULL,NULL},
        {"_Open drives.json...",G_CALLBACK(on_open_fw)},
        {"Open _compatibility.json...",G_CALLBACK(on_open_compat)},
        {NULL,NULL},
        {"_Save drives.json",G_CALLBACK(on_save)},
        {NULL,NULL},
        {"_Quit",G_CALLBACK(gtk_main_quit)},
        {NULL,NULL}
    };
    int fi;
    for(fi=0;file_items[fi].label||fi==0;fi++){
        if(!file_items[fi].label&&fi>0) {
            gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),gtk_separator_menu_item_new());
        } else if(file_items[fi].label) {
            GtkWidget *mi=gtk_menu_item_new_with_mnemonic(file_items[fi].label);
            g_signal_connect(mi,"activate",file_items[fi].cb,NULL);
            gtk_menu_shell_append(GTK_MENU_SHELL(file_menu),mi);
        }
        if(!file_items[fi].label&&fi>0) break;
    }

    GtkWidget *edit_menu=gtk_menu_new();
    GtkWidget *edit_item=gtk_menu_item_new_with_mnemonic("_Edit");
    gtk_menu_item_set_submenu(GTK_MENU_ITEM(edit_item),edit_menu);
    gtk_menu_shell_append(GTK_MENU_SHELL(menubar),edit_item);
    { GtkWidget *mi;
      mi=gtk_menu_item_new_with_mnemonic("_Add entry");
      g_signal_connect(mi,"activate",G_CALLBACK(on_add),NULL);
      gtk_menu_shell_append(GTK_MENU_SHELL(edit_menu),mi);
      mi=gtk_menu_item_new_with_mnemonic("_Edit entry");
      g_signal_connect(mi,"activate",G_CALLBACK(on_edit),NULL);
      gtk_menu_shell_append(GTK_MENU_SHELL(edit_menu),mi);
      mi=gtk_menu_item_new_with_mnemonic("_Delete entry");
      g_signal_connect(mi,"activate",G_CALLBACK(on_delete),NULL);
      gtk_menu_shell_append(GTK_MENU_SHELL(edit_menu),mi);
    }

    /* Help menu */
    {
      GtkWidget *help_menu=gtk_menu_new();
      GtkWidget *help_item=gtk_menu_item_new_with_mnemonic("_Help");
      gtk_menu_item_set_submenu(GTK_MENU_ITEM(help_item),help_menu);
      gtk_menu_shell_append(GTK_MENU_SHELL(menubar),help_item);
      GtkWidget *about_mi=gtk_menu_item_new_with_mnemonic("_About...");
      g_signal_connect(about_mi,"activate",G_CALLBACK(on_about),NULL);
      gtk_menu_shell_append(GTK_MENU_SHELL(help_menu),about_mi);
    }

    gtk_box_pack_start(GTK_BOX(vbox),menubar,FALSE,FALSE,0);

    /* Toolbar area - search + family + filters */
    GtkWidget *toolbar=gtk_box_new(GTK_ORIENTATION_HORIZONTAL,6);
    gtk_container_set_border_width(GTK_CONTAINER(toolbar),4);
    gtk_box_pack_start(GTK_BOX(vbox),toolbar,FALSE,FALSE,0);

    gtk_box_pack_start(GTK_BOX(toolbar),gtk_label_new("Search:"),FALSE,FALSE,0);
    g_search=gtk_entry_new();
    gtk_widget_set_size_request(g_search,220,-1);
    g_signal_connect(g_search,"changed",G_CALLBACK(on_search_changed),NULL);
    gtk_box_pack_start(GTK_BOX(toolbar),g_search,FALSE,FALSE,0);

    gtk_box_pack_start(GTK_BOX(toolbar),gtk_label_new("Family:"),FALSE,FALSE,0);
    g_combo_fam=gtk_combo_box_text_new();
    gtk_widget_set_size_request(g_combo_fam,160,-1);
    g_signal_connect(g_combo_fam,"changed",G_CALLBACK(on_family_changed),NULL);
    gtk_box_pack_start(GTK_BOX(toolbar),g_combo_fam,FALSE,FALSE,0);

    /* Filter radio buttons */
    gtk_box_pack_start(GTK_BOX(toolbar),gtk_separator_new(GTK_ORIENTATION_VERTICAL),FALSE,FALSE,4);
    struct { const char *label; int val; } filters[]={
        {"All",0},{"LibreDrive",1},{"Recommended",2},{"Post-cutoff",3},{"UHD",4},{NULL,0}
    };
    GtkWidget *rb_first=NULL;
    int fi2;
    for(fi2=0;filters[fi2].label;fi2++) {
        GtkWidget *rb;
        if(!rb_first) {
            rb=gtk_radio_button_new_with_label(NULL,filters[fi2].label);
            rb_first=rb;
        } else {
            rb=gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON(rb_first),filters[fi2].label);
        }
        g_signal_connect(rb,"toggled",G_CALLBACK(on_filter_toggled),GINT_TO_POINTER(filters[fi2].val));
        gtk_box_pack_start(GTK_BOX(toolbar),rb,FALSE,FALSE,0);
    }

    /* Main pane - list on top, detail+compat on bottom */
    GtkWidget *vpane=gtk_paned_new(GTK_ORIENTATION_VERTICAL);
    gtk_box_pack_start(GTK_BOX(vbox),vpane,TRUE,TRUE,0);

    /* Main list */
    g_store=gtk_list_store_new(N_COLS,
        G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,
        G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_INT);
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(g_store),COL_MODEL,GTK_SORT_ASCENDING);

    g_tree=gtk_tree_view_new_with_model(GTK_TREE_MODEL(g_store));
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(g_tree),TRUE);
    gtk_tree_view_set_search_column(GTK_TREE_VIEW(g_tree),COL_MODEL);
    g_signal_connect(g_tree,"row-activated",G_CALLBACK(on_row_activated),NULL);
    { GtkTreeSelection *sel=gtk_tree_view_get_selection(GTK_TREE_VIEW(g_tree));
      g_signal_connect(sel,"changed",G_CALLBACK(on_row_selected),NULL); }

    add_col(g_tree,"Model",   COL_MODEL, 200);
    add_col(g_tree,"Drive ID",COL_DID,   80);
    add_col(g_tree,"Version", COL_FW,    70);
    add_col(g_tree,"Kernel",  COL_KERNEL,65);
    add_col(g_tree,"Date",    COL_DATE,  85);
    add_col(g_tree,"Platform",COL_PNAME, 95);
    add_col(g_tree,"Flags",   COL_FLAGS, 50);

    GtkWidget *sw_list=gtk_scrolled_window_new(NULL,NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_list),GTK_POLICY_AUTOMATIC,GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw_list),g_tree);
    gtk_paned_pack1(GTK_PANED(vpane),sw_list,TRUE,TRUE);

    /* Bottom pane - detail + compat */
    GtkWidget *hpane=gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_pack2(GTK_PANED(vpane),hpane,FALSE,TRUE);
    gtk_paned_set_position(GTK_PANED(vpane),420);

    /* Detail text */
    GtkWidget *detail_frame=gtk_frame_new("Entry details");
    g_detail=gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(g_detail),FALSE);
    gtk_text_view_set_monospace(GTK_TEXT_VIEW(g_detail),TRUE);
    GtkWidget *sw_det=gtk_scrolled_window_new(NULL,NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_det),GTK_POLICY_AUTOMATIC,GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw_det),g_detail);
    gtk_container_add(GTK_CONTAINER(detail_frame),sw_det);
    gtk_paned_pack1(GTK_PANED(hpane),detail_frame,TRUE,TRUE);

    /* Compat list */
    GtkWidget *compat_frame=gtk_frame_new("Compatible firmware (same crossflash group)");
    g_compat_store=gtk_list_store_new(4,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);
    GtkWidget *compat_tv=gtk_tree_view_new_with_model(GTK_TREE_MODEL(g_compat_store));
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(compat_tv),TRUE);
    { GtkCellRenderer *r=gtk_cell_renderer_text_new();
      GtkTreeViewColumn *c;
      c=gtk_tree_view_column_new_with_attributes("Filename",r,"text",0,NULL);
      gtk_tree_view_column_set_min_width(c,160); gtk_tree_view_append_column(GTK_TREE_VIEW(compat_tv),c);
      c=gtk_tree_view_column_new_with_attributes("Version",r,"text",1,NULL);
      gtk_tree_view_column_set_min_width(c,60); gtk_tree_view_append_column(GTK_TREE_VIEW(compat_tv),c);
      c=gtk_tree_view_column_new_with_attributes("Type",r,"text",2,NULL);
      gtk_tree_view_column_set_min_width(c,55); gtk_tree_view_append_column(GTK_TREE_VIEW(compat_tv),c);
      c=gtk_tree_view_column_new_with_attributes("Drive ID",r,"text",3,NULL);
      gtk_tree_view_column_set_min_width(c,65); gtk_tree_view_append_column(GTK_TREE_VIEW(compat_tv),c);
    }
    GtkWidget *sw_comp=gtk_scrolled_window_new(NULL,NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw_comp),GTK_POLICY_AUTOMATIC,GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw_comp),compat_tv);
    gtk_container_add(GTK_CONTAINER(compat_frame),sw_comp);
    gtk_paned_pack2(GTK_PANED(hpane),compat_frame,TRUE,TRUE);
    gtk_paned_set_position(GTK_PANED(hpane),400);

    /* Status bar */
    g_statusbar=gtk_statusbar_new();
    g_status_ctx=gtk_statusbar_get_context_id(GTK_STATUSBAR(g_statusbar),"main");
    gtk_box_pack_end(GTK_BOX(vbox),g_statusbar,FALSE,FALSE,0);

    gtk_widget_show_all(g_window);
}

/* =========================================================
   MAIN
   ========================================================= */
int main(int argc, char *argv[])
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    gtk_init(&argc,&argv);

    /* Try to find JSON files next to executable */
    { char exepath[512]={0}; char *sep;
      ssize_t n=readlink("/proc/self/exe",exepath,sizeof(exepath)-1);
      if(n>0){exepath[n]=0;sep=strrchr(exepath,'/');
        if(sep){*sep=0;
          snprintf(g_fw_file,sizeof(g_fw_file),"%s/drives.json",exepath);
          snprintf(g_compat_file,sizeof(g_compat_file),"%s/compatibility.json",exepath);}}
    }

    build_ui();

    /* Try Supabase first, fall back to local files */
    if(!sync_from_supabase()) {
        load_fw(g_fw_file);
        load_compat(g_compat_file);
    }

    build_family_combo();
    populate_list();

    { char title[128];
      snprintf(title,sizeof(title),"Pioneer BD Drive Database - %d entries",g_fw_count);
      gtk_window_set_title(GTK_WINDOW(g_window),title); }

    gtk_main();
    curl_global_cleanup();
    return 0;
}
