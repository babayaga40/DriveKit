/* DriveKit Pass 57: read-only ASM viewer + separate annotation editor. POSIX / Win32. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#ifdef _WIN32
#include <windows.h>
#include <conio.h>
#include <io.h>
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#define isatty _isatty
#else
#include <unistd.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#endif

typedef struct { char *s; unsigned addr; int has_addr; int target; unsigned dest; } Line;
typedef struct { unsigned addr; char *name; char *comment; } Note;
static Line *lines; static size_t count,capacity,selected,top; static Note *notes; static size_t nn,cn;
static char *asmfile,*notefile; static char status[256]="Ready",search[256]=""; static int dirty,mono,rows=24,cols=80;
#ifdef _WIN32
static HANDLE hin, hout; static DWORD saved_in, saved_out; static int raw_on;
#else
static struct termios saved; static int raw_on;
#endif
static unsigned long long image_hash;
static unsigned *bookmarks; static size_t nb, cb; static char bookmarkpath[4096];
static size_t *functions; static size_t nfunctions, cfunctions;
/* Browser navigation history: back and forward, without modifying ASM data. */
#define NAV_LIMIT 1024
static size_t nav_back[NAV_LIMIT], nav_forward[NAV_LIMIT];
static size_t nav_nb, nav_nf;
static void nav_push(size_t *stack,size_t *n,size_t value){
 if(*n==NAV_LIMIT){memmove(stack,stack+1,(NAV_LIMIT-1)*sizeof(*stack));*n=NAV_LIMIT-1;}
 stack[(*n)++]=value;
}
static void nav_record(size_t previous){
 if(selected!=previous){nav_push(nav_back,&nav_nb,previous);nav_nf=0;}
}
static void nav_go_back(void){
 if(!nav_nb){snprintf(status,sizeof(status),"No earlier navigation location");return;}
 nav_push(nav_forward,&nav_nf,selected);selected=nav_back[--nav_nb];
 snprintf(status,sizeof(status),"History back (%zu remaining)",nav_nb);
}
static void nav_go_forward(void){
 if(!nav_nf){snprintf(status,sizeof(status),"No forward navigation location");return;}
 nav_push(nav_back,&nav_nb,selected);selected=nav_forward[--nav_nf];
 snprintf(status,sizeof(status),"History forward (%zu remaining)",nav_nf);
}
#ifdef _WIN32
static char *dk_local_strdup(const char *s){size_t n=strlen(s)+1;char *p=(char*)malloc(n);if(p)memcpy(p,s,n);return p;}
static ssize_t dk_getline(char **line,size_t *cap,FILE *f){size_t n=0;int c;if(!*line || !*cap){*cap=256;*line=(char*)malloc(*cap);if(!*line)return -1;}while((c=fgetc(f))!=EOF){if(n+1>=*cap){size_t nc=*cap*2;char *p=(char*)realloc(*line,nc);if(!p)return -1;*line=p;*cap=nc;}(*line)[n++]=(char)c;if(c=='\n')break;}if(!n)return -1;(*line)[n]=0;return (ssize_t)n;}
#define getline dk_getline
#define strdup dk_local_strdup
#endif
static void restore(void){
#ifdef _WIN32
if(raw_on){SetConsoleMode(hin,saved_in);SetConsoleMode(hout,saved_out);raw_on=0;}
#else
if(raw_on){tcsetattr(STDIN_FILENO,TCSAFLUSH,&saved);raw_on=0;}
#endif
fputs("\033[?25h\033[0m\033[?1049l",stdout);fflush(stdout);
}
static void die(const char *s){restore();fprintf(stderr,"%s: %s\n",s,strerror(errno));exit(1);}
static void sigexit(int sig){(void)sig;restore();exit(128+sig);}
static void raw(void){
#ifdef _WIN32
DWORD mode;
hin=GetStdHandle(STD_INPUT_HANDLE);hout=GetStdHandle(STD_OUTPUT_HANDLE);
if(hin==INVALID_HANDLE_VALUE||hout==INVALID_HANDLE_VALUE||!GetConsoleMode(hin,&saved_in)||!GetConsoleMode(hout,&saved_out)){fprintf(stderr,"Windows console required\n");exit(1);}
mode=saved_out|ENABLE_VIRTUAL_TERMINAL_PROCESSING;
if(!SetConsoleMode(hout,mode)){fprintf(stderr,"ANSI terminal support required (use Windows Terminal or modern conhost)\n");exit(1);}
mode=saved_in & ~(ENABLE_LINE_INPUT|ENABLE_ECHO_INPUT|ENABLE_PROCESSED_INPUT);
mode |= ENABLE_WINDOW_INPUT;
if(!SetConsoleMode(hin,mode)){SetConsoleMode(hout,saved_out);fprintf(stderr,"Cannot set console input mode\n");exit(1);}
#else
struct termios t;if(tcgetattr(0,&saved)<0)die("terminal");t=saved;t.c_lflag &= (tcflag_t)~(ECHO|ICANON|IEXTEN|ISIG);t.c_iflag &= (tcflag_t)~(IXON|ICRNL);t.c_oflag &= (tcflag_t)~OPOST;t.c_cc[VMIN]=1;t.c_cc[VTIME]=0;if(tcsetattr(0,TCSAFLUSH,&t)<0)die("raw mode");
#endif
raw_on=1;fputs("\033[?1049h\033[?25l",stdout);
}
static void size_term(void){
#ifdef _WIN32
CONSOLE_SCREEN_BUFFER_INFO w;if(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&w)){int r=w.srWindow.Bottom-w.srWindow.Top+1,c=w.srWindow.Right-w.srWindow.Left+1;if(r>3&&c>15){rows=r;cols=c;}}
#else
struct winsize w;if(ioctl(1,TIOCGWINSZ,&w)==0 && w.ws_row>3 && w.ws_col>15){rows=w.ws_row;cols=w.ws_col;}
#endif
}
static char *dk_strdup(const char *s){char *p=strdup(s?s:"");if(!p)die("allocation");return p;}
static int hexaddr(const char *s,unsigned *v){char b[9];int i=0;while(isxdigit((unsigned char)s[i]) && i<8){b[i]=s[i];i++;}if(i<6 || (i<8 && isxdigit((unsigned char)s[i])))return 0;b[i]=0;*v=(unsigned)strtoul(b,0,16);return 1;}
static void parse(Line *l){const char *p=l->s;unsigned a;while(*p==' '||*p=='\t')p++;if(*p==';')return;if(!strncmp(p,"func_",5)||!strncmp(p,"FUNC_",5)||!strncmp(p,"sub_",4)||!strncmp(p,"SUB_",4)||!strncmp(p,"loc_",4)){const char *u=strchr(p,'_');if(u&&hexaddr(u+1,&a)){l->addr=a;l->has_addr=1;}return;}if(!strncmp(p,"0x",2))p+=2;if(hexaddr(p,&a)){const char *e=p;while(isxdigit((unsigned char)*e))e++;if(*e==':'||isspace((unsigned char)*e)){l->addr=a;l->has_addr=1;}}
  /* Direct targets only: label or absolute address after branch/call mnemonic. */
  p=l->s;while(*p){if(isalpha((unsigned char)*p)){char word[20];int k=0;const char *start=p;while(isalpha((unsigned char)*p)||*p=='.'){if(k<19)word[k++]=(char)toupper((unsigned char)*p);p++;}word[k]=0;if(!strcmp(word,"JSR")||!strcmp(word,"JMP")||!strcmp(word,"BRA")||!strcmp(word,"BSR")||!strcmp(word,"BNE")||!strcmp(word,"BEQ")||!strcmp(word,"BCC")||!strcmp(word,"BCS")||!strcmp(word,"BHI")||!strcmp(word,"BLS")||!strcmp(word,"BGE")||!strcmp(word,"BLT")||!strcmp(word,"BGT")||!strcmp(word,"BLE")||!strcmp(word,"BPL")||!strcmp(word,"BMI")){
      const char *q=p;while(isspace((unsigned char)*q))q++;if(*q=='@')q++;if(!strncmp(q,"0x",2)){q+=2;if(hexaddr(q,&a)){l->target=1;l->dest=a;}}else if(!strncmp(q,"@H'",3)){q+=3;if(hexaddr(q,&a)){l->target=1;l->dest=a;}}else if(!strncmp(q,"loc_",4)||!strncmp(q,"BB_",3)||!strncmp(q,"func_",5)||!strncmp(q,"sub_",4)){q=strchr(q,'_')+1;if(hexaddr(q,&a)){l->target=1;l->dest=a;}}break;
    }if(p==start)p++;}else p++;}
  /* Explicit comment target in DriveKit CFG output (not a semantic decode). */
  if(!l->target && l->has_addr){p=strstr(l->s,"-> loc_");if(!p)p=strstr(l->s,"-> BB_");if(p){p=strchr(p,'_')+1;if(hexaddr(p,&a)){l->target=1;l->dest=a;}}}
}
static int function_marker(const char *s){
 const char *p=s; while(*p==' '||*p=='\t')p++;
 return !strncmp(p,"func_",5)||!strncmp(p,"FUNC_",5)||!strncmp(p,"sub_",4)||!strncmp(p,"SUB_",4)||!strncmp(p,"FUNCTION ",9)||!strncmp(p,"Function ",9);
}
static void addfunction(size_t i){if(nfunctions==cfunctions){size_t nc=cfunctions?cfunctions*2:256;size_t *t=(size_t*)realloc(functions,nc*sizeof(*t));if(!t)die("function index allocation");functions=t;cfunctions=nc;}functions[nfunctions++]=i;}
static void loadasm(const char *path){FILE *f=fopen(path,"rb");char *s=0;size_t cap=0;ssize_t n;unsigned long long h=1469598103934665603ULL;if(!f)die("open ASM");while((n=getline(&s,&cap,f))!=-1){while(n && (s[n-1]=='\r'||s[n-1]=='\n'))s[--n]=0;for(ssize_t i=0;i<n;i++){h^=(unsigned char)s[i];h*=1099511628211ULL;}h^=10;h*=1099511628211ULL;if(count==capacity){capacity=capacity?capacity*2:4096;Line *t=realloc(lines,capacity*sizeof(*lines));if(!t)die("line allocation");lines=t;}Line *l=&lines[count++];memset(l,0,sizeof(*l));l->s=dk_strdup(s);parse(l);if(function_marker(l->s))addfunction(count-1);}free(s);fclose(f);image_hash=h;}
static ssize_t locate(unsigned a){size_t i;for(i=0;i<count;i++)if(lines[i].has_addr && lines[i].addr==a)return (ssize_t)i;return -1;}
static Note *note(unsigned a,int create){for(size_t i=0;i<nn;i++)if(notes[i].addr==a)return &notes[i];if(!create)return NULL;if(nn==cn){cn=cn?cn*2:64;Note *t=realloc(notes,cn*sizeof(*notes));if(!t)die("notes allocation");notes=t;}Note *n=&notes[nn++];n->addr=a;n->name=dk_strdup("");n->comment=dk_strdup("");return n;}
static int safe_field(const char *s){for(;*s;s++)if(*s=='\t'||*s=='\n'||*s=='\r')return 0;return 1;}
static void loadnotes(void){FILE *f=fopen(notefile,"rb");char buf[8192];unsigned long long hash;if(!f)return;if(!fgets(buf,sizeof(buf),f)||sscanf(buf,"DRIVEKIT_NOTES_V1 %llx",&hash)!=1||hash!=image_hash){snprintf(status,sizeof(status),"Annotations hash mismatch: not loaded");fclose(f);return;}while(fgets(buf,sizeof(buf),f)){char *a=strtok(buf,"\t\r\n"),*name=strtok(NULL,"\t\r\n"),*comment=strtok(NULL,"\r\n");unsigned x;if(!a||!hexaddr(a,&x))continue;Note *n=note(x,1);free(n->name);free(n->comment);n->name=dk_strdup(name&&strcmp(name,"-")?name:"");n->comment=dk_strdup(comment&&strcmp(comment,"-")?comment:"");}fclose(f);}
static int replace_notes(const char *src,const char *dst){
#ifdef _WIN32
return MoveFileExA(src,dst,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)?0:-1;
#else
return rename(src,dst);
#endif
}
static void savenotes(void){char tmp[4096];if(strlen(notefile)+5>=sizeof(tmp)){strcpy(status,"Annotation path too long");return;}snprintf(tmp,sizeof(tmp),"%s.tmp",notefile);FILE *f=fopen(tmp,"wb");if(!f){snprintf(status,sizeof(status),"Cannot save notes: %s",strerror(errno));return;}fprintf(f,"DRIVEKIT_NOTES_V1 %016llx\n",image_hash);for(size_t i=0;i<nn;i++)fprintf(f,"%08X\t%s\t%s\n",notes[i].addr,*notes[i].name?notes[i].name:"-",*notes[i].comment?notes[i].comment:"-");if(fclose(f)||replace_notes(tmp,notefile)){snprintf(status,sizeof(status),"Save failed: %s",strerror(errno));remove(tmp);return;}dirty=0;snprintf(status,sizeof(status),"Annotations saved: %s",notefile);}
static int bookmark_index(unsigned a){for(size_t i=0;i<nb;i++)if(bookmarks[i]==a)return (int)i;return -1;}
static void toggle_bookmark(void){
 if(!count||!lines[selected].has_addr){snprintf(status,sizeof(status),"Select an addressed instruction to bookmark");return;}
 unsigned a=lines[selected].addr;int ix=bookmark_index(a);
 if(ix>=0){memmove(&bookmarks[ix],&bookmarks[ix+1],(nb-(size_t)ix-1)*sizeof(*bookmarks));nb--;snprintf(status,sizeof(status),"Bookmark removed: %08X",a);}
 else {if(nb==cb){size_t nc=cb?cb*2:32;unsigned *v=(unsigned*)realloc(bookmarks,nc*sizeof(*v));if(!v)die("bookmark allocation");bookmarks=v;cb=nc;}bookmarks[nb++]=a;snprintf(status,sizeof(status),"Bookmark added: %08X",a);}dirty=1;
}
static void loadbookmarks(void){FILE *f=fopen(bookmarkpath,"rb");char buf[256];unsigned long long hash;if(!f)return;
 if(!fgets(buf,sizeof(buf),f)||sscanf(buf,"DRIVEKIT_BOOKMARKS_V1 %llx",&hash)!=1||hash!=image_hash){snprintf(status,sizeof(status),"Bookmark hash mismatch: ignored");fclose(f);return;}
 while(fgets(buf,sizeof(buf),f)){unsigned a;if(hexaddr(buf,&a)&&locate(a)>=0&&bookmark_index(a)<0){if(nb==cb){size_t nc=cb?cb*2:32;unsigned *v=(unsigned*)realloc(bookmarks,nc*sizeof(*v));if(!v)die("bookmark allocation");bookmarks=v;cb=nc;}bookmarks[nb++]=a;}}fclose(f);
}
static int savebookmarks(void){char tmp[4096];if(strlen(bookmarkpath)+5>=sizeof(tmp))return -1;
 snprintf(tmp,sizeof(tmp),"%s.tmp",bookmarkpath);FILE *f=fopen(tmp,"wb");if(!f)return -1;
 fprintf(f,"DRIVEKIT_BOOKMARKS_V1 %016llx\n",image_hash);for(size_t i=0;i<nb;i++)fprintf(f,"%08X\n",bookmarks[i]);
 if(fclose(f)!=0||replace_notes(tmp,bookmarkpath)!=0){remove(tmp);return -1;}return 0;
}
static void saveproject(void){savenotes();if(dirty==0){if(savebookmarks()!=0){dirty=1;snprintf(status,sizeof(status),"Bookmark save failed: %s",strerror(errno));}else snprintf(status,sizeof(status),"Annotations and %zu bookmarks saved",nb);}}
#ifdef _WIN32
static int key(void){
INPUT_RECORD r;DWORD n;
for(;;){
if(!ReadConsoleInputA(hin,&r,1,&n))return -1;
if(r.EventType!=KEY_EVENT||!r.Event.KeyEvent.bKeyDown)continue;
KEY_EVENT_RECORD *k=&r.Event.KeyEvent;
if((k->dwControlKeyState&(LEFT_CTRL_PRESSED|RIGHT_CTRL_PRESSED)) && (k->wVirtualKeyCode=='S'))return 19;
switch(k->wVirtualKeyCode){case VK_UP:return 1001;case VK_DOWN:return 1002;case VK_PRIOR:return 1003;case VK_NEXT:return 1004;case VK_HOME:return 1005;case VK_END:return 1006;case VK_BACK:return 127;case VK_RETURN:return 13;case VK_ESCAPE:return 27;}
if(k->uChar.AsciiChar)return (unsigned char)k->uChar.AsciiChar;
}
}
#else
static int key(void){unsigned char c;if(read(0,&c,1)!=1)return -1;if(c!=27)return c;unsigned char b[16];int n=0;while(n<15){fd_set set;struct timeval tv={0,35000};FD_ZERO(&set);FD_SET(0,&set);if(select(1,&set,0,0,&tv)<=0)break;if(read(0,&b[n],1)!=1)break;n++;if(isalpha(b[n-1])||b[n-1]=='~')break;}if(n>=2&&b[0]=='['){if(b[n-1]=='A')return 1001;if(b[n-1]=='B')return 1002;if(b[n-1]=='H')return 1005;if(b[n-1]=='F')return 1006;if(b[n-1]=='~'){if(b[1]=='5')return 1003;if(b[1]=='6')return 1004;if(b[1]=='1'||b[1]=='7')return 1005;if(b[1]=='4'||b[1]=='8')return 1006;}}return 27;}
#endif
static void cursor(int y,int x); static void color(int id);

/* Pass 58: firmware is read-only; mappings must pass ASM byte validation. */
static unsigned char *firmware; static size_t firmware_size;
static char firmware_path[4096]; static unsigned firmware_base=0x00410000U;
static int hex_visible=1, hex_focus=0, mapping_ok=0;
static unsigned hex_addr=0; static int hex_pinned=0;
static int parse_asm_bytes(const Line *l,unsigned char *bytes,int cap){
 const char *p=l->s;int n=0;unsigned v;
 while(*p==' '||*p=='\t')p++;
 if(!l->has_addr)return 0;
 while(isxdigit((unsigned char)*p))p++;
 if(*p!=' '&&*p!='\t')return 0;
 while(*p==' '||*p=='\t')p++;
 while(n<cap && isxdigit((unsigned char)p[0])&&isxdigit((unsigned char)p[1]) &&
       (p[2]==' '||p[2]=='\t'||p[2]==0)){
   char tmp[3]={p[0],p[1],0};v=(unsigned)strtoul(tmp,NULL,16);
   bytes[n++]=(unsigned char)v;p+=2;
   while(*p==' '||*p=='\t')p++;
 }
 return n;
}
static int firmware_offset(unsigned addr,size_t *off){
 if(addr<firmware_base)return 0;
 *off=(size_t)(addr-firmware_base);
 return firmware && *off<firmware_size;
}
static int check_mapping(void){
 size_t checked=0,failed=0;
 for(size_t i=0;i<count && checked<64;i++){
  unsigned char bytes[16];int n=parse_asm_bytes(&lines[i],bytes,16);size_t off;
  if(n<2)continue;
  checked++;
  if(!firmware_offset(lines[i].addr,&off)||firmware_size-off<(size_t)n||memcmp(firmware+off,bytes,(size_t)n))failed++;
 }
 mapping_ok=(checked>=4&&failed==0);
 snprintf(status,sizeof(status),mapping_ok?"Firmware verified: %zu ASM byte samples":"Firmware mapping mismatch: %zu/%zu samples; HEX sync disabled",mapping_ok?checked:failed,checked);
 return mapping_ok;
}
static int load_firmware(const char *path){
 FILE *f=fopen(path,"rb");long n;
 if(!f)return 0;
 if(fseek(f,0,SEEK_END)|| (n=ftell(f))<=0 || fseek(f,0,SEEK_SET)){fclose(f);return 0;}
 if((unsigned long)n>100000000UL){fclose(f);return 0;}
 unsigned char *p=(unsigned char*)malloc((size_t)n);
 if(!p){fclose(f);return 0;}
 if(fread(p,1,(size_t)n,f)!=(size_t)n){free(p);fclose(f);return 0;}
 fclose(f);free(firmware);firmware=p;firmware_size=(size_t)n;
 snprintf(firmware_path,sizeof(firmware_path),"%s",path);
 check_mapping();return 1;
}
static void hex_render(int start,int height){
 cursor(start,1);fputs("\033[2K",stdout);color(3);
 printf("HEX / ASCII | %s | %s",firmware_path[0]?firmware_path:"no firmware",mapping_ok?"VERIFIED":"UNVERIFIED - SYNC DISABLED");color(0);
 if(!firmware){cursor(start+1,1);printf("No firmware loaded. Use --firmware path.bin");return;}
 if(!mapping_ok){cursor(start+1,1);printf("ASM bytes differ from firmware at declared image base %08X",firmware_base);
 cursor(start+2,1);printf("Refusing to show misleading address-synchronized HEX.");return;}
 unsigned a=hex_pinned?hex_addr:(count&&lines[selected].has_addr?lines[selected].addr:hex_addr);
 size_t off;
 if(!firmware_offset(a,&off)){cursor(start+1,1);printf("Address %08X is outside firmware",a);return;}
 size_t origin=off & ~(size_t)15;
 for(int row=0;row<height-1;row++){
  size_t pos=origin+(size_t)row*16;
  if(pos>=firmware_size)break;
  cursor(start+1+row,1);fputs("\033[2K",stdout);
  printf("%08X  ",(unsigned)(firmware_base+pos));
  for(int j=0;j<16;j++){
   if(pos+(size_t)j<firmware_size)printf("%02X ",firmware[pos+j]);else fputs("   ",stdout);
  }
  fputs(" |",stdout);
  for(int j=0;j<16 && pos+(size_t)j<firmware_size;j++){
   unsigned char c=firmware[pos+j];putchar(c>=32&&c<=126?c:'.');
  }
  putchar('|');
 }
}

static void cursor(int y,int x){printf("\033[%d;%dH",y,x);}
static void color(int id){if(mono)return;static const char *c[]={"\033[0m","\033[38;5;110m","\033[38;5;81m","\033[38;5;221m","\033[38;5;183m","\033[38;5;114m","\033[38;5;209m","\033[30;48;5;67m"};fputs(c[id],stdout);}
static void paintline(size_t ix,int y){cursor(y,1);fputs("\033[2K",stdout);Line *l=&lines[ix];const char *s=l->s;int sel=(ix==selected);if(sel)color(7);int n=0,mode=0;for(int i=0;s[i] && n<cols;i++){unsigned char ch=s[i];if(ch=='\t'){int spaces=4-(n%4);while(spaces-- && n<cols){putchar(' ');n++;}continue;}if(ch<32||ch==127)ch='?';if(!sel&&!mono){int next=mode;if(ch==';')next=5;else if(mode!=5 && i==0 && isxdigit(ch))next=1;else if(mode!=5 && ch=='#')next=4;else if(mode!=5 && ch=='@')next=4;else if(mode!=5 && (i==0||isspace((unsigned char)s[i-1])) && isalpha(ch)){char w[12];int j=0;while(j<11 && (isalpha((unsigned char)s[i+j])||s[i+j]=='.')){w[j]=(char)toupper((unsigned char)s[i+j]);j++;}w[j]=0;if(!strncmp(w,"RTS",3))next=6;else if(w[0]=='B'||!strncmp(w,"JSR",3)||!strncmp(w,"JMP",3))next=3;else next=2;}if(next!=mode){mode=next;color(mode);}}putchar(ch);n++;}color(0);}
static void draw(void){
 size_term();if(selected>=count&&count)selected=count-1;
 int hexheight=hex_visible?(rows>=18?rows/3:0):0;
 int height=rows-3-hexheight;if(height<1)height=1;
 if(selected<top)top=selected;
 if(selected>=top+(size_t)height)top=selected-height+1;
 fputs("\033[?25l\033[H\033[2J",stdout);color(3);
 printf("DriveKit ASM Editor Pass58 | %s | %s",asmfile,dirty?"ANNOTATIONS MODIFIED":"ASM READ-ONLY");color(0);
 for(int y=0;y<height;y++){size_t i=top+y;if(i<count)paintline(i,y+2);}
 if(hexheight)hex_render(height+2,hexheight);
 cursor(rows-1,1);fputs("\033[2K",stdout);
 if(count){Line *l=&lines[selected];printf("Line %zu/%zu  History %zu< %zu>  %s",selected+1,count,nav_nb,nav_nf,hex_focus?"HEX FOCUS":"ASM FOCUS");
 if(l->has_addr){printf("  0x%08X",l->addr);Note *n=note(l->addr,0);if(n&&*n->name)printf("  %.35s",n->name);}}
 cursor(rows,1);fputs("\033[2K",stdout);
 printf("H HEX  Tab focus  F X G / Enter [ ] B M N ; Ctrl+S Q | %.48s",status);fflush(stdout);
}
static int prompt(const char *label,char *out,size_t cap){size_t len=strlen(out);for(;;){cursor(rows,1);fputs("\033[2K\033[?25h",stdout);printf("%s%s",label,out);fflush(stdout);int c=key();if(c==27){fputs("\033[?25l",stdout);return 0;}if(c=='\r'||c=='\n'){fputs("\033[?25l",stdout);return 1;}if(c==127||c==8){if(len)out[--len]=0;}else if(c>=32&&c<127&&len+1<cap){out[len++]=(char)c;out[len]=0;}}}
static int contains(const char *hay,const char *needle){for(;*hay;hay++){const char *a=hay,*b=needle;while(*a&&*b&&tolower((unsigned char)*a)==tolower((unsigned char)*b)){a++;b++;}if(!*b)return 1;}return 0;}
static void findnext(int direction){if(!*search)return;for(size_t k=1;k<=count;k++){size_t ix=(selected+count+(direction>0?k:count-(k%count)))%count;if(contains(lines[ix].s,search)){selected=ix;snprintf(status,sizeof(status),"Found: %.240s",search);return;}}strcpy(status,"No matching line");}
static void jump(unsigned a){ssize_t i=locate(a);if(i<0)snprintf(status,sizeof(status),"0x%08X not in this ASM export",a);else {selected=(size_t)i;snprintf(status,sizeof(status),"Jumped to 0x%08X",a);}}
static int contains(const char *hay,const char *needle);
static int function_address(size_t ix,unsigned *addr){
 const char *p=lines[ix].s;while(*p==' '||*p=='\t')p++;
 if(!strncmp(p,"func_",5)||!strncmp(p,"FUNC_",5)||!strncmp(p,"sub_",4)||!strncmp(p,"SUB_",4)||!strncmp(p,"loc_",4)){
   const char *u=strchr(p,'_');if(u&&hexaddr(u+1,addr))return 1;
 }
 return 0;
}
static void function_browser(void){
 if(!nfunctions){snprintf(status,sizeof(status),"No explicit function markers in this export");return;}
 size_t cursor_ix=0,first=0;char filter[128]="";
 for(;;){size_term();int height=rows-4;if(height<1)height=1;
 size_t *matches=(size_t*)malloc(nfunctions*sizeof(size_t));if(!matches)die("function filter allocation");
 size_t nmatch=0;for(size_t i=0;i<nfunctions;i++){
   unsigned a;char address[16]="";if(function_address(functions[i],&a))snprintf(address,sizeof(address),"%08X",a);
   if(!*filter||contains(lines[functions[i]].s,filter)||contains(address,filter))matches[nmatch++]=functions[i];
 }
 if(nmatch && cursor_ix>=nmatch)cursor_ix=nmatch-1;
 if(!nmatch)cursor_ix=0;
 if(cursor_ix<first)first=cursor_ix;
 if(cursor_ix>=first+(size_t)height)first=cursor_ix-(size_t)height+1;
 fputs("\033[H\033[2J",stdout);color(3);printf("DriveKit Functions %zu/%zu | / filter, Enter jump, Esc close",nmatch,nfunctions);color(0);
 for(int j=0;j<height;j++){size_t k=first+(size_t)j;if(k>=nmatch)break;
   size_t li=matches[k];unsigned a=0;int has=function_address(li,&a);Note *nt=has?note(a,0):NULL;
   cursor(j+2,1);fputs("\033[2K",stdout);
   printf("%c %4zu  %s  %-20.*s %.*s",k==cursor_ix?'>':' ',k+1,has?"ADDR":"MARK",20,lines[li].s,
     cols>55?cols-55:10,nt&&*nt->name?nt->name:"");
 }
 cursor(rows,1);fputs("\033[2K",stdout);printf("Filter: %s | arrows/PgUp/PgDn/Home/End",*filter?filter:"(all)");fflush(stdout);
 int c=key();if(c==27||c=='q'||c=='Q'){free(matches);return;}
 if(c=='/'){char next[128]="";if(prompt("Function filter (empty = all): ",next,sizeof(next))){snprintf(filter,sizeof(filter),"%s",next);cursor_ix=first=0;}}
 else if((c==13||c==10)&&nmatch){selected=matches[cursor_ix];unsigned a;if(function_address(selected,&a)){ssize_t at=locate(a);if(at>=0)selected=(size_t)at;}snprintf(status,sizeof(status),"Function %zu/%zu",cursor_ix+1,nmatch);free(matches);return;}
 else if((c==1001||c=='k')&&cursor_ix)cursor_ix--;
 else if((c==1002||c=='j')&&cursor_ix+1<nmatch)cursor_ix++;
 else if(c==1003)cursor_ix=cursor_ix>(size_t)height?cursor_ix-height:0;
 else if(c==1004&&nmatch)cursor_ix=cursor_ix+(size_t)height<nmatch?cursor_ix+height:nmatch-1;
 else if(c==1005)cursor_ix=0;else if(c==1006&&nmatch)cursor_ix=nmatch-1;
 free(matches);
 }
}
static void bookmark_browser(void){if(!nb){snprintf(status,sizeof(status),"No bookmarks; press B on an addressed line");return;}
 size_t cursor_ix=0;for(;;){size_term();int height=rows-4;if(height<1)height=1;
 size_t first=cursor_ix>=(size_t)height?cursor_ix-(size_t)height+1:0;
 fputs("\033[H\033[2J",stdout);color(3);printf("DriveKit Bookmarks (%zu) | arrows, Enter jump, Q/Esc close",nb);color(0);
 for(int j=0;j<height;j++){size_t k=first+(size_t)j;if(k>=nb)break;ssize_t at=locate(bookmarks[k]);cursor(j+2,1);printf("%c %08X  line %-7zu  %.*s",k==cursor_ix?'>':' ',bookmarks[k],at>=0?(size_t)at+1:0,cols>35?cols-35:20,at>=0?lines[at].s:"");}
 cursor(rows,1);printf("\033[2KBookmark %zu/%zu",cursor_ix+1,nb);fflush(stdout);int c=key();if(c==27||c=='q'||c=='Q')return;
 if(c==13||c==10){ssize_t at=locate(bookmarks[cursor_ix]);if(at>=0)selected=(size_t)at;return;}
 if((c==1001||c=='k')&&cursor_ix)cursor_ix--;else if((c==1002||c=='j')&&cursor_ix+1<nb)cursor_ix++;else if(c==1005)cursor_ix=0;else if(c==1006)cursor_ix=nb-1;
 else if(c==1003)cursor_ix=cursor_ix>(size_t)height?cursor_ix-height:0;else if(c==1004)cursor_ix=cursor_ix+(size_t)height<nb?cursor_ix+height:nb-1;
 }
}
static void xrefs(void){
 if(!count)return;
 unsigned addr=0;if(lines[selected].has_addr)addr=lines[selected].addr;
 else if(!function_address(selected,&addr)){snprintf(status,sizeof(status),"Select an addressed line or function label");return;}
 size_t *refs=(size_t*)malloc(count*sizeof(size_t));if(!refs)die("xref allocation");
 size_t n=0;for(size_t i=0;i<count;i++)if(lines[i].target&&lines[i].dest==addr)refs[n++]=i;
 if(!n){snprintf(status,sizeof(status),"No parsed direct references to %08X",addr);free(refs);return;}
 size_t pos=0,first=0;
 for(;;){size_term();int height=rows-4;if(height<1)height=1;
 if(pos<first)first=pos;
 if(pos>=first+(size_t)height)first=pos-(size_t)height+1;
 fputs("\033[H\033[2J",stdout);color(3);printf("Xrefs to %08X (%zu) | Enter jump, Esc close",addr,n);color(0);
 for(int j=0;j<height;j++){size_t k=first+(size_t)j;if(k>=n)break;cursor(j+2,1);fputs("\033[2K",stdout);
   printf("%c line %-6zu %.*s",k==pos?'>':' ',refs[k]+1,cols>24?cols-24:12,lines[refs[k]].s);
 }
 cursor(rows,1);fputs("\033[2K",stdout);printf("Reference %zu/%zu | arrows/PgUp/PgDn",pos+1,n);fflush(stdout);
 int c=key();if(c==27||c=='q'||c=='Q'){free(refs);return;}
 if(c==13||c==10){selected=refs[pos];snprintf(status,sizeof(status),"Reference %zu/%zu to %08X",pos+1,n,addr);free(refs);return;}
 if((c==1001||c=='k')&&pos)pos--;else if((c==1002||c=='j')&&pos+1<n)pos++;
 else if(c==1003)pos=pos>(size_t)height?pos-height:0;
 else if(c==1004)pos=pos+(size_t)height<n?pos+height:n-1;
 else if(c==1005)pos=0;else if(c==1006)pos=n-1;
 }
}
int main(int argc,char **argv){if(argc<2){fprintf(stderr,"Usage: %s file.asm [notes.tsv] [--firmware normal.bin] [--base 00410000] [--mono]\n",argv[0]);return 2;}asmfile=argv[1];const char *firmware_arg=NULL;for(int i=2;i<argc;i++){if(!strcmp(argv[i],"--mono"))mono=1;else if(!strcmp(argv[i],"--firmware")&&i+1<argc)firmware_arg=argv[++i];else if(!strcmp(argv[i],"--base")&&i+1<argc){char *endptr=NULL;unsigned long v=strtoul(argv[++i],&endptr,16);if(!endptr||*endptr||v>0xffffffffUL){fprintf(stderr,"Invalid base\n");return 2;}firmware_base=(unsigned)v;}else if(argv[i][0]=='-'){fprintf(stderr,"Unknown option: %s\n",argv[i]);return 2;}else if(!notefile)notefile=argv[i];else {fprintf(stderr,"Unexpected argument: %s\n",argv[i]);return 2;}}char defaultnote[4096];if(!notefile){if(strlen(asmfile)+11>=sizeof(defaultnote)){fprintf(stderr,"Path too long\n");return 2;}snprintf(defaultnote,sizeof(defaultnote),"%s.notes.tsv",asmfile);notefile=defaultnote;}if(strlen(notefile)+11>=sizeof(bookmarkpath)){fprintf(stderr,"Bookmark path too long\n");return 2;}snprintf(bookmarkpath,sizeof(bookmarkpath),"%s.bookmarks",notefile);loadasm(asmfile);loadnotes();loadbookmarks();if(firmware_arg){if(!load_firmware(firmware_arg))snprintf(status,sizeof(status),"Cannot load firmware: %.200s",firmware_arg);}else {hex_visible=0;snprintf(status,sizeof(status),"No firmware supplied: use --firmware normal.bin");}if(!isatty(0)||!isatty(1)){fprintf(stderr,"Loaded %zu lines; terminal required for interactive mode.\n",count);return 0;}signal(SIGINT,sigexit);signal(SIGTERM,sigexit);raw();for(;;){draw();int c=key();size_t previous=selected;int record_navigation=0;if(c<0)break;if(c=='h'||c=='H'){hex_visible=!hex_visible;}
 else if(c==9){hex_focus=!hex_focus;hex_pinned=hex_focus;if(hex_focus && count && lines[selected].has_addr)hex_addr=lines[selected].addr;}
 else if(hex_focus && mapping_ok && (c==1001||c==1002||c==1003||c==1004)){
  size_t off;if(firmware_offset(hex_addr,&off)){
   int step=(c==1001?-16:c==1002?16:c==1003?-160:160);
   long long next=(long long)off+step;
   if(next>=0&&(unsigned long long)next<firmware_size)hex_addr=(unsigned)(firmware_base+(size_t)next);
  }
 }
 else if(c==1001||c=='k'){if(selected)selected--;}else if(c==1002||c=='j'){if(selected+1<count)selected++;}else if(c==1003){selected=selected>(size_t)(rows-3)?selected-(rows-3):0;}else if(c==1004){selected=selected+(size_t)(rows-3)<count?selected+(rows-3):(count?count-1:0);}else if(c==1005)selected=0;else if(c==1006)selected=count?count-1:0;else if(c=='f'||c=='F'){function_browser();record_navigation=1;}else if(c=='b'||c=='B'){toggle_bookmark();}else if(c=='m'||c=='M'){bookmark_browser();record_navigation=1;}else if(c=='g'||c=='G'){record_navigation=1;char buf[128]="";if(prompt("Go to hex address: ",buf,sizeof(buf))){char *p=buf;while(isspace((unsigned char)*p))p++;if(!strncmp(p,"0x",2))p+=2;unsigned a;if(hexaddr(p,&a))jump(a);else strcpy(status,"Invalid firmware address");}}else if(c=='/'){record_navigation=1;search[0]=0;if(prompt("Search: ",search,sizeof(search)))findnext(1);}else if(c=='n'){record_navigation=1;findnext(1);}else if(c=='p'){record_navigation=1;findnext(-1);}else if(c=='\r'||c=='\n'){record_navigation=1;if(count&&lines[selected].target){ssize_t dest=locate(lines[selected].dest);if(dest>=0){selected=(size_t)dest;}else snprintf(status,sizeof(status),"Target 0x%08X not listed",lines[selected].dest);}else strcpy(status,"No safe direct target parsed on this line");}else if(c==127||c==8||c=='['){nav_go_back();}else if(c==']'){nav_go_forward();}else if(c=='x'||c=='X'){if(count)xrefs();record_navigation=1;}else if(c=='N'||c==';'){if(count&&lines[selected].has_addr){Note *n=note(lines[selected].addr,1);char buf[2048];snprintf(buf,sizeof(buf),"%s",c=='N'?n->name:n->comment);if(prompt(c=='N'?"Function name: ":"Address comment: ",buf,sizeof(buf))){if(safe_field(buf)){char **dst=c=='N'?&n->name:&n->comment;free(*dst);*dst=dk_strdup(buf);dirty=1;strcpy(status,"Annotation modified; Ctrl+S to save");}else strcpy(status,"Tabs/newlines not allowed");}}else strcpy(status,"Select an addressed line for annotations");}else if(c==19)saveproject();else if(c=='q'||c=='Q'){if(dirty){char buf[16]="";if(prompt("Unsaved annotations: Q quit / S save / Esc cancel: ",buf,sizeof(buf))){if(buf[0]=='S'||buf[0]=='s'){saveproject();if(!dirty)break;}else if(buf[0]=='Q'||buf[0]=='q')break;}}else break; }
 if(record_navigation)nav_record(previous);
 }restore();return 0;}
