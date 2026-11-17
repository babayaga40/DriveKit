/* Original Pass 44/45 discovery and Pass 46 CFG listing; existing H8S decoder. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "drivekit_disasm.h"
#include "drivekit_normal_validator.h"
#include "drivekit_normal_tables.h"
#include "drivekit_code_survey.h"
#include "drivekit_pass84.h"
#include "drivekit_pass85.h"
#include "drivekit_pass86.h"
#include "drivekit_pass90.h"
#include "drivekit_pass91.h"
/* Pass 63: evidence-only accounting. Does not modify discovery or export. */
static int dk_p63_audit(FILE *idx,FILE *discovery,const char *audit_path,const char *leads_path){
 FILE *a=NULL,*l=NULL;char line[8192],copy[8192],*f[16],*p;size_t nf;
 unsigned long total=0,bounded=0,unresolved=0,not_eval=0,audit_total=0,audit_bounded=0,audit_conditional=0,audit_failed=0;
 unsigned long gap=0,flow=0,limit=0,budget=0,other=0;
 if(fseek(idx,0,SEEK_SET)||fseek(discovery,0,SEEK_SET))return 0;
 a=fopen(audit_path,"wb");l=fopen(leads_path,"wb");if(!a||!l)goto fail;
 fputs("DRIVEKIT_PASS63_DISCOVERY_AUDIT\nPOLICY EVIDENCE_ONLY NO_NEW_CODE_CLASSIFICATION\n",a);
 fputs("kind\taddress\tstatus\tcategory\treason\tfirst_caller_or_stop\n",l);
 while(fgets(line,sizeof(line),idx)){
  if(!strchr(line,'\n')&&!feof(idx))goto fail;
  memcpy(copy,line,strlen(line)+1);p=copy;nf=0;
  while(nf<16){f[nf++]=p;p=strchr(p,'\t');if(!p)break;*p++=0;}
  if(nf<3)continue;
  f[nf-1][strcspn(f[nf-1],"\r\n")]=0;
  if(!strcmp(f[0],"CALL_TARGET")){
   const char *cat=nf>14?f[14]:"UNKNOWN";
   const char *reason=nf>9?f[9]:"UNKNOWN";
   total++;
   if(!strcmp(f[2],"BOUNDED_CFG"))bounded++;
   else{
    if(!strcmp(f[2],"NOT_EVALUATED"))not_eval++;else unresolved++;
    if(!strcmp(cat,"DECODER_GAP"))gap++;
    else if(!strcmp(cat,"CONTROL_FLOW_UNRESOLVED"))flow++;
    else if(!strcmp(cat,"ANALYSIS_LIMIT"))limit++;
    else if(!strcmp(cat,"BUDGET_LIMIT"))budget++;
    else other++;
    fprintf(l,"CALL_TARGET\t%s\t%s\t%s\t%s\t%s\n",f[1],f[2],cat,reason,nf>4?f[4]:"");
   }
  }else if(!strcmp(f[0],"PASS45_AUDIT")){
   audit_total++;
   if(!strcmp(f[2],"BOUNDED_CFG"))audit_bounded++;
   else if(!strcmp(f[2],"BOUNDED_WITH_UNRESOLVED_INDIRECT_CALLS"))audit_conditional++;
   else audit_failed++;
   if(strcmp(f[2],"BOUNDED_CFG"))fprintf(l,"PASS45_AUDIT\t%s\t%s\t%s\t%s\t%s\n",f[1],f[2],"AUDIT_RESULT",f[2],nf>3?f[3]:"");
  }
 }
 if(ferror(idx))goto fail;
 fprintf(a,"CALL_TARGET_TOTAL %lu\nCALL_TARGET_BOUNDED %lu\nCALL_TARGET_UNRESOLVED %lu\nCALL_TARGET_NOT_EVALUATED %lu\n",total,bounded,unresolved,not_eval);
 fprintf(a,"UNEXPORTED_DECODER_GAP %lu\nUNEXPORTED_CONTROL_FLOW_UNRESOLVED %lu\nUNEXPORTED_ANALYSIS_LIMIT %lu\nUNEXPORTED_BUDGET_LIMIT %lu\nUNEXPORTED_OTHER %lu\n",gap,flow,limit,budget,other);
 fprintf(a,"PASS45_AUDITED %lu\nPASS45_STRICT_BOUNDED %lu\nPASS45_CONDITIONAL_INDIRECT_CALLS %lu\nPASS45_UNRESOLVED %lu\n",audit_total,audit_bounded,audit_conditional,audit_failed);
 fputs("\nHISTORICAL_DISCOVERY_REPORT_BEGIN\n",a);
 while(fgets(line,sizeof(line),discovery))if(fputs(line,a)==EOF)goto fail;
 if(ferror(discovery))goto fail;
 fputs("HISTORICAL_DISCOVERY_REPORT_END\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF\n",a);
 if(fclose(a)!=0){a=NULL;goto fail;}a=NULL;
 if(fclose(l)!=0){l=NULL;goto fail;}l=NULL;
 return 1;
 fail:if(a)fclose(a);if(l)fclose(l);remove(audit_path);remove(leads_path);return 0;
}
/* Pass 65: re-evaluate archived candidates against CURRENT firmware bytes and
 * the SAME H8S CFG exporter. Historical classifications never imply proof. */
static int dk_p65_reconcile(const unsigned char *b,size_t len,uint32_t base,const char *path){
 FILE *src=NULL,*out=NULL,*trace=NULL;char line[4096],copy[4096],status[160];
 unsigned long records=0,unique=0,strict=0,conditional=0,partial=0,invalid=0,duplicates=0,proposed=0;
 uint32_t *seen=NULL;size_t nseen=0,capacity=0;int ok=0;
 src=fopen(path,"rb");if(!src)return 1; /* optional evidence file */
 out=fopen("HISTORICAL_REVALIDATION.tsv","wb");if(!out)goto done;
 seen=(uint32_t*)calloc(4096,sizeof(*seen));if(!seen)goto done;capacity=4096;
 fputs("record_type\tentry_hex\tarchived_status\tcurrent_cfg_status\tcurrent_instructions\tarchived_provenance\tclassification\n",out);
 if(!fgets(line,sizeof(line),src))goto done;
 while(fgets(line,sizeof(line),src)){
  char *f[16],*p=copy,*end;size_t nf=0,i;unsigned long v;unsigned insns=0;int result;
  if(!strchr(line,'\n')&&!feof(src))goto done;
  memcpy(copy,line,strlen(line)+1);
  while(nf<16){f[nf++]=p;p=strchr(p,'\t');if(!p)break;*p++=0;}
  if(nf<14)goto done;
  for(i=0;i<nf;i++)f[i][strcspn(f[i],"\r\n")]=0;
  if(strcmp(f[0],"SEED")&&strcmp(f[0],"DISCOVERED_CALL_TARGET")&&strcmp(f[0],"PASS50_PROPOSED"))goto done;
  records++;if(!strcmp(f[0],"PASS50_PROPOSED"))proposed++;
  if(strncmp(f[1],"0x",2))goto done;
  v=strtoul(f[1],&end,0);if(*end||v>UINT32_MAX)goto done;
  for(i=0;i<nseen;i++)if(seen[i]==(uint32_t)v)break;
  if(i<nseen){duplicates++;continue;}
  if(nseen>=capacity)goto done;
  seen[nseen++]=(uint32_t)v;unique++;
  if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u)){
   invalid++;fprintf(out,"%s\t%s\t%s\tINVALID_ADDRESS\t0\t%s\tREVIEW_ONLY\n",f[0],f[1],f[2],f[13]);continue;
  }
  trace=tmpfile();if(!trace)goto done;
  result=dk_p46_export_one(b,len,base,trace,(uint32_t)v,0,&insns);
  if(!result)goto done;
  if(fflush(trace)||fseek(trace,0,SEEK_SET))goto done;
  strcpy(status,"UNKNOWN");
  while(fgets(line,sizeof(line),trace)){
   if(!strncmp(line,"; STATUS ",9)){
    char *q=line+9;size_t k=0;
    while(q[k]&&q[k]!=' '&&q[k]!='\r'&&q[k]!='\n'&&k<sizeof(status)-1){status[k]=q[k];k++;}
    status[k]=0;
   }
  }
  fclose(trace);trace=NULL;
  if(!strcmp(status,"BOUNDED_CFG"))strict++;
  else if(!strcmp(status,"CONDITIONAL_INDIRECT_CALLS"))conditional++;
  else partial++;
  fprintf(out,"%s\t%s\t%s\t%s\t%u\t%s\t%s\n",f[0],f[1],f[2],status,insns,f[13],"REVIEW_ONLY");
 }
 if(ferror(src)||ferror(out))goto done;
 {FILE *summary=fopen("HISTORICAL_REVALIDATION_SUMMARY.txt","wb");if(!summary)goto done;
  fprintf(summary,"DRIVEKIT_PASS65_HISTORICAL_REVALIDATION\nARCHIVE_RECORDS %lu\nUNIQUE_ADDRESSES %lu\nDUPLICATE_ADDRESSES %lu\nPROPOSED_RECORDS %lu\nCURRENT_CFG_BOUNDED %lu\nCURRENT_CFG_CONDITIONAL_INDIRECT_CALLS %lu\nCURRENT_CFG_PARTIAL %lu\nINVALID_ADDRESSES %lu\nPOLICY REVIEW_ONLY NO_AUTOMATIC_PROMOTION\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF\n",records,unique,duplicates,proposed,strict,conditional,partial,invalid);
  if(fclose(summary))goto done;
 }
 ok=1;
 done:if(trace)fclose(trace);if(src)fclose(src);if(out)fclose(out);free(seen);
 if(!ok){remove("HISTORICAL_REVALIDATION.tsv");remove("HISTORICAL_REVALIDATION_SUMMARY.txt");}
 return ok;
}

/* Pass 66: merge evidence inventories, NOT proof classifications.  The original
 * strict exporter remains untouched; bounded historical CFGs are regenerated
 * in a separate review assembly from the actual firmware bytes. */
static int dk_p66_recover(const unsigned char *b,size_t len,uint32_t base,FILE *current_index){
 FILE *hist=NULL,*registry=NULL,*asmout=NULL,*summary=NULL,*trace=NULL;
 char line[4096],copy[4096],status[160];
 uint32_t *current=NULL;size_t nc=0,cap=4096;
 unsigned long historical=0,overlap=0,strict_only=0,bounded=0,conditional=0,partial=0,emitted=0;
 int ok=0;
 hist=fopen("HISTORICAL_DISCOVERY_INDEX.tsv","rb");if(!hist)return 1;
 current=(uint32_t*)calloc(cap,sizeof(*current));if(!current)goto done;
 if(fseek(current_index,0,SEEK_SET))goto done;
 while(fgets(line,sizeof(line),current_index)){
  char *p=line,*q,*end;unsigned long v;
  if(strncmp(p,"CALL_TARGET\t",12)&&strncmp(p,"PASS45_AUDIT\t",13))continue;
  q=strchr(p,'\t');if(!q)continue;p=q+1;q=strchr(p,'\t');if(!q)continue;*q=0;
  v=strtoul(p,&end,0);if(*end||v>UINT32_MAX)continue;
  {size_t i;for(i=0;i<nc&&current[i]!=(uint32_t)v;i++);if(i==nc){if(nc==cap)goto done;current[nc++]=(uint32_t)v;}}
 }
 if(ferror(current_index))goto done;
 registry=fopen("FUNCTION_CANDIDATE_UNIFIED.tsv","wb");
 asmout=fopen("HISTORICAL_BOUNDED_REVIEW.asm","wb");
 summary=fopen("PASS66_RECOVERY_SUMMARY.txt","wb");
 if(!registry||!asmout||!summary)goto done;
 fputs("entry_hex\tsource\tcurrent_discovery\tcfg_status\tinstructions\tclassification\n",registry);
 fprintf(asmout,"; DRIVEKIT PASS66 HISTORICAL BOUNDED REVIEW ONLY\n; Firmware bytes freshly decoded by the existing H8S CFG exporter\n; IMAGE_BASE 0x%08X IMAGE_BYTES %lu\n; NOT verified function boundaries; NOT loaded into editor automatically\n",base,(unsigned long)len);
 if(!fgets(line,sizeof(line),hist))goto done;
 while(fgets(line,sizeof(line),hist)){
  char *f[16],*p=copy,*end;size_t nf=0,i;unsigned long v;unsigned insns=0;int result;
  if(!strchr(line,'\n')&&!feof(hist))goto done;
  memcpy(copy,line,strlen(line)+1);
  while(nf<16){f[nf++]=p;p=strchr(p,'\t');if(!p)break;*p++=0;}
  if(nf<14)goto done;
  for(i=0;i<nf;i++)f[i][strcspn(f[i],"\r\n")]=0;
  v=strtoul(f[1],&end,0);if(*end||v>UINT32_MAX||v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))goto done;
  historical++;
  for(i=0;i<nc&&current[i]!=(uint32_t)v;i++);
  if(i<nc)overlap++;
  trace=tmpfile();if(!trace)goto done;
  result=dk_p46_export_one(b,len,base,trace,(uint32_t)v,0,&insns);
  if(!result||fflush(trace)||fseek(trace,0,SEEK_SET))goto done;
  strcpy(status,"UNKNOWN");
  while(fgets(line,sizeof(line),trace))if(!strncmp(line,"; STATUS ",9)){
   char *q=line+9;size_t k=0;
   while(q[k]&&q[k]!=' '&&q[k]!='\r'&&q[k]!='\n'&&k<sizeof(status)-1){status[k]=q[k];k++;}status[k]=0;
  }
  if(!strcmp(status,"BOUNDED_CFG")){
   bounded++;
   if(fseek(trace,0,SEEK_SET))goto done;
   fprintf(asmout,"\n; HISTORICAL_ENTRY 0x%08lX RECORD %s EVIDENCE %s REVIEW_ONLY\n",v,f[0],f[13]);
   while(fgets(line,sizeof(line),trace))if(fputs(line,asmout)==EOF)goto done;
   emitted++;
  }else if(!strcmp(status,"CONDITIONAL_INDIRECT_CALLS"))conditional++;
  else partial++;
  fprintf(registry,"0x%08lX\t%s\t%s\t%s\t%u\tREVIEW_ONLY\n",v,f[0],i<nc?"YES":"NO",status,insns);
  fclose(trace);trace=NULL;
 }
 if(ferror(hist))goto done;
 {size_t i;for(i=0;i<nc;i++){
  /* Current addresses not in the archive remain visible in the unified registry.
   * Determine membership by rewinding historical index (small, bounded file). */
  int found=0;char row[4096];
  if(fseek(hist,0,SEEK_SET))goto done;
  if(!fgets(row,sizeof(row),hist))goto done;
  while(fgets(row,sizeof(row),hist)){
   char *p=strchr(row,'\t'),*end;unsigned long v;
   if(!p)continue;v=strtoul(p+1,&end,0);
   if(end!=p+1&&v==current[i]){found=1;break;}
  }
  if(!found){fprintf(registry,"0x%08X\tCURRENT_DISCOVERY\tYES\tNOT_REVALIDATED_HERE\t0\tCURRENT_EVIDENCE\n",current[i]);strict_only++;}
 }}
 fprintf(summary,"DRIVEKIT_PASS66_UNIFIED_RECOVERY\nHISTORICAL_RECORDS %lu\nCURRENT_DISCOVERY_UNIQUE %lu\nOVERLAP_HISTORICAL_CURRENT %lu\nCURRENT_ONLY %lu\nUNIFIED_UNIQUE %lu\nHISTORICAL_BOUNDED_REVIEW %lu\nHISTORICAL_CONDITIONAL %lu\nHISTORICAL_PARTIAL %lu\nHISTORICAL_ASM_ENTRIES %lu\nPOLICY REVIEW_ONLY NO_AUTOMATIC_PROMOTION\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF\n",historical,(unsigned long)nc,overlap,strict_only,historical+strict_only,bounded,conditional,partial,emitted);
 if(ferror(registry)||ferror(asmout)||ferror(summary))goto done;
 ok=1;
 done:if(trace)fclose(trace);if(hist)fclose(hist);if(registry)fclose(registry);if(asmout)fclose(asmout);if(summary)fclose(summary);free(current);
 if(!ok){remove("FUNCTION_CANDIDATE_UNIFIED.tsv");remove("HISTORICAL_BOUNDED_REVIEW.asm");remove("PASS66_RECOVERY_SUMMARY.txt");}
 return ok;
}

/* Pass 67: audit instruction-address overlap, without promoting candidates.
 * Only the original historical 84 and strict 22 are compared.  The exporter
 * is reused verbatim; instruction starts come from its emitted trace. */
#define DK_P67_MAX 128
#define DK_P67_ADDRS 4096
typedef struct {
 uint32_t entry, starts[DK_P67_ADDRS];
 unsigned n, instructions;int strict, bounded, conditional, truncated;
 char status[96];
} dk_p67_item;
static int dk_p67_cmp(const void *a,const void *b){uint32_t x=*(const uint32_t*)a,y=*(const uint32_t*)b;return x<y?-1:x>y?1:0;}
static int dk_p67_has(const dk_p67_item *v,uint32_t a){return bsearch(&a,v->starts,v->n,sizeof(uint32_t),dk_p67_cmp)!=NULL;}
static int dk_p67_parse(FILE *trace,dk_p67_item *item){
 char line[512];
 if(fseek(trace,0,SEEK_SET))return 0;
 while(fgets(line,sizeof(line),trace)){
  unsigned long a;char tail;
  if(!strncmp(line,"; STATUS ",9)){
   size_t k=0;const char *q=line+9;
   while(q[k]&&q[k]!=' '&&q[k]!='\n'&&q[k]!='\r'&&k<sizeof(item->status)-1){item->status[k]=q[k];k++;}
   item->status[k]=0;
  }
  /* The existing exporter writes instruction lines with two spaces followed
   * by exactly eight hexadecimal address digits and two spaces. */
  if(strlen(line)>=12&&line[0]==' '&&line[1]==' '&&line[10]==' '&&line[11]==' '&&
     sscanf(line+2,"%8lx%c",&a,&tail)==2&&tail==' '&&a<=UINT32_MAX){
   if(item->n==DK_P67_ADDRS){item->truncated=1;continue;}
   item->starts[item->n++]=(uint32_t)a;
  }
 }
 return !ferror(trace)&&item->status[0]!=0;
}
static int dk_p67_audit(const unsigned char *b,size_t len,uint32_t base,FILE *current_index){
 dk_p67_item *items=NULL;FILE *hist=NULL,*trace=NULL,*out=NULL,*pairs=NULL,*summary=NULL;
 char line[4096];size_t n=0,i,j;unsigned long exact=0,shared_pairs=0,inside_pairs=0,disjoint_pairs=0;
 unsigned long strict_count=0,hist_count=0,bounded_hist=0,conditional_hist=0,partial_hist=0,excluded=0;
 int ok=0;
 items=(dk_p67_item*)calloc(DK_P67_MAX,sizeof(*items));if(!items)goto done;
 /* Current strict candidates are taken from the Pass 46 index statuses,
  * not from the 31 unfiltered call targets. */
 if(fseek(current_index,0,SEEK_SET))goto done;
 while(fgets(line,sizeof(line),current_index)){
  char *p=line,*q,*end;unsigned long v;int accepted=0;size_t k;
  if(!strncmp(p,"CALL_TARGET\t",12)){
   q=strchr(p,'\t');if(!q)continue;p=q+1;q=strchr(p,'\t');if(!q)continue;*q++=0;
   accepted=!strncmp(q,"BOUNDED_CFG",11);
  }else if(!strncmp(p,"PASS45_AUDIT\t",13)){
   q=strchr(p,'\t');if(!q)continue;p=q+1;q=strchr(p,'\t');if(!q)continue;*q++=0;
   accepted=!strncmp(q,"BOUNDED_CFG",11);
  }else continue;
  if(!accepted)continue;
  v=strtoul(p,&end,0);if(*end||v>UINT32_MAX)continue;
  for(k=0;k<n;k++)if(items[k].entry==(uint32_t)v)break;
  if(k<n)continue;
  if(n==DK_P67_MAX)goto done;
  items[n].entry=(uint32_t)v;items[n].strict=1;n++;strict_count++;
 }
 if(ferror(current_index))goto done;
 hist=fopen("HISTORICAL_84_REGISTRY.tsv","rb");if(!hist){fprintf(stderr,"Pass 67: missing HISTORICAL_84_REGISTRY.tsv\n");goto done;}
 if(!fgets(line,sizeof(line),hist))goto done;
 while(fgets(line,sizeof(line),hist)){
  char *end;unsigned long v;size_t k;
  v=strtoul(line,&end,0);if(end==line||v>UINT32_MAX)goto done;
  hist_count++;
  for(k=0;k<n;k++)if(items[k].entry==(uint32_t)v)break;
  if(k<n){exact++;continue;}
  if(n==DK_P67_MAX)goto done;
  items[n++].entry=(uint32_t)v;
 }
 if(ferror(hist))goto done;
 out=fopen("PASS67_CANDIDATE_OVERLAP.tsv","wb");pairs=fopen("PASS67_OVERLAP_PAIRS.tsv","wb");summary=fopen("PASS67_OVERLAP_SUMMARY.txt","wb");
 if(!out||!pairs||!summary)goto done;
 fputs("entry_hex\tsource\tcfg_status\tinstructions\tdecoded_starts\tentry_inside_other\tshared_with_other\tanalysis_truncated\tclassification\n",out);
 fputs("entry_a\tentry_b\tshared_instruction_starts\ta_inside_b\tb_inside_a\tinterpretation\n",pairs);
 for(i=0;i<n;i++){
  unsigned count=0;int r;
  trace=tmpfile();if(!trace)goto done;
  r=dk_p46_export_one(b,len,base,trace,items[i].entry,0,&count);
  if(!r||fflush(trace)||!dk_p67_parse(trace,&items[i]))goto done;
  qsort(items[i].starts,items[i].n,sizeof(uint32_t),dk_p67_cmp);
  items[i].instructions=count;
  items[i].bounded=!strcmp(items[i].status,"BOUNDED_CFG");
  items[i].conditional=!strcmp(items[i].status,"CONDITIONAL_INDIRECT_CALLS");
  if(!items[i].strict){if(items[i].bounded)bounded_hist++;else if(items[i].conditional)conditional_hist++;else partial_hist++;}
  if(items[i].truncated)excluded++;
  fclose(trace);trace=NULL;
 }
 for(i=0;i<n;i++){
  unsigned inside=0,shared=0;
  for(j=0;j<n;j++)if(i!=j){
   unsigned k,common=0;int a_in_b,b_in_a;
   a_in_b=dk_p67_has(&items[j],items[i].entry);
   b_in_a=dk_p67_has(&items[i],items[j].entry);
   for(k=0;k<items[i].n;k++)if(dk_p67_has(&items[j],items[i].starts[k]))common++;
   if(a_in_b)inside++;
   if(common)shared++;
   if(j>i){
    if(common)shared_pairs++;else disjoint_pairs++;
    if(a_in_b||b_in_a)inside_pairs++;
    if(common||a_in_b||b_in_a)
     fprintf(pairs,"0x%08X\t0x%08X\t%u\t%s\t%s\t%s\n",items[i].entry,items[j].entry,common,a_in_b?"YES":"NO",b_in_a?"YES":"NO",(items[i].truncated||items[j].truncated)?"INCOMPLETE_TRACE":"REVIEW_OVERLAP_NOT_PROOF");
   }
  }
  fprintf(out,"0x%08X\t%s\t%s\t%u\t%u\t%u\t%u\t%s\tREVIEW_ONLY\n",items[i].entry,items[i].strict?"CURRENT_STRICT":"HISTORICAL_84",items[i].status,items[i].instructions,items[i].n,inside,shared,items[i].truncated?"YES":"NO");
 }
 fprintf(summary,"DRIVEKIT_PASS67_OVERLAP_AUDIT\nCURRENT_STRICT_INDEX_ENTRIES %lu\nHISTORICAL_84_RECORDS %lu\nEXACT_ENTRY_OVERLAP %lu\nCOMPARED_UNIQUE %lu\nHISTORICAL_BOUNDED %lu\nHISTORICAL_CONDITIONAL %lu\nHISTORICAL_PARTIAL %lu\nPAIRS_SHARED_INSTRUCTION_STARTS %lu\nPAIRS_ENTRY_INSIDE_OTHER %lu\nPAIRS_NO_SHARED_STARTS %lu\nINCOMPLETE_TRACES %lu\nPOLICY REVIEW_ONLY NO_AUTOMATIC_PROMOTION\nNOTE NO_SHARED_STARTS_DOES_NOT_PROVE_DISJOINT_BYTE_RANGES\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF\n",strict_count,hist_count,exact,(unsigned long)n,bounded_hist,conditional_hist,partial_hist,shared_pairs,inside_pairs,disjoint_pairs,excluded);
 if(ferror(out)||ferror(pairs)||ferror(summary))goto done;
 ok=1;
 done:
 if(trace)fclose(trace);if(hist)fclose(hist);if(out)fclose(out);if(pairs)fclose(pairs);if(summary)fclose(summary);free(items);
 if(!ok){remove("PASS67_CANDIDATE_OVERLAP.tsv");remove("PASS67_OVERLAP_PAIRS.tsv");remove("PASS67_OVERLAP_SUMMARY.txt");}
 return ok;
}

int dk_functions_export(const char *firmware,const char *listing,const char *index,const char *summary){
 FILE *f=NULL,*idx=NULL,*report=NULL,*asmout=NULL,*sum=NULL;
 unsigned char *b=NULL;long size;int ok=0;
 f=fopen(firmware,"rb");if(!f){perror(firmware);goto done;}
 if(fseek(f,0,SEEK_END)|| (size=ftell(f))<=0 || (unsigned long)size>0x10000000UL || fseek(f,0,SEEK_SET)){
  fprintf(stderr,"makeasm: invalid firmware size\n");goto done;}
 b=(unsigned char*)malloc((size_t)size);if(!b){fprintf(stderr,"makeasm: allocation failed\n");goto done;}
 if(fread(b,1,(size_t)size,f)!=(size_t)size){fprintf(stderr,"makeasm: read failed\n");goto done;}
 fclose(f);f=NULL;
 idx=fopen(index,"w+");report=tmpfile();if(!idx||!report){perror("makeasm index");goto done;}
 fprintf(stderr,"makeasm: running historical Pass 44/45 bounded function discovery...\n");
 if(!dk_p45_report(b,(size_t)size,0x00410000U,report,idx,DK_P40_DEFAULT_BUDGET)){
  fprintf(stderr,"makeasm: function discovery failed; no listing generated\n");goto done;}
 if(fflush(idx)||fseek(idx,0,SEEK_SET)){fprintf(stderr,"makeasm: index rewind failed\n");goto done;}
 asmout=fopen(listing,"wb");sum=fopen(summary,"wb");if(!asmout||!sum){perror("makeasm listing");goto done;}
 fprintf(stderr,"makeasm: exporting Pass 46 CFG-reachable functions...\n");
 if(!dk_p46_export(b,(size_t)size,0x00410000U,idx,asmout,sum)){
  fprintf(stderr,"makeasm: Pass 46 export failed\n");goto done;}
 if(fflush(asmout)||fflush(sum)){fprintf(stderr,"makeasm: output write failed\n");goto done;}
 if(!dk_p66_recover(b,(size_t)size,0x00410000U,idx)){fprintf(stderr,"makeasm: Pass 66 recovery failed\n");goto done;}
 if(!dk_p67_audit(b,(size_t)size,0x00410000U,idx)){fprintf(stderr,"makeasm: Pass 67 overlap audit failed\n");goto done;}
 if(!dk84_discover(b,(size_t)size,0x00410000U)){fprintf(stderr,"makeasm: Pass 84 dynamic discovery failed\n");goto done;}
 if(!dk85_run(b,(size_t)size,0x00410000U,index,0)){fprintf(stderr,"makeasm: Pass 85 reachable call filter failed\n");goto done;}
 { FILE *pass86_seeds=fopen("PASS86_ANALYSIS_SEEDS.tsv","rb"); if(pass86_seeds){fclose(pass86_seeds); if(!dk86_run(b,(size_t)size,0x00410000U,"PASS86_ANALYSIS_SEEDS.tsv",2,128)){fprintf(stderr,"makeasm: optional Pass 86 analysis failed\n");goto done;}} }
 { FILE *pass90_seeds=fopen("PASS90_ANALYSIS_SEEDS.tsv","rb"); if(pass90_seeds){fclose(pass90_seeds); if(!dk90_run(b,(size_t)size,0x00410000U,"PASS90_ANALYSIS_SEEDS.tsv")){fprintf(stderr,"makeasm: optional Pass 90 location catalog failed\n");goto done;}} }
 if(!dk91_auto(b,(size_t)size,0x00410000U,index,2,128)){fprintf(stderr,"makeasm: Pass 91 automatic review generation failed\n");goto done;}
 if(!dk_p65_reconcile(b,(size_t)size,0x00410000U,"HISTORICAL_DISCOVERY_INDEX.tsv")){fprintf(stderr,"makeasm: historical revalidation failed\n");goto done;}
 fprintf(stderr,"makeasm: Pass 65 historical revalidation (if archive index present) complete\n");
 if(!dk_p63_audit(idx,report,"FUNCTIONS_DISCOVERY_AUDIT.txt","FUNCTIONS_REVIEW_LEADS.tsv")){
  fprintf(stderr,"makeasm: Pass 63 audit generation failed\n");goto done;
 }
 fprintf(stderr,"makeasm: Pass 63 audit FUNCTIONS_DISCOVERY_AUDIT.txt; leads FUNCTIONS_REVIEW_LEADS.tsv\n");
 fprintf(stderr,"makeasm: wrote %s (function candidates only)\n",listing);
 fprintf(stderr,"makeasm: evidence %s; summary %s\n",index,summary);
 ok=1;
 done:
 if(f)fclose(f);if(idx)fclose(idx);if(report)fclose(report);
 if(asmout)fclose(asmout);if(sum)fclose(sum);free(b);
 return ok?0:1;
}
