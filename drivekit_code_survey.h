#ifndef DRIVEKIT_CODE_SURVEY_H
#define DRIVEKIT_CODE_SURVEY_H
/* Pass 36: firmware-independent bounded candidate survey with diagnostics. Never execution proof. */
#define DK_P35_WINDOW 512u
#define DK_P35_MAX_INSNS 192u
#define DK_P35_MAX_SEEDS 2048u /* Pass 64: retain more unique pointer seeds; strict CFG policy unchanged */
#define DK_P35_MAX_POINTER_RUN 4096u
#define DK_P35_MAX_TOTAL_POINTERS 200000u
#define DK_P35_MAX_CALLS 64u
typedef struct {uint32_t address;unsigned sources;uint32_t first_pointer_run;unsigned pointer_references;} dk_p35_seed;
typedef struct {unsigned char starts[DK_P35_WINDOW];uint32_t branches[DK_P35_MAX_INSNS];unsigned branch_count;uint32_t returns[DK_P35_MAX_INSNS];unsigned return_count;} dk_p37_trace;
typedef struct {unsigned insns,returns,calls,branches;uint32_t call_targets[DK_P35_MAX_CALLS];unsigned stored_calls;const char *reason;uint32_t stop_address;unsigned char stop_bytes[8];unsigned stop_count;} dk_p35_result;
static int dk_p35_add(dk_p35_seed *s,size_t *count,uint32_t a,unsigned source){size_t i;
 for(i=0;i<*count;i++)if(s[i].address==a){s[i].sources|=source;return 1;}
 if(*count>=DK_P35_MAX_SEEDS)return 0;
 s[*count].address=a;s[*count].sources=source;s[*count].first_pointer_run=0;s[*count].pointer_references=0;(*count)++;return 1;
}
static void dk_p36_stop(dk_p35_result *r,const unsigned char *b,size_t len,uint32_t base,size_t off){
 size_t k;r->stop_address=(uint32_t)((uint64_t)base+off);r->stop_count=0;
 if(off>=len)return;
 for(k=0;k<8&&off+k<len;k++)r->stop_bytes[r->stop_count++]=b[off+k];
}
/* Optional global decode accounting for Pass 40; NULL leaves earlier passes unchanged. */
static size_t *dk_p40_budget_remaining=NULL;
static size_t *dk_p40_budget_used=NULL;
static int dk_p40_charge(void){
 if(!dk_p40_budget_remaining)return 1;
 if(!*dk_p40_budget_remaining)return 0;
 --*dk_p40_budget_remaining;++*dk_p40_budget_used;return 1;
}
static int dk_p37_check_trace(const unsigned char *b,size_t len,uint32_t base,uint32_t address,dk_p35_result *r,dk_p37_trace *trace){
 unsigned char mark[DK_P35_WINDOW]={0},queued[DK_P35_WINDOW]={0};unsigned short queue[DK_P35_WINDOW];size_t head=0,tail=0,start,fail_off=0;
 memset(r,0,sizeof(*r));if(trace)memset(trace,0,sizeof(*trace));r->reason="UNRESOLVED";
 if(address<base||(uint64_t)address>=(uint64_t)base+len||(address&1u)){r->reason="OUT_OF_RANGE_OR_UNALIGNED";r->stop_address=address;return 0;}
 start=address-base;fail_off=start;queue[tail++]=0;queued[0]=1;
 while(head<tail){size_t at=queue[head++],off=start+at,n,j;char op[192];int ht=0,ft=0,is_call=0;uint64_t dest=0;
  fail_off=off;
  if(at>=DK_P35_WINDOW||off>=len){r->reason="WINDOW_LIMIT";goto fail;}
  if(mark[at]==1)continue;
  if(mark[at]==2){r->reason="INSTRUCTION_OVERLAP";goto fail;}
  if(r->insns>=DK_P35_MAX_INSNS){r->reason="INSTRUCTION_LIMIT";goto fail;}
  if(!dk_p40_charge()){r->reason="GLOBAL_DECODE_BUDGET";goto fail;}
  n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>DK_P35_WINDOW-at||n>len-off||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED")){r->reason="UNSUPPORTED_DECODE";goto fail;}
  for(j=0;j<n;j++)if(mark[at+j]){r->reason="INSTRUCTION_OVERLAP";goto fail;}
  mark[at]=1;for(j=1;j<n;j++)mark[at+j]=2;r->insns++;if(trace)trace->starts[at]=1;
  if(b[off]==0x54&&n==2&&b[off+1]==0x70){r->returns++;if(trace&&trace->return_count<DK_P35_MAX_INSNS)trace->returns[trace->return_count++]=(uint32_t)((uint64_t)base+off);continue;}
  if(b[off]==0x56&&n==2&&b[off+1]==0x70){r->reason="EXCEPTION_RETURN";goto fail;}
  if(b[off]==0x59||b[off]==0x5d||b[off]==0x5f||b[off]==0x57||
     (b[off]==0x01&&n>=2&&b[off+1]==0x80)) {r->reason="INDIRECT_OR_SPECIAL_FLOW";goto fail;}
  dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
  is_call=(b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4);
  if(is_call){
   if(!ht||dest>0xffffffffu||(dest&1u)){r->reason="UNRESOLVED_CALL";goto fail;}
   r->calls++;if(r->stored_calls<DK_P35_MAX_CALLS)r->call_targets[r->stored_calls++]=(uint32_t)dest;
   ht=0;ft=1; /* call return is assumed for survey, not proven */
  }else if(ht){size_t d;
   r->branches++;if(trace&&trace->branch_count<DK_P35_MAX_INSNS&&dest<=0xffffffffu)trace->branches[trace->branch_count++]=(uint32_t)dest;
   if(dest<address||dest>=(uint64_t)address+DK_P35_WINDOW){r->reason="BRANCH_OUTSIDE_WINDOW";goto fail;}
   d=(size_t)(dest-address);
   if((d&1u)||mark[d]==2){r->reason="BRANCH_MISALIGNED";goto fail;}
   if(!queued[d]){if(tail>=DK_P35_WINDOW){r->reason="QUEUE_LIMIT";goto fail;}queued[d]=1;queue[tail++]=(unsigned short)d;}
  }
  if(ft){size_t d=at+n;
   if(d>=DK_P35_WINDOW){r->reason="FALLTHROUGH_OUTSIDE_WINDOW";goto fail;}
   if((d&1u)||mark[d]==2){r->reason="FALLTHROUGH_MISALIGNED";goto fail;}
   if(!queued[d]){if(tail>=DK_P35_WINDOW){r->reason="QUEUE_LIMIT";goto fail;}queued[d]=1;queue[tail++]=(unsigned short)d;}
  }else if(!ht){r->reason="UNKNOWN_TERMINAL";goto fail;}
 }
 if(!r->returns){r->reason="NO_RETURN";fail_off=start;goto fail;}
 r->reason="BOUNDED_CFG";return 1;
 fail:dk_p36_stop(r,b,len,base,fail_off);return 0;
}
static int dk_p35_check(const unsigned char *b,size_t len,uint32_t base,uint32_t address,dk_p35_result *r){return dk_p37_check_trace(b,len,base,address,r,NULL);}
typedef struct {uint32_t address;const char *reason;size_t references;unsigned char bytes[8];unsigned count;} dk_p37_site;
/* Pass 38: print only instructions independently visited by the bounded CFG walk.
   This is a candidate listing, never a certified function or runtime entry. */
static int dk_p38_listing(const unsigned char *b,size_t len,uint32_t base,uint32_t entry,FILE *o){
 dk_p37_trace tr;dk_p35_result r;size_t k,n,printed=0;char op[192];int ok;
 if(!b||!o||entry<base||(entry&1u)||(uint64_t)entry>=(uint64_t)base+len)return 0;
 ok=dk_p37_check_trace(b,len,base,entry,&r,&tr);
 fprintf(o,"DRIVEKIT_PASS38_BOUNDED_ASSEMBLY\nENTRY_CANDIDATE 0x%08X\nSTATUS %s\nINSTRUCTIONS %u RETURNS %u CALLS %u BRANCHES %u\nENTRY_NOT_PROVEN RUNTIME_REACHABILITY_NOT_PROVEN CALL_RETURNS_ASSUMED\n",entry,r.reason,r.insns,r.returns,r.calls,r.branches);
 if(!ok){size_t t;fprintf(o,"PARTIAL_CFG_ONLY FAILURE_AT 0x%08X BYTES",r.stop_address);for(t=0;t<r.stop_count;t++)fprintf(o," %02X",r.stop_bytes[t]);fprintf(o,"\n");}
 fprintf(o,"ASSEMBLY_BEGIN\n");
 for(k=0;k<DK_P35_WINDOW;k++)if(tr.starts[k]){
  size_t off=(size_t)(entry-base)+k,j;
  if(off>=len)return 0;
  n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>len-off||n>DK_P35_WINDOW-k||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED"))return 0;
  fprintf(o,"0x%08X  ",(uint32_t)((uint64_t)entry+k));
  for(j=0;j<n;j++)fprintf(o,"%02X%s",b[off+j],j+1==n?"":" ");
  for(j=n;j<8;j++)fprintf(o,"   ");
  fprintf(o,"  %s\n",op);printed++;
 }
 fprintf(o,"ASSEMBLY_END\nPRINTED_INSTRUCTIONS %lu\n",(unsigned long)printed);
 return !ferror(o)&&printed==r.insns;
}
/* Pass 39: RTS-anchored backwards candidate reconstruction.
   Raw matches are never proof of instruction boundaries. All scans are bounded. */
#define DK_P39_BACK 128u
#define DK_P39_MAX_RTS 4096u
static int dk_p39_forward_to_rts(const unsigned char *b,size_t len,uint32_t base,size_t start,size_t rts,size_t *insns){
 size_t off=start,count=0;char op[192];
 if(start>rts||rts+2>len||((start^rts)&1u))return 0;
 while(off<=rts&&count<DK_P35_MAX_INSNS){size_t n; if(!dk_p40_charge())return 0;n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>len-off||off+n>rts+2||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED"))return 0;
  if(off==rts){if(n!=2||b[off]!=0x54||b[off+1]!=0x70)return 0;*insns=count+1;return 1;}
  if((b[off]==0x54&&n==2&&b[off+1]==0x70)||(b[off]==0x56&&n==2&&b[off+1]==0x70))return 0;
  off+=n;count++;
 }
 (void)base;return 0;
}
static int dk_p39_report(const unsigned char *b,size_t len,uint32_t base,FILE *o){
 size_t at,raw=0,processed=0,validated=0,uncertain=0,limit=0,ambiguous=0;unsigned long long tested=0;
 if(!b||!o||(uint64_t)base+len>0x100000000ULL)return 0;
 fprintf(o,"DRIVEKIT_PASS39_RTS_BACKWARD_RECONSTRUCTION\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nBACKWARD_WINDOW %u\nMAX_RTS_ANALYSED %u\n",base,(unsigned long)len,DK_P39_BACK,DK_P39_MAX_RTS);
 for(at=0;at+1<len;at+=2){size_t low,scan,chosen=0,ways=0,decoded=0;int boundary=0;dk_p37_trace tr;dk_p35_result r;int cfg=0,seen=0;
  if(b[at]!=0x54||b[at+1]!=0x70)continue;
  raw++;
  if(processed>=DK_P39_MAX_RTS){limit++;continue;}
  processed++;
  low=at>DK_P39_BACK?at-DK_P39_BACK:0;
  /* Search nearest potential no-fallthrough boundary on even positions. A raw
     terminator may itself be an immediate: this is a hint, never proof. */
  for(scan=at;scan>=low+2;scan-=2){size_t prev=scan-2;
   if(b[prev]==0x54&&b[prev+1]==0x70){low=prev+2;boundary=1;break;}
   if(b[prev]==0x40){low=prev+2;boundary=1;break;}
   if(prev>=2&&b[prev-2]==0x5a){low=prev+2;boundary=1;break;}
   if(prev==low)break;
  }
  /* Enumerate every even-aligned proposed entry in the bounded window.
     Only accept one if its forward decoding AND CFG visit this RTS. */
  for(scan=low;scan<at;scan+=2){size_t nins=0,k;int hit=0;
   if(!dk_p39_forward_to_rts(b,len,base,scan,at,&nins))continue;
   tested++;
   if(!dk_p37_check_trace(b,len,base,(uint32_t)((uint64_t)base+scan),&r,&tr))continue;
   for(k=0;k<DK_P35_WINDOW;k++)if(tr.starts[k]&&scan+k==at){hit=1;break;}
   if(!hit)continue;
   if(!ways){chosen=scan;decoded=nins;cfg=1;seen=(int)r.returns;}
   ways++;
  }
  if(!ways){uncertain++;fprintf(o,"RTS_RAW 0x%08X STATUS BOUNDARY_UNCERTAIN NO_VALIDATED_FORWARD_CFG\n",(unsigned)((uint64_t)base+at));}
  else {validated++;if(ways>1)ambiguous++;
   fprintf(o,"RTS_VALIDATED 0x%08X CANDIDATE_START 0x%08X LINEAR_INSNS %lu CFG_RETURNS %d START_CHOICES %lu BOUNDARY_HINT %s STATUS %s ENTRY_NOT_PROVEN\n",
    (unsigned)((uint64_t)base+at),(unsigned)((uint64_t)base+chosen),(unsigned long)decoded,seen,(unsigned long)ways,boundary?"RAW_TERMINATOR":"WINDOW_EDGE",ways>1?"MULTIPLE_PLAUSIBLE_STARTS":"SINGLE_BOUNDED_START");
  }
  (void)cfg;
 }
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_RTS_ANALYSED %lu\nSUMMARY_RTS_VALIDATED %lu\nSUMMARY_BOUNDARY_UNCERTAIN %lu\nSUMMARY_MULTIPLE_PLAUSIBLE_STARTS %lu\nSUMMARY_RTS_LIMITED %lu\nSUMMARY_FORWARD_CFG_ATTEMPTS %llu\nNO_FUNCTION_ENTRY_PROOF NO_RUNTIME_REACHABILITY_PROOF RAW_TERMINATORS_ARE_HINTS\n",(unsigned long)raw,(unsigned long)processed,(unsigned long)validated,(unsigned long)uncertain,(unsigned long)ambiguous,(unsigned long)limit,tested);
 return !ferror(o);
}

/* Pass 40: independent, pointer-seeded call-site evidence plus RTS-first
   backward reconstruction. The global budget counts ALL decoder invocations. */
#define DK_P40_DEFAULT_BUDGET 10000u
#define DK_P40_MAX_BUDGET 2000000u
#define DK_P40_MAX_REFERENCES 4096u
typedef struct {uint32_t target,caller;unsigned target_cfg_ok;unsigned target_returns;unsigned target_insns;uint32_t first_return;} dk_p40_ref;
static int dk_p40_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,size_t budget){
 dk_p40_ref *refs=NULL;size_t refs_n=0,remaining=budget,used=0,seed_count=0,seed_limited=0,raw=0,processed=0,validated=0,uncertain=0,ambiguous=0,unprocessed=0,call_checked=0,call_bounded=0,call_unresolved=0;
 dk_p35_seed *seeds=NULL;size_t i,j,at;int ok=0;
 if(!b||!o||!budget||budget>DK_P40_MAX_BUDGET||(uint64_t)base+len>0x100000000ULL)return 0;
 refs=(dk_p40_ref*)calloc(DK_P40_MAX_REFERENCES,sizeof(*refs));seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));if(!refs||!seeds)goto cleanup;
 fprintf(o,"DRIVEKIT_PASS40_EVIDENCE_DRIVEN_RECONSTRUCTION\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nGLOBAL_DECODE_BUDGET %lu\nBACKWARD_WINDOW %u\n",base,(unsigned long)len,(unsigned long)budget,DK_P39_BACK);
 dk_p40_budget_remaining=&remaining;dk_p40_budget_used=&used;
 /* Externally structured pointer runs are candidate seeds, not confirmed code. */
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  for(j=0;j<n;j++)if(!dk_p35_add(seeds,&seed_count,dk_p33_be32(b+i+j*4),2))seed_limited++;
 }
 /* Only calls observed from a fully bounded, pointer-seeded CFG become
    call-reference evidence. Call return remains an explicit assumption. */
 for(i=0;i<seed_count&&remaining&&used<budget/4;i++){
  dk_p35_result r;dk_p37_trace tr;int good=dk_p37_check_trace(b,len,base,seeds[i].address,&r,&tr);
  if(!good)continue;
  for(j=0;j<DK_P35_WINDOW;j++)if(tr.starts[j]){
   size_t off=(size_t)(seeds[i].address-base)+j;size_t n;char op[192];int ht=0,ft=0;uint64_t dest=0;size_t k;
   if(off>=len)continue;
   /* Already decoded by validated CFG: no extra decode charge is necessary
      for the cached instruction start, but re-decode to inspect its size. */
   if(!dk_p40_charge())break;
   n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
   if(!n||n>len-off)continue;
   if(!((b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4)))continue;
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   if(!ht||dest<base||dest>=(uint64_t)base+len||(dest&1u))continue;
   for(k=0;k<refs_n;k++)if(refs[k].target==(uint32_t)dest&&refs[k].caller==(uint32_t)(base+off))break;
   if(k==refs_n&&refs_n<DK_P40_MAX_REFERENCES){refs[k].target=(uint32_t)dest;refs[k].caller=(uint32_t)(base+off);refs_n++;}
  }
 }
 fprintf(o,"POINTER_SEEDS %lu POINTER_SEEDS_LIMITED %lu\nVALIDATED_CFG_DIRECT_CALL_REFERENCES %lu\n",(unsigned long)seed_count,(unsigned long)seed_limited,(unsigned long)refs_n);
 /* Call targets are evaluated before orphan RTS sites so the global budget
    prioritizes independently supported entry candidates. */
 for(i=0;i<refs_n&&remaining&&used<budget/2;i++){
  dk_p35_result r;dk_p37_trace tr;int good;
  call_checked++;good=dk_p37_check_trace(b,len,base,refs[i].target,&r,&tr);
  if(good){call_bounded++;refs[i].target_cfg_ok=1;refs[i].target_returns=r.returns;refs[i].target_insns=r.insns;
   if(tr.return_count)refs[i].first_return=tr.returns[0];
   fprintf(o,"CALL_REFERENCED_ENTRY 0x%08X JSR_FROM 0x%08X STATUS BOUNDED_ROUTINE INSTRUCTIONS %u RETURNS %u FIRST_RTS 0x%08X CALL_RETURNS_ASSUMED RUNTIME_NOT_PROVEN\n",refs[i].target,refs[i].caller,r.insns,r.returns,refs[i].first_return);
  }else{call_unresolved++;fprintf(o,"CALL_REFERENCED_ENTRY 0x%08X JSR_FROM 0x%08X STATUS UNRESOLVED REASON %s\n",refs[i].target,refs[i].caller,r.reason);}
 }
 /* RTS-first scan; no per-RTS cap. Budget exhaustion is visible and explicit. */
 for(at=0;at+1<len;at+=2){size_t low,scan,choices=0,shortest=0,longest=0,short_insns=0;unsigned direct_refs=0;uint32_t strongest=0;
  if(b[at]!=0x54||b[at+1]!=0x70)continue;
  raw++;
  if(!remaining){unprocessed++;continue;}processed++;
  low=at>DK_P39_BACK?at-DK_P39_BACK:0;
  for(scan=low;scan<at&&remaining;scan+=2){size_t nins=0,k;dk_p35_result r;dk_p37_trace tr;int hit=0;
   if(!dk_p39_forward_to_rts(b,len,base,scan,at,&nins))continue;
   if(!remaining)break;
   if(!dk_p37_check_trace(b,len,base,(uint32_t)(base+scan),&r,&tr))continue;
   for(k=0;k<DK_P35_WINDOW;k++)if(tr.starts[k]&&scan+k==at){hit=1;break;}
   if(!hit)continue;
   if(!choices){longest=scan;shortest=scan;short_insns=nins;}
   else {shortest=scan;short_insns=nins;}
   choices++;
  }
  if(!choices){uncertain++;fprintf(o,"RTS_SITE 0x%08X STATUS %s\n",(unsigned)(base+at),remaining?"BOUNDARY_UNCERTAIN":"BUDGET_INTERRUPTED");continue;}
  validated++;if(choices>1)ambiguous++;
  for(i=0;i<refs_n;i++)if(refs[i].target_cfg_ok&&refs[i].first_return==(uint32_t)(base+at)){
   direct_refs++;if(!strongest||refs[i].target<strongest)strongest=refs[i].target;
  }
  fprintf(o,"RTS_SITE 0x%08X SUFFIX_START 0x%08X SUFFIX_INSNS %lu LONGEST_BOUNDED_START 0x%08X START_CHOICES %lu STATUS CLEAN_SUFFIX %s\n",(unsigned)(base+at),(unsigned)(base+shortest),(unsigned long)short_insns,(unsigned)(base+longest),(unsigned long)choices,direct_refs?"CALL_LINKED":"ORPHAN_CANDIDATE_NO_OBSERVED_DIRECT_JSR");
  if(direct_refs)fprintf(o,"  ROUTINE_START 0x%08X EVIDENCE VALIDATED_CFG_JSR_TARGET BOUNDED_CFG FIRST_RTS_MATCH JSR_REFERENCES %u ENTRY_RUNTIME_NOT_PROVEN\n",strongest,direct_refs);
 }
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_RTS_ANALYSED %lu\nSUMMARY_RTS_VALIDATED %lu\nSUMMARY_RTS_UNCERTAIN %lu\nSUMMARY_MULTIPLE_SUFFIXES %lu\nSUMMARY_RTS_NOT_ANALYSED_BUDGET %lu\nSUMMARY_CALL_TARGETS_CHECKED %lu\nSUMMARY_CALL_TARGETS_BOUNDED %lu\nSUMMARY_CALL_TARGETS_UNRESOLVED %lu\nDECODE_BUDGET_USED %lu\nDECODE_BUDGET_REMAINING %lu\nANALYSIS_TRUNCATED %s\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF POINTER_SEEDS_NOT_PROVEN CALL_RETURNS_ASSUMED\n",(unsigned long)raw,(unsigned long)processed,(unsigned long)validated,(unsigned long)uncertain,(unsigned long)ambiguous,(unsigned long)unprocessed,(unsigned long)call_checked,(unsigned long)call_bounded,(unsigned long)call_unresolved,(unsigned long)used,(unsigned long)remaining,remaining?"NO":"YES");
 ok=!ferror(o);
 cleanup:dk_p40_budget_remaining=NULL;dk_p40_budget_used=NULL;free(refs);free(seeds);return ok;
}

/* Pass 41: call-first, unique-target CFG cache and return-site index.
   Cache contains only bounded, pointer-seeded call targets. Not runtime proof. */
typedef struct {uint32_t address;unsigned references,insns,returns;unsigned bounded;const char *reason;uint32_t first_caller;} dk_p41_target;
static int dk_p41_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,size_t budget){
 dk_p35_seed *seeds=NULL;dk_p41_target *targets=NULL;unsigned char *return_index=NULL;
 size_t remaining=budget,used=0,seed_count=0,seed_limited=0,targets_n=0,refs=0,raw=0,covered=0,orphan=0,uncertain=0,unvisited=0,skipped=0,attempted=0;
 size_t i,j,at;int ok=0,call_budget_stopped=0;
 if(!b||!o||!budget||budget>DK_P40_MAX_BUDGET||(uint64_t)base+len>0x100000000ULL)return 0;
 seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));
 targets=(dk_p41_target*)calloc(DK_P40_MAX_REFERENCES,sizeof(*targets));
 return_index=(unsigned char*)calloc(len?len:1,1);
 if(!seeds||!targets||!return_index)goto done;
 fprintf(o,"DRIVEKIT_PASS41_CALL_FIRST_FUNCTION_INDEX\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nGLOBAL_DECODE_BUDGET %lu\nBACKWARD_WINDOW %u\n",base,(unsigned long)len,(unsigned long)budget,DK_P39_BACK);
 dk_p40_budget_remaining=&remaining;dk_p40_budget_used=&used;
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  for(j=0;j<n;j++)if(!dk_p35_add(seeds,&seed_count,dk_p33_be32(b+i+j*4),2))seed_limited++;
 }
 /* Discover direct calls in bounded seed CFGs, retaining unique destinations.
    Reserve half the budget for evaluating targets and orphan RTS work. */
 for(i=0;i<seed_count&&remaining&&used<budget/4;i++){
  dk_p35_result r;dk_p37_trace tr;
  if(!dk_p37_check_trace(b,len,base,seeds[i].address,&r,&tr))continue;
  for(j=0;j<DK_P35_WINDOW&&remaining;j++)if(tr.starts[j]){
   size_t off=(size_t)(seeds[i].address-base)+j,n,k;char op[192];int ht=0,ft=0;uint64_t dest=0;
   if(off>=len||!dk_p40_charge())break;
   n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
   if(!n||n>len-off||!((b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4)))continue;
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   if(!ht||dest<base||dest>=(uint64_t)base+len||(dest&1u))continue;
   refs++;
   for(k=0;k<targets_n;k++)if(targets[k].address==(uint32_t)dest)break;
   if(k==targets_n){if(targets_n==DK_P40_MAX_REFERENCES){skipped++;continue;}
    targets[k].address=(uint32_t)dest;targets[k].first_caller=(uint32_t)(base+off);targets_n++;}
   targets[k].references++;
  }
 }
 fprintf(o,"POINTER_SEEDS %lu POINTER_SEEDS_LIMITED %lu\nDIRECT_CALL_REFERENCES %lu\nUNIQUE_CALL_TARGETS %lu\nCALL_TARGETS_DROPPED_CAP %lu\n",(unsigned long)seed_count,(unsigned long)seed_limited,(unsigned long)refs,(unsigned long)targets_n,(unsigned long)skipped);
 /* One CFG per unique target, cache ALL return addresses, not only first RTS. */
 for(i=0;i<targets_n;i++){
  dk_p35_result r;dk_p37_trace tr;int good;size_t k;
  if(!remaining||used>=budget*3/4){call_budget_stopped=1;break;}
  attempted++;good=dk_p37_check_trace(b,len,base,targets[i].address,&r,&tr);
  targets[i].reason=r.reason;
  if(good){targets[i].bounded=1;targets[i].insns=r.insns;targets[i].returns=r.returns;
   for(k=0;k<tr.return_count;k++){
    uint32_t addr=tr.returns[k];if(addr>=base&&(uint64_t)addr<(uint64_t)base+len)return_index[addr-base]=1;
   }
  }
  fprintf(o,"CALL_ENTRY 0x%08X JSR_FROM_FIRST 0x%08X DIRECT_REFERENCES %u STATUS %s INSTRUCTIONS %u RETURNS %u RUNTIME_NOT_PROVEN\n",
   targets[i].address,targets[i].first_caller,targets[i].references,good?"BOUNDED_CFG":r.reason,r.insns,r.returns);
 }
 /* A call-supported return is reported without backward re-decoding. */
 for(at=0;at+1<len;at+=2){
  size_t low,scan,choices=0,longest=0,shortest=0,short_insns=0;
  if(b[at]!=0x54||b[at+1]!=0x70)continue;
  raw++;
  if(return_index[at]){covered++;fprintf(o,"RTS_SITE 0x%08X STATUS CALL_SUPPORTED_RETURN ENTRY_EVIDENCE INDEXED_BOUNDED_CALL_TARGET NO_BACKWARD_REDECODE\n",(unsigned)(base+at));continue;}
  if(!remaining){unvisited++;continue;}
  /* Avoid the O(window * CFG) candidate explosion: first find linear clean
     suffixes, then perform at most ONE bounded CFG confirmation per RTS. */
  low=at>DK_P39_BACK?at-DK_P39_BACK:0;
  for(scan=at>=2?at-2:at;scan>=low&&scan<at&&remaining;){size_t nins=0;
   if(dk_p39_forward_to_rts(b,len,base,scan,at,&nins)){
    if(!choices){shortest=scan;short_insns=nins;}longest=scan;choices++;
   }
   if(scan<low+2)break;
   scan-=2;
  }
  if(choices&&remaining){dk_p35_result r;dk_p37_trace tr;size_t k;int hit=0;
   if(dk_p37_check_trace(b,len,base,(uint32_t)(base+longest),&r,&tr))
    for(k=0;k<DK_P35_WINDOW;k++)if(tr.starts[k]&&longest+k==at){hit=1;break;}
   if(hit){orphan++;fprintf(o,"RTS_SITE 0x%08X STATUS ORPHAN_CLEAN_SUFFIX SUFFIX_START 0x%08X SUFFIX_INSNS %lu LONGEST_LINEAR_START 0x%08X LINEAR_START_CHOICES %lu ENTRY_NOT_PROVEN\n",
    (unsigned)(base+at),(unsigned)(base+shortest),(unsigned long)short_insns,(unsigned)(base+longest),(unsigned long)choices);continue;}
  }
  uncertain++;fprintf(o,"RTS_SITE 0x%08X STATUS %s ENTRY_NOT_PROVEN\n",(unsigned)(base+at),remaining?"BOUNDARY_UNCERTAIN":"BUDGET_INTERRUPTED");
 }
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_CALL_SUPPORTED_RTS %lu\nSUMMARY_ORPHAN_CLEAN_SUFFIX %lu\nSUMMARY_BOUNDARY_UNCERTAIN %lu\nSUMMARY_RTS_NOT_ANALYSED_BUDGET %lu\nSUMMARY_UNIQUE_CALL_TARGETS %lu\nSUMMARY_CALL_TARGETS_EVALUATED %lu\nSUMMARY_CALL_TARGETS_NOT_EVALUATED %lu\nDECODE_BUDGET_USED %lu\nDECODE_BUDGET_REMAINING %lu\nANALYSIS_TRUNCATED %s\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF POINTER_SEEDS_NOT_PROVEN CALL_RETURNS_ASSUMED\n",
  (unsigned long)raw,(unsigned long)covered,(unsigned long)orphan,(unsigned long)uncertain,(unsigned long)unvisited,(unsigned long)targets_n,(unsigned long)attempted,(unsigned long)(targets_n-attempted),(unsigned long)used,(unsigned long)remaining,(unvisited||call_budget_stopped||skipped)?"YES":"NO");
 ok=!ferror(o);
 done:dk_p40_budget_remaining=NULL;dk_p40_budget_used=NULL;free(seeds);free(targets);free(return_index);return ok;
}

/* Pass 42: call-first auditable function index and evidence-prioritized orphan probes.
   A call reference requires a bounded pointer-seeded CFG. Entries and orphan
   suffixes are candidates only; no runtime or globally closed boundary proof. */
#define DK_P42_MAX_ORPHAN_PROBES 256u
#define DK_P42_NEAR_BYTES 2048u
#define DK_P42_ORPHAN_BUDGET_DIVISOR 8u
#define DK_P42_MAX_CALLERS 4096u
typedef struct {uint32_t entry,first_caller;unsigned refs,insns,returns,attempted,bounded;const char *reason;uint32_t rts[DK_P35_MAX_INSNS];unsigned rts_count;} dk_p42_target;
typedef struct {uint32_t target,caller;} dk_p42_edge;
static int dk_p42_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,FILE *tsv,size_t budget){
 dk_p35_seed *seeds=NULL;dk_p42_target *targets=NULL;dk_p42_edge *edges=NULL;
 unsigned char *supported=NULL;size_t *raw_rts=NULL;
 size_t remaining=budget,used=0,seed_n=0,seed_limited=0,target_n=0,edge_n=0,edge_dropped=0;
 size_t raw_n=0,covered=0,near_n=0,orphan_probes=0,orphan_suffix=0,orphan_uncertain=0,unexamined=0;
 size_t i,j,k,seed_cut,orphan_cut,orphan_start;int ok=0;
 if(!b||!o||!tsv||!len||!budget||budget>DK_P40_MAX_BUDGET||(uint64_t)base+len>0x100000000ULL)return 0;
 seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));
 targets=(dk_p42_target*)calloc(DK_P40_MAX_REFERENCES,sizeof(*targets));
 edges=(dk_p42_edge*)calloc(DK_P42_MAX_CALLERS,sizeof(*edges));
 supported=(unsigned char*)calloc(len,1);raw_rts=(size_t*)calloc(len/2+1,sizeof(*raw_rts));
 if(!seeds||!targets||!edges||!supported||!raw_rts)goto done;
 fprintf(o,"DRIVEKIT_PASS42_EVIDENCE_PRIORITIZED_FUNCTION_INDEX\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nGLOBAL_DECODE_BUDGET %lu\n",base,(unsigned long)len,(unsigned long)budget);
 fprintf(tsv,"record_type\tentry_hex\tstatus\tdirect_references\tfirst_caller_hex\tcaller_addresses_hex\treturn_addresses_hex\tinstructions\treturn_count\tfailure_reason\tevidence\n");
 dk_p40_budget_remaining=&remaining;dk_p40_budget_used=&used;
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  for(j=0;j<n;j++)if(!dk_p35_add(seeds,&seed_n,dk_p33_be32(b+i+j*4),2))seed_limited++;
 }
 seed_cut=budget/4;
 for(i=0;i<seed_n&&remaining&&used<seed_cut;i++){
  dk_p35_result r;dk_p37_trace tr;
  if(!dk_p37_check_trace(b,len,base,seeds[i].address,&r,&tr))continue;
  for(j=0;j<DK_P35_WINDOW&&remaining&&used<seed_cut;j++)if(tr.starts[j]){
   size_t off=(size_t)(seeds[i].address-base)+j,n;char op[192];int ht=0,ft=0;uint64_t dest=0;
   if(off>=len||!dk_p40_charge())break;
   n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
   if(!n||n>len-off||!((b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4)))continue;
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   if(!ht||dest<base||dest>=(uint64_t)base+len||(dest&1u))continue;
   for(k=0;k<target_n;k++)if(targets[k].entry==(uint32_t)dest)break;
   if(k==target_n){if(target_n==DK_P40_MAX_REFERENCES){edge_dropped++;continue;}
    targets[k].entry=(uint32_t)dest;targets[k].first_caller=(uint32_t)(base+off);target_n++;}
   targets[k].refs++;
   if(edge_n<DK_P42_MAX_CALLERS){edges[edge_n].target=(uint32_t)dest;edges[edge_n].caller=(uint32_t)(base+off);edge_n++;}else edge_dropped++;
  }
 }
 fprintf(o,"POINTER_SEEDS %lu POINTER_SEEDS_LIMITED %lu\nDIRECT_CALL_REFERENCES %lu\nUNIQUE_CALL_TARGETS %lu\nCALL_EDGE_RECORDS %lu CALL_EDGE_RECORDS_DROPPED %lu\n",(unsigned long)seed_n,(unsigned long)seed_limited,(unsigned long)(edge_n+edge_dropped),(unsigned long)target_n,(unsigned long)edge_n,(unsigned long)edge_dropped);
 for(i=0;i<target_n;i++){
  dk_p35_result r;dk_p37_trace tr;int good;size_t q;
  if(!remaining){targets[i].reason="NOT_EVALUATED_BUDGET";continue;}
  targets[i].attempted=1;good=dk_p37_check_trace(b,len,base,targets[i].entry,&r,&tr);
  targets[i].reason=r.reason;targets[i].bounded=(unsigned)good;targets[i].insns=r.insns;targets[i].returns=r.returns;
  /* Partial traces are not used as independently supported return sites. */
  if(good)for(q=0;q<tr.return_count;q++){
   uint32_t a=tr.returns[q];if(a>=base&&(uint64_t)a<(uint64_t)base+len){supported[a-base]=1;targets[i].rts[targets[i].rts_count++]=a;}
  }
  fprintf(o,"CALL_ENTRY 0x%08X JSR_FROM_FIRST 0x%08X DIRECT_REFERENCES %u STATUS %s INSTRUCTIONS %u RETURNS %u RUNTIME_NOT_PROVEN\n",targets[i].entry,targets[i].first_caller,targets[i].refs,good?"BOUNDED_CFG":r.reason,r.insns,r.returns);
 }
 /* The machine-readable table is one row per unique target, with all observed
    caller sites and all CFG-supported RTS sites (no duplicated target rows). */
 for(i=0;i<target_n;i++){
  dk_p42_target *t=&targets[i];
  fprintf(tsv,"CALL_TARGET\t0x%08X\t%s\t%u\t0x%08X\t",t->entry,t->attempted?(t->bounded?"BOUNDED_CFG":"UNRESOLVED"):"NOT_EVALUATED",t->refs,t->first_caller);
  for(j=0,k=0;j<edge_n;j++)if(edges[j].target==t->entry){fprintf(tsv,"%s0x%08X",k?";":"",edges[j].caller);k++;}
  fprintf(tsv,"\t");for(j=0;j<t->rts_count;j++)fprintf(tsv,"%s0x%08X",j?";":"",t->rts[j]);
  fprintf(tsv,"\t%u\t%u\t%s\tBOUNDED_POINTER_SEED_CFG_DIRECT_CALL;CALL_RETURN_ASSUMED;NO_RUNTIME_PROOF\n",t->insns,t->returns,t->reason?t->reason:"NOT_EVALUATED_BUDGET");
 }
 /* Inventory raw RTS first; do not mistake raw opcode bytes for valid code. */
 for(i=0;i+1<len;i+=2)if(b[i]==0x54&&b[i+1]==0x70){raw_rts[raw_n++]=i;if(supported[i])covered++;}
 /* Phase 1: prioritize RTS sites close to independently referenced call targets.
    Phase 2: remaining raw RTS sites. Both phases use a small, strict orphan
    budget and at most one forward linear suffix check per site. */
 orphan_start=used;orphan_cut=budget/DK_P42_ORPHAN_BUDGET_DIVISOR;
 for(k=0;k<2;k++)for(i=0;i<raw_n;i++){
  size_t at=raw_rts[i],dist=SIZE_MAX,low,scan,insns=0;int near_target=0,hit=0;
  if(supported[at])continue;
  for(j=0;j<target_n;j++){
   size_t off=(size_t)(targets[j].entry-base),d=at>off?at-off:off-at;
   if(d<dist)dist=d;
  }
  near_target=dist<=DK_P42_NEAR_BYTES;
  if((k==0&&!near_target)||(k==1&&near_target))continue;
  if(near_target)near_n++;
  if(orphan_probes>=DK_P42_MAX_ORPHAN_PROBES||!remaining||used-orphan_start>=orphan_cut){unexamined++;continue;}
  /* Check only the closest possible instruction predecessor, not all 64
     arbitrary backward starts. A suffix is explicitly NOT an entry. */
  orphan_probes++;
  if(at>=2){low=at-2;scan=low;hit=dk_p39_forward_to_rts(b,len,base,scan,at,&insns);}
  if(hit){orphan_suffix++;fprintf(o,"RTS_SITE 0x%08X STATUS ORPHAN_SUFFIX_ONLY SUFFIX_START 0x%08X ENTRY_NOT_PROVEN\n",(unsigned)(base+at),(unsigned)(base+at-2));}
  else {orphan_uncertain++;fprintf(o,"RTS_SITE 0x%08X STATUS BOUNDARY_UNCERTAIN ENTRY_NOT_PROVEN\n",(unsigned)(base+at));}
 }
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_CALL_SUPPORTED_RTS %lu\nSUMMARY_ORPHAN_PROBES %lu\nSUMMARY_ORPHAN_SUFFIX_ONLY %lu\nSUMMARY_ORPHAN_UNCERTAIN %lu\nSUMMARY_RTS_NOT_PROBED %lu\nSUMMARY_NEAR_CALL_TARGET_RTS %lu\nSUMMARY_UNIQUE_CALL_TARGETS %lu\nDECODE_BUDGET_USED %lu\nDECODE_BUDGET_REMAINING %lu\nANALYSIS_TRUNCATED %s\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF POINTER_SEEDS_NOT_PROVEN CALL_RETURNS_ASSUMED\n",(unsigned long)raw_n,(unsigned long)covered,(unsigned long)orphan_probes,(unsigned long)orphan_suffix,(unsigned long)orphan_uncertain,(unsigned long)unexamined,(unsigned long)near_n,(unsigned long)target_n,(unsigned long)used,(unsigned long)remaining,(unexamined||edge_dropped)?"YES":"NO");
 ok=!ferror(o)&&!ferror(tsv);
 done:dk_p40_budget_remaining=NULL;dk_p40_budget_used=NULL;
 free(raw_rts);free(supported);free(edges);free(targets);free(seeds);return ok;
}

/* Pass 43: call-first auditable function index and evidence-prioritized orphan probes.
   A call reference requires a bounded pointer-seeded CFG. Entries and orphan
   suffixes are candidates only; no runtime or globally closed boundary proof. */
#define DK_P43_MAX_ORPHAN_PROBES 512u
#define DK_P42_NEAR_BYTES 2048u
#define DK_P42_ORPHAN_BUDGET_DIVISOR 8u
#define DK_P42_MAX_CALLERS 4096u
typedef struct {uint32_t entry,first_caller;unsigned refs,insns,returns,attempted,bounded;const char *reason;uint32_t rts[DK_P35_MAX_INSNS];unsigned rts_count;} dk_p43_target;
typedef struct {uint32_t target,caller;} dk_p43_edge;
static int dk_p43_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,FILE *tsv,size_t budget){
 dk_p35_seed *seeds=NULL;dk_p43_target *targets=NULL;dk_p43_edge *edges=NULL;
 unsigned char *supported=NULL;size_t *raw_rts=NULL;
 size_t remaining=budget,used=0,seed_n=0,seed_limited=0,target_n=0,edge_n=0,edge_dropped=0;
 size_t raw_n=0,covered=0,near_n=0,orphan_probes=0,orphan_suffix=0,orphan_uncertain=0,unexamined=0,duplicate_edges=0,unique_edges=0,queue_candidates=0,queue_cap=0,queue_budget=0;
 size_t i,j,k,seed_cut,orphan_cut,orphan_start,pass;int ok=0;
 if(!b||!o||!tsv||!len||!budget||budget>DK_P40_MAX_BUDGET||(uint64_t)base+len>0x100000000ULL)return 0;
 seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));
 targets=(dk_p43_target*)calloc(DK_P40_MAX_REFERENCES,sizeof(*targets));
 edges=(dk_p43_edge*)calloc(DK_P42_MAX_CALLERS,sizeof(*edges));
 supported=(unsigned char*)calloc(len,1);raw_rts=(size_t*)calloc(len/2+1,sizeof(*raw_rts));
 if(!seeds||!targets||!edges||!supported||!raw_rts)goto done;
 fprintf(o,"DRIVEKIT_PASS43_UNIQUE_EDGE_EVIDENCE_QUEUE\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nGLOBAL_DECODE_BUDGET %lu\n",base,(unsigned long)len,(unsigned long)budget);
 fprintf(tsv,"record_type\tentry_hex\tstatus\tunique_call_sites\tfirst_caller_hex\tcaller_addresses_hex\treturn_addresses_hex\tinstructions\treturn_count\tfailure_reason\tevidence\tdiscovery_occurrences\n");
 dk_p40_budget_remaining=&remaining;dk_p40_budget_used=&used;
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  for(j=0;j<n;j++)if(!dk_p35_add(seeds,&seed_n,dk_p33_be32(b+i+j*4),2))seed_limited++;
 }
 seed_cut=budget/4;
 for(i=0;i<seed_n&&remaining&&used<seed_cut;i++){
  dk_p35_result r;dk_p37_trace tr;
  if(!dk_p37_check_trace(b,len,base,seeds[i].address,&r,&tr))continue;
  for(j=0;j<DK_P35_WINDOW&&remaining&&used<seed_cut;j++)if(tr.starts[j]){
   size_t off=(size_t)(seeds[i].address-base)+j,n;char op[192];int ht=0,ft=0;uint64_t dest=0;
   if(off>=len||!dk_p40_charge())break;
   n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
   if(!n||n>len-off||!((b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4)))continue;
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   if(!ht||dest<base||dest>=(uint64_t)base+len||(dest&1u))continue;
   for(k=0;k<target_n;k++)if(targets[k].entry==(uint32_t)dest)break;
   if(k==target_n){if(target_n==DK_P40_MAX_REFERENCES){edge_dropped++;continue;}
    targets[k].entry=(uint32_t)dest;targets[k].first_caller=(uint32_t)(base+off);target_n++;}
   /* Preserve discovery occurrences, but index each (caller,target) only once. */
   targets[k].refs++;
   {size_t e;for(e=0;e<edge_n;e++)if(edges[e].target==(uint32_t)dest&&edges[e].caller==(uint32_t)(base+off))break;
    if(e<edge_n)duplicate_edges++;
    else if(edge_n<DK_P42_MAX_CALLERS){edges[edge_n].target=(uint32_t)dest;edges[edge_n].caller=(uint32_t)(base+off);edge_n++;unique_edges++;}
    else edge_dropped++;
   }
  }
 }
 fprintf(o,"POINTER_SEEDS %lu POINTER_SEEDS_LIMITED %lu\nDIRECT_CALL_REFERENCES %lu\nUNIQUE_CALL_TARGETS %lu\nCALL_EDGE_RECORDS %lu CALL_EDGE_RECORDS_DROPPED %lu\nUNIQUE_CALL_EDGES %lu\nDUPLICATE_EDGE_DISCOVERIES %lu\n",(unsigned long)seed_n,(unsigned long)seed_limited,(unsigned long)(edge_n+duplicate_edges+edge_dropped),(unsigned long)target_n,(unsigned long)edge_n,(unsigned long)edge_dropped,(unsigned long)unique_edges,(unsigned long)duplicate_edges);
 for(i=0;i<target_n;i++){
  dk_p35_result r;dk_p37_trace tr;int good;size_t q;
  if(!remaining){targets[i].reason="NOT_EVALUATED_BUDGET";continue;}
  targets[i].attempted=1;good=dk_p37_check_trace(b,len,base,targets[i].entry,&r,&tr);
  targets[i].reason=r.reason;targets[i].bounded=(unsigned)good;targets[i].insns=r.insns;targets[i].returns=r.returns;
  /* Partial traces are not used as independently supported return sites. */
  if(good)for(q=0;q<tr.return_count;q++){
   uint32_t a=tr.returns[q];if(a>=base&&(uint64_t)a<(uint64_t)base+len){supported[a-base]=1;targets[i].rts[targets[i].rts_count++]=a;}
  }
  fprintf(o,"CALL_ENTRY 0x%08X JSR_FROM_FIRST 0x%08X DIRECT_REFERENCES %u STATUS %s INSTRUCTIONS %u RETURNS %u RUNTIME_NOT_PROVEN\n",targets[i].entry,targets[i].first_caller,targets[i].refs,good?"BOUNDED_CFG":r.reason,r.insns,r.returns);
 }
 /* The machine-readable table is one row per unique target, with all observed
    caller sites and all CFG-supported RTS sites (no duplicated target rows). */
 for(i=0;i<target_n;i++){
  dk_p43_target *t=&targets[i];
  {unsigned unique_for_target=0;for(j=0;j<edge_n;j++)if(edges[j].target==t->entry)unique_for_target++;
  fprintf(tsv,"CALL_TARGET\t0x%08X\t%s\t%u\t0x%08X\t",t->entry,t->attempted?(t->bounded?"BOUNDED_CFG":"UNRESOLVED"):"NOT_EVALUATED",unique_for_target,t->first_caller);}
  for(j=0,k=0;j<edge_n;j++)if(edges[j].target==t->entry){fprintf(tsv,"%s0x%08X",k?";":"",edges[j].caller);k++;}
  fprintf(tsv,"\t");for(j=0;j<t->rts_count;j++)fprintf(tsv,"%s0x%08X",j?";":"",t->rts[j]);
  fprintf(tsv,"\t%u\t%u\t%s\tBOUNDED_POINTER_SEED_CFG_DIRECT_CALL;CALL_RETURN_ASSUMED;NO_RUNTIME_PROOF\t%u\n",t->insns,t->returns,t->reason?t->reason:"NOT_EVALUATED_BUDGET",t->refs);
 }
 /* Inventory raw RTS first; do not mistake raw opcode bytes for valid code. */
 for(i=0;i+1<len;i+=2)if(b[i]==0x54&&b[i+1]==0x70){raw_rts[raw_n++]=i;if(supported[i])covered++;}
 /* Pass 43: evidence-only second-stage queue. Four distance bands, closest
    first, with no arbitrary raw-RTS fallback. An RTS suffix remains weak evidence. */
 orphan_start=used;orphan_cut=budget/DK_P42_ORPHAN_BUDGET_DIVISOR;
 for(i=0;i<raw_n;i++)if(!supported[raw_rts[i]]){
  size_t at=raw_rts[i],dist=SIZE_MAX;
  for(j=0;j<target_n;j++){size_t off=(size_t)(targets[j].entry-base),d=at>off?at-off:off-at;if(d<dist)dist=d;}
  if(dist<=DK_P42_NEAR_BYTES)queue_candidates++;
 }
 near_n=queue_candidates;
 for(pass=0;pass<4;pass++)for(i=0;i<raw_n;i++){
  size_t at=raw_rts[i],dist=SIZE_MAX,insns=0;int hit=0;
  if(supported[at])continue;
  for(j=0;j<target_n;j++){size_t off=(size_t)(targets[j].entry-base),d=at>off?at-off:off-at;if(d<dist)dist=d;}
  if(dist>DK_P42_NEAR_BYTES||(dist==DK_P42_NEAR_BYTES?3u:dist/512u)!=pass)continue;
  if(orphan_probes>=DK_P43_MAX_ORPHAN_PROBES){queue_cap++;continue;}
  if(!remaining||used-orphan_start>=orphan_cut){queue_budget++;continue;}
  orphan_probes++;
  if(at>=2)hit=dk_p39_forward_to_rts(b,len,base,at-2,at,&insns);
  if(hit){orphan_suffix++;fprintf(o,"RTS_SITE 0x%08X STATUS ORPHAN_SUFFIX_ONLY SUFFIX_START 0x%08X ENTRY_NOT_PROVEN\n",(unsigned)(base+at),(unsigned)(base+at-2));}
  else {orphan_uncertain++;fprintf(o,"RTS_SITE 0x%08X STATUS BOUNDARY_UNCERTAIN ENTRY_NOT_PROVEN\n",(unsigned)(base+at));}
 }
 unexamined=raw_n-covered-orphan_probes;
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_CALL_SUPPORTED_RTS %lu\nSUMMARY_ORPHAN_PROBES %lu\nSUMMARY_ORPHAN_SUFFIX_ONLY %lu\nSUMMARY_ORPHAN_UNCERTAIN %lu\nSUMMARY_RTS_NOT_PROBED %lu\nSUMMARY_NEAR_CALL_TARGET_RTS %lu\nSUMMARY_UNIQUE_CALL_TARGETS %lu\nSUMMARY_UNIQUE_CALL_EDGES %lu\nSUMMARY_DUPLICATE_EDGE_DISCOVERIES %lu\nQUEUE_CANDIDATES %lu\nQUEUE_PROCESSED %lu\nQUEUE_DEFERRED_CAP %lu\nQUEUE_DEFERRED_BUDGET %lu\nQUEUE_OUTSIDE_EVIDENCE %lu\nDECODE_BUDGET_USED %lu\nDECODE_BUDGET_REMAINING %lu\nANALYSIS_TRUNCATED %s\nTRUNCATION_REASON %s\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF POINTER_SEEDS_NOT_PROVEN CALL_RETURNS_ASSUMED\n",(unsigned long)raw_n,(unsigned long)covered,(unsigned long)orphan_probes,(unsigned long)orphan_suffix,(unsigned long)orphan_uncertain,(unsigned long)unexamined,(unsigned long)near_n,(unsigned long)target_n,(unsigned long)unique_edges,(unsigned long)duplicate_edges,(unsigned long)queue_candidates,(unsigned long)orphan_probes,(unsigned long)queue_cap,(unsigned long)queue_budget,(unsigned long)(unexamined-queue_cap-queue_budget),(unsigned long)used,(unsigned long)remaining,(queue_cap||queue_budget||edge_dropped||seed_limited)?"YES":"NO",edge_dropped?"EDGE_CAP":seed_limited?"SEED_CAP":queue_budget?"QUEUE_BUDGET":queue_cap?"QUEUE_CAP":"NONE");
 ok=!ferror(o)&&!ferror(tsv);
 done:dk_p40_budget_remaining=NULL;dk_p40_budget_used=NULL;
 free(raw_rts);free(supported);free(edges);free(targets);free(seeds);return ok;
}

/* Pass 44: call-first auditable function index and evidence-prioritized orphan probes.
   A call reference requires a bounded pointer-seeded CFG. Entries and orphan
   suffixes are candidates only; no runtime or globally closed boundary proof. */
#define DK_P44_MAX_ORPHAN_PROBES 2048u
#define DK_P42_NEAR_BYTES 2048u
#define DK_P42_ORPHAN_BUDGET_DIVISOR 8u
#define DK_P42_MAX_CALLERS 4096u
typedef struct {uint32_t entry,first_caller;unsigned refs,insns,returns,attempted,bounded;const char *reason;uint32_t rts[DK_P35_MAX_INSNS];unsigned rts_count;uint32_t stop_address;unsigned char stop_bytes[8];unsigned stop_count;} dk_p44_target;
typedef struct {uint32_t target,caller;} dk_p44_edge;
static int dk_p44_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,FILE *tsv,size_t budget){
 dk_p35_seed *seeds=NULL;dk_p44_target *targets=NULL;dk_p44_edge *edges=NULL;
 unsigned char *supported=NULL;size_t *raw_rts=NULL;
 size_t remaining=budget,used=0,seed_n=0,seed_limited=0,target_n=0,edge_n=0,edge_dropped=0;
 size_t raw_n=0,covered=0,near_n=0,orphan_probes=0,orphan_suffix=0,orphan_uncertain=0,unexamined=0,duplicate_edges=0,unique_edges=0,queue_candidates=0,queue_cap=0,queue_budget=0;
 size_t i,j,k,seed_cut,orphan_cut,orphan_start,pass;size_t p64_seed_attempted=0,p64_seed_bounded=0,p64_seed_failed=0;int ok=0;
 if(!b||!o||!tsv||!len||!budget||budget>DK_P40_MAX_BUDGET||(uint64_t)base+len>0x100000000ULL)return 0;
 seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));
 targets=(dk_p44_target*)calloc(DK_P40_MAX_REFERENCES,sizeof(*targets));
 edges=(dk_p44_edge*)calloc(DK_P42_MAX_CALLERS,sizeof(*edges));
 supported=(unsigned char*)calloc(len,1);raw_rts=(size_t*)calloc(len/2+1,sizeof(*raw_rts));
 if(!seeds||!targets||!edges||!supported||!raw_rts)goto done;
 fprintf(o,"DRIVEKIT_PASS44_TARGET_FAILURE_DIAGNOSTICS\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nGLOBAL_DECODE_BUDGET %lu\n",base,(unsigned long)len,(unsigned long)budget);
 fprintf(tsv,"record_type\tentry_hex\tstatus\tunique_call_sites\tfirst_caller_hex\tcaller_addresses_hex\treturn_addresses_hex\tinstructions\treturn_count\tfailure_reason\tevidence\tdiscovery_occurrences\tstop_address_hex\tstop_bytes_hex\tfailure_category\n");
 dk_p40_budget_remaining=&remaining;dk_p40_budget_used=&used;
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  for(j=0;j<n;j++)if(!dk_p35_add(seeds,&seed_n,dk_p33_be32(b+i+j*4),2))seed_limited++;
 }
 seed_cut=budget/4;
 for(i=0;i<seed_n&&remaining&&used<seed_cut;i++){
  dk_p35_result r;dk_p37_trace tr;
  p64_seed_attempted++;
  if(!dk_p37_check_trace(b,len,base,seeds[i].address,&r,&tr)){p64_seed_failed++;continue;}
  p64_seed_bounded++;
  for(j=0;j<DK_P35_WINDOW&&remaining&&used<seed_cut;j++)if(tr.starts[j]){
   size_t off=(size_t)(seeds[i].address-base)+j,n;char op[192];int ht=0,ft=0;uint64_t dest=0;
   if(off>=len||!dk_p40_charge())break;
   n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
   if(!n||n>len-off||!((b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4)))continue;
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   if(!ht||dest<base||dest>=(uint64_t)base+len||(dest&1u))continue;
   for(k=0;k<target_n;k++)if(targets[k].entry==(uint32_t)dest)break;
   if(k==target_n){if(target_n==DK_P40_MAX_REFERENCES){edge_dropped++;continue;}
    targets[k].entry=(uint32_t)dest;targets[k].first_caller=(uint32_t)(base+off);target_n++;}
   /* Preserve discovery occurrences, but index each (caller,target) only once. */
   targets[k].refs++;
   {size_t e;for(e=0;e<edge_n;e++)if(edges[e].target==(uint32_t)dest&&edges[e].caller==(uint32_t)(base+off))break;
    if(e<edge_n)duplicate_edges++;
    else if(edge_n<DK_P42_MAX_CALLERS){edges[edge_n].target=(uint32_t)dest;edges[edge_n].caller=(uint32_t)(base+off);edge_n++;unique_edges++;}
    else edge_dropped++;
   }
  }
 }
 fprintf(o,"PASS64_SEED_CAP %u\nPASS64_SEED_DISCOVERED %lu\nPASS64_SEED_EVALUATED %lu\nPASS64_SEED_BOUNDED %lu\nPASS64_SEED_FAILED %lu\nPASS64_SEED_NOT_EVALUATED %lu\nPASS64_SEED_BUDGET_CUTOFF %lu\n",DK_P35_MAX_SEEDS,(unsigned long)seed_n,(unsigned long)p64_seed_attempted,(unsigned long)p64_seed_bounded,(unsigned long)p64_seed_failed,(unsigned long)(seed_n-p64_seed_attempted),(unsigned long)seed_cut);
 fprintf(o,"POINTER_SEEDS %lu POINTER_SEEDS_LIMITED %lu\nDIRECT_CALL_REFERENCES %lu\nUNIQUE_CALL_TARGETS %lu\nCALL_EDGE_RECORDS %lu CALL_EDGE_RECORDS_DROPPED %lu\nUNIQUE_CALL_EDGES %lu\nDUPLICATE_EDGE_DISCOVERIES %lu\n",(unsigned long)seed_n,(unsigned long)seed_limited,(unsigned long)(edge_n+duplicate_edges+edge_dropped),(unsigned long)target_n,(unsigned long)edge_n,(unsigned long)edge_dropped,(unsigned long)unique_edges,(unsigned long)duplicate_edges);
 for(i=0;i<target_n;i++){
  dk_p35_result r;dk_p37_trace tr;int good;size_t q;
  if(!remaining){targets[i].reason="NOT_EVALUATED_BUDGET";continue;}
  targets[i].attempted=1;good=dk_p37_check_trace(b,len,base,targets[i].entry,&r,&tr);
  targets[i].reason=r.reason;targets[i].bounded=(unsigned)good;targets[i].insns=r.insns;targets[i].returns=r.returns;targets[i].stop_address=r.stop_address;targets[i].stop_count=r.stop_count;memcpy(targets[i].stop_bytes,r.stop_bytes,sizeof(r.stop_bytes));
  /* Partial traces are not used as independently supported return sites. */
  if(good)for(q=0;q<tr.return_count;q++){
   uint32_t a=tr.returns[q];if(a>=base&&(uint64_t)a<(uint64_t)base+len){supported[a-base]=1;targets[i].rts[targets[i].rts_count++]=a;}
  }
  if(!good){
   const char *category="OTHER_UNRESOLVED";size_t bi;
   if(!strcmp(r.reason,"UNSUPPORTED_DECODE"))category="DECODER_GAP";
   else if(!strcmp(r.reason,"INDIRECT_OR_SPECIAL_FLOW")||!strcmp(r.reason,"UNRESOLVED_CALL")||!strcmp(r.reason,"EXCEPTION_RETURN"))category="CONTROL_FLOW_UNRESOLVED";
   else if(!strcmp(r.reason,"BRANCH_OUTSIDE_WINDOW")||!strcmp(r.reason,"FALLTHROUGH_OUTSIDE_WINDOW")||!strcmp(r.reason,"WINDOW_LIMIT")||!strcmp(r.reason,"INSTRUCTION_LIMIT")||!strcmp(r.reason,"QUEUE_LIMIT"))category="ANALYSIS_LIMIT";
   else if(!strcmp(r.reason,"GLOBAL_DECODE_BUDGET"))category="BUDGET_LIMIT";
   fprintf(o,"TARGET_FAILURE 0x%08X CATEGORY %s REASON %s STOP_AT 0x%08X STOP_BYTES",targets[i].entry,category,r.reason?r.reason:"UNKNOWN",r.stop_address);
   for(bi=0;bi<r.stop_count;bi++)fprintf(o," %02X",r.stop_bytes[bi]);
   fprintf(o," PARTIAL_INSTRUCTIONS %u PARTIAL_RETURNS %u NOT_A_PROVEN_BOUNDARY\n",r.insns,r.returns);
  }
  fprintf(o,"CALL_ENTRY 0x%08X JSR_FROM_FIRST 0x%08X DIRECT_REFERENCES %u STATUS %s INSTRUCTIONS %u RETURNS %u RUNTIME_NOT_PROVEN\n",targets[i].entry,targets[i].first_caller,targets[i].refs,good?"BOUNDED_CFG":r.reason,r.insns,r.returns);
 }
 /* The machine-readable table is one row per unique target, with all observed
    caller sites and all CFG-supported RTS sites (no duplicated target rows). */
 for(i=0;i<target_n;i++){
  dk_p44_target *t=&targets[i];
  {unsigned unique_for_target=0;for(j=0;j<edge_n;j++)if(edges[j].target==t->entry)unique_for_target++;
  fprintf(tsv,"CALL_TARGET\t0x%08X\t%s\t%u\t0x%08X\t",t->entry,t->attempted?(t->bounded?"BOUNDED_CFG":"UNRESOLVED"):"NOT_EVALUATED",unique_for_target,t->first_caller);}
  for(j=0,k=0;j<edge_n;j++)if(edges[j].target==t->entry){fprintf(tsv,"%s0x%08X",k?";":"",edges[j].caller);k++;}
  fprintf(tsv,"\t");for(j=0;j<t->rts_count;j++)fprintf(tsv,"%s0x%08X",j?";":"",t->rts[j]);
  {const char *cat="NONE";unsigned bi;
   if(!t->bounded){cat="OTHER_UNRESOLVED";
    if(t->reason&&!strcmp(t->reason,"UNSUPPORTED_DECODE"))cat="DECODER_GAP";
    else if(t->reason&&(!strcmp(t->reason,"INDIRECT_OR_SPECIAL_FLOW")||!strcmp(t->reason,"UNRESOLVED_CALL")||!strcmp(t->reason,"EXCEPTION_RETURN")))cat="CONTROL_FLOW_UNRESOLVED";
    else if(t->reason&&(!strcmp(t->reason,"BRANCH_OUTSIDE_WINDOW")||!strcmp(t->reason,"FALLTHROUGH_OUTSIDE_WINDOW")||!strcmp(t->reason,"WINDOW_LIMIT")||!strcmp(t->reason,"INSTRUCTION_LIMIT")||!strcmp(t->reason,"QUEUE_LIMIT")))cat="ANALYSIS_LIMIT";
    else if(t->reason&&(!strcmp(t->reason,"GLOBAL_DECODE_BUDGET")||!strcmp(t->reason,"NOT_EVALUATED_BUDGET")))cat="BUDGET_LIMIT";
   }
   fprintf(tsv,"\t%u\t%u\t%s\tBOUNDED_POINTER_SEED_CFG_DIRECT_CALL;CALL_RETURN_ASSUMED;NO_RUNTIME_PROOF\t%u\t0x%08X\t",t->insns,t->returns,t->reason?t->reason:"NOT_EVALUATED_BUDGET",t->refs,t->stop_address);
   for(bi=0;bi<t->stop_count;bi++)fprintf(tsv,"%s%02X",bi?" ":"",t->stop_bytes[bi]);
   fprintf(tsv,"\t%s\n",cat);
  }
 }
 /* Inventory raw RTS first; do not mistake raw opcode bytes for valid code. */
 for(i=0;i+1<len;i+=2)if(b[i]==0x54&&b[i+1]==0x70){raw_rts[raw_n++]=i;if(supported[i])covered++;}
 /* Pass 44: evidence-only second-stage queue. Four distance bands, closest
    first, with no arbitrary raw-RTS fallback. An RTS suffix remains weak evidence. */
 orphan_start=used;orphan_cut=budget/DK_P42_ORPHAN_BUDGET_DIVISOR;
 for(i=0;i<raw_n;i++)if(!supported[raw_rts[i]]){
  size_t at=raw_rts[i],dist=SIZE_MAX;
  for(j=0;j<target_n;j++){size_t off=(size_t)(targets[j].entry-base),d=at>off?at-off:off-at;if(d<dist)dist=d;}
  if(dist<=DK_P42_NEAR_BYTES)queue_candidates++;
 }
 near_n=queue_candidates;
 for(pass=0;pass<4;pass++)for(i=0;i<raw_n;i++){
  size_t at=raw_rts[i],dist=SIZE_MAX,insns=0;int hit=0;
  if(supported[at])continue;
  for(j=0;j<target_n;j++){size_t off=(size_t)(targets[j].entry-base),d=at>off?at-off:off-at;if(d<dist)dist=d;}
  if(dist>DK_P42_NEAR_BYTES||(dist==DK_P42_NEAR_BYTES?3u:dist/512u)!=pass)continue;
  if(orphan_probes>=DK_P44_MAX_ORPHAN_PROBES){queue_cap++;continue;}
  if(!remaining||used-orphan_start>=orphan_cut){queue_budget++;continue;}
  orphan_probes++;
  if(at>=2)hit=dk_p39_forward_to_rts(b,len,base,at-2,at,&insns);
  if(hit){orphan_suffix++;fprintf(o,"RTS_SITE 0x%08X STATUS ORPHAN_SUFFIX_ONLY SUFFIX_START 0x%08X ENTRY_NOT_PROVEN\n",(unsigned)(base+at),(unsigned)(base+at-2));}
  else {orphan_uncertain++;fprintf(o,"RTS_SITE 0x%08X STATUS BOUNDARY_UNCERTAIN ENTRY_NOT_PROVEN\n",(unsigned)(base+at));}
 }
 unexamined=raw_n-covered-orphan_probes;
 {size_t bounded_n=0,unresolved_n=0;for(i=0;i<target_n;i++){if(targets[i].bounded)bounded_n++;else unresolved_n++;}fprintf(o,"SUMMARY_CALL_TARGETS_BOUNDED %lu\nSUMMARY_CALL_TARGETS_UNRESOLVED %lu\n",(unsigned long)bounded_n,(unsigned long)unresolved_n);}
 fprintf(o,"SUMMARY_RAW_RTS %lu\nSUMMARY_CALL_SUPPORTED_RTS %lu\nSUMMARY_ORPHAN_PROBES %lu\nSUMMARY_ORPHAN_SUFFIX_ONLY %lu\nSUMMARY_ORPHAN_UNCERTAIN %lu\nSUMMARY_RTS_NOT_PROBED %lu\nSUMMARY_NEAR_CALL_TARGET_RTS %lu\nSUMMARY_UNIQUE_CALL_TARGETS %lu\nSUMMARY_UNIQUE_CALL_EDGES %lu\nSUMMARY_DUPLICATE_EDGE_DISCOVERIES %lu\nQUEUE_CANDIDATES %lu\nQUEUE_PROCESSED %lu\nQUEUE_DEFERRED_CAP %lu\nQUEUE_DEFERRED_BUDGET %lu\nQUEUE_OUTSIDE_EVIDENCE %lu\nDECODE_BUDGET_USED %lu\nDECODE_BUDGET_REMAINING %lu\nANALYSIS_TRUNCATED %s\nTRUNCATION_REASON %s\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF POINTER_SEEDS_NOT_PROVEN CALL_RETURNS_ASSUMED\n",(unsigned long)raw_n,(unsigned long)covered,(unsigned long)orphan_probes,(unsigned long)orphan_suffix,(unsigned long)orphan_uncertain,(unsigned long)unexamined,(unsigned long)near_n,(unsigned long)target_n,(unsigned long)unique_edges,(unsigned long)duplicate_edges,(unsigned long)queue_candidates,(unsigned long)orphan_probes,(unsigned long)queue_cap,(unsigned long)queue_budget,(unsigned long)(unexamined-queue_cap-queue_budget),(unsigned long)used,(unsigned long)remaining,(queue_cap||queue_budget||edge_dropped||seed_limited)?"YES":"NO",edge_dropped?"EDGE_CAP":seed_limited?"SEED_CAP":queue_budget?"QUEUE_BUDGET":queue_cap?"QUEUE_CAP":"NONE");
 ok=!ferror(o)&&!ferror(tsv);
 done:dk_p40_budget_remaining=NULL;dk_p40_budget_used=NULL;
 free(raw_rts);free(supported);free(edges);free(targets);free(seeds);return ok;
}


/* Pass 45: second-stage diagnostic only. A larger bounded window is applied
 * exclusively to Pass 44 unresolved, direct-call-supported targets. Indirect
 * calls may be assumed to return but never resolve their destinations. */
#define DK_P45_WINDOW 4096u
#define DK_P45_MAX_INSNS 1024u
#define DK_P45_AUDIT_BUDGET 10000u
typedef struct {const char *reason;uint32_t stop;unsigned insns,returns,indirect_calls;size_t charged;} dk_p45_result;
static int dk_p45_check(const unsigned char *b,size_t len,uint32_t base,uint32_t entry,size_t *remaining,dk_p45_result *r){
 unsigned char *mark=NULL,*queued=NULL;unsigned short *queue=NULL;size_t head=0,tail=0,start,span;int ok=0;
 memset(r,0,sizeof(*r));r->reason="UNRESOLVED";r->stop=entry;
 if(entry<base||(uint64_t)entry>=(uint64_t)base+len||(entry&1u)){r->reason="ENTRY_OUT_OF_IMAGE";return 0;}
 start=(size_t)(entry-base);span=len-start;if(span>DK_P45_WINDOW)span=DK_P45_WINDOW;
 mark=(unsigned char*)calloc(span,1);queued=(unsigned char*)calloc(span,1);queue=(unsigned short*)malloc(span*sizeof(*queue));
 if(!mark||!queued||!queue){r->reason="ALLOCATION_FAILURE";goto done;}
 queue[tail++]=0;queued[0]=1;
 while(head<tail){size_t at=queue[head++],off=start+at,n,j;char op[192];int ht=0,ft=0,is_call;uint64_t dest=0;
  r->stop=(uint32_t)((uint64_t)base+off);
  if(at>=span){r->reason="WINDOW_LIMIT";goto done;}
  if(mark[at]==1)continue;
  if(mark[at]==2){r->reason="INSTRUCTION_OVERLAP";goto done;}
  if(r->insns>=DK_P45_MAX_INSNS){r->reason="INSTRUCTION_LIMIT";goto done;}
  if(!*remaining){r->reason="AUDIT_BUDGET_LIMIT";goto done;}
  --*remaining;r->charged++;
  n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>span-at||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED")){r->reason="DECODER_GAP";goto done;}
  for(j=0;j<n;j++)if(mark[at+j]){r->reason="INSTRUCTION_OVERLAP";goto done;}
  mark[at]=1;for(j=1;j<n;j++)mark[at+j]=2;r->insns++;
  if(n==2&&b[off]==0x54&&b[off+1]==0x70){r->returns++;continue;}
  if(n==2&&b[off]==0x56&&b[off+1]==0x70){r->reason="EXCEPTION_RETURN";goto done;}
  /* 0x5D is an indirect JSR: record unresolved callee and assume return.
   * 0x59 is indirect JMP: no successor can be proven. */
  if(b[off]==0x5d){r->indirect_calls++;ft=1;ht=0;}
  else if(b[off]==0x59||b[off]==0x5f||b[off]==0x57||(b[off]==0x01&&n>=2&&b[off+1]==0x80)){
   r->reason="INDIRECT_JUMP_OR_SPECIAL_FLOW";goto done;
  }else{
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   is_call=(b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4);
   if(is_call){if(!ht||dest>UINT32_MAX||(dest&1u)){r->reason="UNRESOLVED_DIRECT_CALL";goto done;}ht=0;ft=1;}
   else if(ht){size_t d;
    if(dest<base||(uint64_t)dest>=(uint64_t)base+len||(dest&1u)){r->reason="BRANCH_OUTSIDE_IMAGE";goto done;}
    if(dest<entry||(uint64_t)dest>=(uint64_t)entry+span){r->reason="BRANCH_OUTSIDE_AUDIT_WINDOW";goto done;}
    d=(size_t)(dest-entry);
    if(mark[d]==2){r->reason="BRANCH_INSTRUCTION_INTERIOR";goto done;}
    if(!queued[d]){queued[d]=1;queue[tail++]=(unsigned short)d;}
   }
  }
  if(ft){size_t d=at+n;
   if(d>=span){r->reason="FALLTHROUGH_OUTSIDE_AUDIT_WINDOW";goto done;}
   if(mark[d]==2){r->reason="FALLTHROUGH_INSTRUCTION_INTERIOR";goto done;}
   if(!queued[d]){queued[d]=1;queue[tail++]=(unsigned short)d;}
  }else if(!ht){r->reason="UNKNOWN_TERMINAL";goto done;}
 }
 if(!r->returns){r->reason="NO_RETURN";goto done;}
 r->reason=r->indirect_calls?"BOUNDED_WITH_UNRESOLVED_INDIRECT_CALLS":"BOUNDED_CFG";ok=1;
 done:free(mark);free(queued);free(queue);return ok;
}
static int dk_p45_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,FILE *tsv,size_t budget){
 FILE *tmp=tmpfile();char line[2048];uint32_t entries[DK_P40_MAX_REFERENCES];size_t n=0,i,remaining=DK_P45_AUDIT_BUDGET,spent=0;unsigned bounded=0,conditional=0,unresolved=0;int base_ok=0;
 if(!tmp)return 0;
 base_ok=dk_p44_report(b,len,base,tmp,tsv,budget);
 if(!base_ok){fclose(tmp);return 0;}
 rewind(tmp);
 while(fgets(line,sizeof(line),tmp)){
  unsigned address;
  if(fputs(line,o)==EOF){fclose(tmp);return 0;}
  if(sscanf(line,"TARGET_FAILURE 0x%X",&address)==1&&n<DK_P40_MAX_REFERENCES)entries[n++]=(uint32_t)address;
 }
 fclose(tmp);
 if(remaining>budget)remaining=budget;
 fprintf(o,"PASS45_TARGETED_AUDIT_BEGIN\nAUDIT_WINDOW_BYTES %u\nAUDIT_INSTRUCTION_CAP %u\nAUDIT_DECODE_BUDGET %lu\nPREVIOUSLY_UNRESOLVED_TARGETS %lu\n",DK_P45_WINDOW,DK_P45_MAX_INSNS,(unsigned long)remaining,(unsigned long)n);
 fprintf(tsv,"PASS45_AUDIT\tentry_hex\tstatus\tstop_address_hex\tinstructions\treturns\tindirect_calls\tdecode_charges\tlimitations\n");
 for(i=0;i<n;i++){
  dk_p45_result r;int good=dk_p45_check(b,len,base,entries[i],&remaining,&r);
  spent+=r.charged;
  if(good){if(r.indirect_calls)conditional++;else bounded++;}else unresolved++;
  fprintf(o,"PASS45_TARGET 0x%08X STATUS %s STOP_AT 0x%08X INSTRUCTIONS %u RETURNS %u INDIRECT_CALLS %u DECODE_CHARGES %lu %s\n",entries[i],r.reason,r.stop,r.insns,r.returns,r.indirect_calls,(unsigned long)r.charged,good?"ENTRY_AND_RUNTIME_NOT_PROVEN":"PARTIAL_CFG_ONLY");
  fprintf(tsv,"PASS45_AUDIT\t0x%08X\t%s\t0x%08X\t%u\t%u\t%u\t%lu\t%s\n",entries[i],r.reason,r.stop,r.insns,r.returns,r.indirect_calls,(unsigned long)r.charged,good?"CALL_RETURNS_ASSUMED;NO_RUNTIME_PROOF":"PARTIAL_CFG_ONLY");
 }
 fprintf(o,"PASS45_SUMMARY_STRICT_BOUNDED %u\nPASS45_SUMMARY_CONDITIONAL_INDIRECT_CALL_BOUNDED %u\nPASS45_SUMMARY_STILL_UNRESOLVED %u\nPASS45_AUDIT_BUDGET_USED %lu\nPASS45_AUDIT_BUDGET_REMAINING %lu\nPASS45_TARGETED_AUDIT_END\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF INDIRECT_CALL_TARGETS_UNRESOLVED\n",bounded,conditional,unresolved,(unsigned long)spent,(unsigned long)remaining);
 return !ferror(o)&&!ferror(tsv);
}


/* Pass 46: readable assembly from independently supported candidate entries.
 * Listing is CFG-reachable instructions only; never a contiguous byte sweep. */
#define DK_P46_MAX_TARGETS 256u
/* Optional scoped address labels. Never used to alter decoding or CFG. */
static const char *(*dk_p46_symbol_resolve)(uint32_t)=NULL;
static const char *dk_p46_operand_symbol(const char *op){
 const char *p=op;char *end;unsigned long value;
 if(!dk_p46_symbol_resolve)return NULL;
 while((p=strstr(p,"@H'"))!=NULL){
  p+=3;value=strtoul(p,&end,16);
  if(end!=p&&*end==':'&&value<=UINT32_MAX){
   const char *name=dk_p46_symbol_resolve((uint32_t)value);
   if(name)return name;
  }
  if(!*p)break;
 }
 return NULL;
}
#define DK_P46_SPAN 4096u
#define DK_P46_MAX_INSNS 1024u
typedef struct {uint32_t address;int from_audit;} dk_p46_target;
static int dk_p46_export_one(const unsigned char *b,size_t len,uint32_t base,FILE *o,uint32_t entry,int from_audit,unsigned *total_insns){
 unsigned char *mark=NULL,*queued=NULL,*labels=NULL;unsigned short *queue=NULL;size_t head=0,tail=0,start,span,at;unsigned insns=0,returns=0,indirect=0;const char *status="COMPLETE";uint32_t stop=entry;int complete=0;
 if(entry<base||(uint64_t)entry>=(uint64_t)base+len||(entry&1u))return 0;
 start=(size_t)(entry-base);span=len-start;if(span>DK_P46_SPAN)span=DK_P46_SPAN;
 mark=(unsigned char*)calloc(span,1);queued=(unsigned char*)calloc(span,1);labels=(unsigned char*)calloc(span,1);queue=(unsigned short*)malloc(span*sizeof(*queue));
 if(!mark||!queued||!labels||!queue){free(mark);free(queued);free(labels);free(queue);return 0;}
 fprintf(o,"\n; ======================================================================\n; CANDIDATE 0x%08X SOURCE %s\n; CFG-reachable only | direct-call returns assumed | no runtime/boundary proof\n; ======================================================================\nfunc_%08X:\n",entry,from_audit?"PASS45_STRICT_AUDIT":"PASS44_BOUNDED",entry);
 queue[tail++]=0;queued[0]=1;labels[0]=1;
 while(head<tail){size_t off,n,j;int ht=0,ft=0,is_call;uint64_t dest=0;char op[192];
  at=queue[head++];off=start+at;stop=(uint32_t)((uint64_t)base+off);
  if(mark[at]==1)continue;
  if(mark[at]==2){status="INSTRUCTION_OVERLAP";goto finished;}
  if(insns>=DK_P46_MAX_INSNS){status="INSTRUCTION_CAP";goto finished;}
  n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>span-at||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED")){status="DECODER_GAP";goto finished;}
  for(j=0;j<n;j++)if(mark[at+j]){status="INSTRUCTION_OVERLAP";goto finished;}
  mark[at]=1;for(j=1;j<n;j++)mark[at+j]=2;insns++;
  if(n==2&&b[off]==0x54&&b[off+1]==0x70){returns++;continue;}
  if(n==2&&b[off]==0x56&&b[off+1]==0x70){status="EXCEPTION_RETURN";goto finished;}
  if(b[off]==0x5d){indirect++;ft=1;ht=0;}
  else if(b[off]==0x59||b[off]==0x5f||b[off]==0x57||(b[off]==0x01&&n>=2&&b[off+1]==0x80)){status="INDIRECT_OR_SPECIAL_FLOW";goto finished;}
  else{
   dk_h8s_flow(b+off,n,base,off,&ht,&dest,&ft);
   is_call=(b[off]==0x5e&&n==4)||(b[off]==0x55&&n==2)||(b[off]==0x5c&&n==4);
   if(is_call){if(!ht||dest>UINT32_MAX||(dest&1u)){status="UNRESOLVED_CALL";goto finished;}ht=0;ft=1;}
   else if(ht){size_t d;
    if(dest<entry||(uint64_t)dest>=(uint64_t)entry+span||(dest&1u)){status="BRANCH_OUTSIDE_WINDOW";goto finished;}
    d=(size_t)(dest-entry);if(mark[d]==2){status="BRANCH_INSTRUCTION_INTERIOR";goto finished;}
    labels[d]=1;if(!queued[d]){queued[d]=1;queue[tail++]=(unsigned short)d;}
   }
  }
  if(ft){size_t d=at+n;
   if(d>=span){status="FALLTHROUGH_OUTSIDE_WINDOW";goto finished;}
   if(mark[d]==2){status="FALLTHROUGH_INSTRUCTION_INTERIOR";goto finished;}
   if(!queued[d]){queued[d]=1;queue[tail++]=(unsigned short)d;}
  }else if(!ht){status="UNKNOWN_TERMINAL";goto finished;}
 }
 if(!returns)status="NO_RETURN";else complete=1;
 finished:
 for(at=0;at<span;at++)if(mark[at]==1){size_t n,j;char op[192];uint32_t address=(uint32_t)((uint64_t)entry+at);
  n=dk_h8s_decode(b+start+at,len-start-at,op,sizeof(op));
  if(labels[at]&&at)fprintf(o,"loc_%08X:\n",address);
  fprintf(o,"  %08X  ",address);for(j=0;j<n;j++)fprintf(o,"%02X ",b[start+at+j]);
  for(j=n;j<8;j++)fputs("   ",o);
  fprintf(o," %-42s",op);
  {int ht=0,ft=0;uint64_t dest=0;dk_h8s_flow(b+start+at,n,base,start+at,&ht,&dest,&ft);
   if(ht&&dest>=entry&&dest<(uint64_t)entry+span&&labels[(size_t)(dest-entry)])fprintf(o," ; -> loc_%08X",(unsigned)dest);
   else if(ht&&dest<=UINT32_MAX)fprintf(o," ; -> 0x%08X",(unsigned)dest);
  }
  {const char *sym=dk_p46_operand_symbol(op);if(sym)fprintf(o," ; symbol %s (user-supplied)",sym);}
  if(b[start+at]==0x5d)fputs(" ; indirect callee unknown, return assumed",o);
  fputc('\n',o);
 }
 if(!complete){size_t j,off=(size_t)(stop-base);fprintf(o,"; STOP 0x%08X REASON %s BYTES",stop,status);for(j=0;j<8&&off+j<len;j++)fprintf(o," %02X",b[off+j]);fputc('\n',o);}
 fprintf(o,"; STATUS %s%s INSTRUCTIONS %u RETURNS %u INDIRECT_CALLS %u\n",complete?(indirect?"CONDITIONAL_INDIRECT_CALLS":"BOUNDED_CFG"):"PARTIAL_",complete?"":status,insns,returns,indirect);
 *total_insns+=insns;free(mark);free(queued);free(labels);free(queue);return complete?1:2;
}
static int dk_p46_export(const unsigned char *b,size_t len,uint32_t base,FILE *index,FILE *asmout,FILE *summary){
 char line[4096];dk_p46_target targets[DK_P46_MAX_TARGETS];size_t count=0,i;unsigned completed=0,partial=0,insns=0,strict=0;
 if(!b||!len||(uint64_t)base+len>0x100000000ULL)return 0;
 while(fgets(line,sizeof(line),index)){
  char *field[16],*p=line;size_t nf=0;uint32_t addr;unsigned long value;char *end;
  if(!strchr(line,'\n')&&!feof(index))return 0;
  while(nf<16){field[nf++]=p;p=strchr(p,'\t');if(!p)break;*p++=0;}
  if(nf<3)continue;
  field[2][strcspn(field[2],"\r\n")]=0;
  if(strcmp(field[0],"CALL_TARGET")&&strcmp(field[0],"PASS45_AUDIT"))continue;
  if(strcmp(field[2],"BOUNDED_CFG"))continue;
  if(strncmp(field[1],"0x",2))return 0;
  value=strtoul(field[1],&end,0);if(*end||value>UINT32_MAX)return 0;addr=(uint32_t)value;
  for(i=0;i<count;i++)if(targets[i].address==addr)break;
  if(i<count)continue;
  if(count==DK_P46_MAX_TARGETS)return 0;
  targets[count].address=addr;targets[count].from_audit=!strcmp(field[0],"PASS45_AUDIT");count++;
 }
 if(ferror(index))return 0;
 fprintf(asmout,"; DRIVEKIT PASS46 READABLE FUNCTION CANDIDATE ASSEMBLY\n; IMAGE_BASE 0x%08X IMAGE_BYTES %lu\n; Static CFG traversal only. Unknown bytes are not converted into code.\n",base,(unsigned long)len);
 fprintf(summary,"DRIVEKIT_PASS46_ASSEMBLY_EXPORT\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nSELECTED_STRICT_CANDIDATES %lu\n",base,(unsigned long)len,(unsigned long)count);
 for(i=0;i<count;i++){
  unsigned before=insns;int result=dk_p46_export_one(b,len,base,asmout,targets[i].address,targets[i].from_audit,&insns);
  if(!result)return 0;
  if(result==1)completed++;else partial++;
  if(targets[i].from_audit)strict++;
  fprintf(summary,"CANDIDATE 0x%08X RESULT %s SOURCE %s LISTED_INSTRUCTIONS %u\n",targets[i].address,result==1?"COMPLETE":"PARTIAL",targets[i].from_audit?"PASS45_STRICT_AUDIT":"PASS44_BOUNDED",insns-before);
 }
 fprintf(summary,"SUMMARY_LISTED_CANDIDATES %lu\nSUMMARY_COMPLETE %u\nSUMMARY_PARTIAL %u\nSUMMARY_PASS45_ADDITIONAL %u\nSUMMARY_ASM_INSTRUCTIONS %u\nNO_RUNTIME_PROOF NO_GLOBAL_FUNCTION_BOUNDARY_PROOF\n",(unsigned long)count,completed,partial,strict,insns);
 return !ferror(asmout)&&!ferror(summary);
}

/* Pass 47: review the actual exported instructions, not guessed opcode coverage.
 * All findings are REVIEW leads, never proof of an incorrect decode.
 * Parse only the fixed-format assembly emitted by dk_p46_export. */
static int dk_p47_review(FILE *listing,FILE *review,uint32_t base,size_t len){
 char line[1024],opcode[192],bytes[64];unsigned total=0,findings=0,external=0,selfmove=0,indirect=0;
 unsigned shown=0;uint32_t current=0;unsigned current_findings=0;
 if(!listing||!review||fseek(listing,0,SEEK_SET))return 0;
 fprintf(review,"DRIVEKIT_PASS47_ASSEMBLY_REVIEW\nPOLICY HEURISTIC_REVIEW_ONLY NO_CONFIRMED_DECODER_DEFECTS NO_RUNTIME_PROOF\nIMAGE_RANGE 0x%08X..0x%08X (exclusive)\n",base,(unsigned)((uint64_t)base+len));
 while(fgets(line,sizeof(line),listing)){
  unsigned addr;char *p,*q;size_t k=0;int hashex=0;
  if(sscanf(line,"; CANDIDATE 0x%x",&addr)==1){current=addr;current_findings=0;continue;}
  if(line[0]!=' '||line[1]!=' '||sscanf(line+2,"%x",&addr)!=1)continue;
  p=line+2;while(*p&&*p!=' ')p++;while(*p==' ')p++;
  /* Raw instruction bytes occupy a fixed 24-column field. */
  if(strlen(p)<25)continue;
  memcpy(bytes,p,24);bytes[24]=0;
  for(k=0;k<24;k++)if((bytes[k]>='A'&&bytes[k]<='F')||(bytes[k]>='0'&&bytes[k]<='9'))hashex=1;
  if(!hashex)continue;
  q=p+24;while(*q==' ')q++;if(!*q)continue;
  {size_t z=strcspn(q,";\r\n");if(z>=sizeof(opcode))z=sizeof(opcode)-1;memcpy(opcode,q,z);opcode[z]=0;while(z&&opcode[z-1]==' ')opcode[--z]=0;}
  total++;
  if(!strncmp(opcode,"MOV.",4)){
   char *space=strchr(opcode,' ');if(space){char a[64],b[64];if(sscanf(space+1,"%63[^,],%63s",a,b)==2&&!strcmp(a,b)){
    selfmove++;findings++;current_findings++;
    fprintf(review,"REVIEW 0x%08X CANDIDATE 0x%08X KIND SELF_MOVE OPCODE %s NOTE may deliberately update condition flags\n",addr,current,opcode);
   }}
  }
  if(!strncmp(opcode,"JSR @H'",7)||!strncmp(opcode,"JMP @H'",7)){
   unsigned target=0;char *end=NULL;unsigned long val=strtoul(opcode+7,&end,16);
   if(end!=opcode+7&&end&&*end==':'&&val<=UINT32_MAX){target=(unsigned)val;
    if(target<base||(uint64_t)target>=(uint64_t)base+len){external++;findings++;current_findings++;
     fprintf(review,"REVIEW 0x%08X CANDIDATE 0x%08X KIND OUTSIDE_IMAGE_DIRECT_TRANSFER TARGET 0x%08X OPCODE %s NOTE check address encoding and memory map\n",addr,current,target,opcode);
    }
   }
  }
  if(!strncmp(opcode,"JSR @ER",7)||!strncmp(opcode,"JMP @ER",7)){
   indirect++;findings++;current_findings++;
   fprintf(review,"REVIEW 0x%08X CANDIDATE 0x%08X KIND INDIRECT_TRANSFER OPCODE %s NOTE target not statically resolved\n",addr,current,opcode);
  }
 }
 fprintf(review,"SUMMARY_INSTRUCTIONS_INSPECTED %u\nSUMMARY_REVIEW_LEADS %u\nSUMMARY_SELF_MOVES %u\nSUMMARY_OUTSIDE_IMAGE_DIRECT_TRANSFERS %u\nSUMMARY_INDIRECT_TRANSFERS %u\n",total,findings,selfmove,external,indirect);
 fprintf(review,"IDA_GUIDANCE Validate only a handful of distinct instruction encodings. Compare raw bytes, instruction size, operands, branch destinations, and mapped image base. IDA is a cross-check, not ground truth.\n");
 return !ferror(listing)&&!ferror(review);
}

static int dk_p35_report(const unsigned char *b,size_t len,uint32_t base,FILE *o,int have_entry,uint32_t entry){
 dk_p35_seed *seeds;size_t count=0,i,j,runs=0,pointers=0,limited=0,bounded=0,unresolved=0;unsigned source;size_t reason_counts[32]={0};const char *reason_names[32]={0};size_t reason_n=0;dk_p37_trace *traces=NULL;dk_p35_result *results=NULL;dk_p37_site *sites=NULL;size_t site_n=0,overlap_pairs=0,contained=0,branch_entries=0,call_entries=0,shared_exits=0,unique_insns=0;unsigned char *coverage=NULL;
 if(!b||!o||!len||(uint64_t)base+len>0x100000000ULL)return 0;
 seeds=(dk_p35_seed*)calloc(DK_P35_MAX_SEEDS,sizeof(*seeds));if(!seeds)return 0;
 fprintf(o,"DRIVEKIT_PASS37_CODE_SURVEY\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nPOLICY IMAGE_DERIVED_SEEDS BOUNDED_CFG CALL_RETURNS_ASSUMED NO_ENTRY_PROOF NO_RUNTIME_REACHABILITY_PROOF\nWINDOW_BYTES %u\nMAX_INSTRUCTIONS %u\nMAX_SEEDS %u\n",base,(unsigned long)len,DK_P35_WINDOW,DK_P35_MAX_INSNS,DK_P35_MAX_SEEDS);
 if(have_entry){if(!dk_p35_add(seeds,&count,entry,1)){free(seeds);return 0;}}
 /* Scan all 4 possible word alignments of pointer runs, without fixed offsets. */
 for(i=0;i+16<=len;i+=2){size_t n=0;
  if(i>=4){uint32_t prev=dk_p33_be32(b+i-4);if(prev>=base&&(uint64_t)prev<(uint64_t)base+len&&!(prev&1u))continue;}
  for(j=i;j+4<=len&&n<DK_P35_MAX_POINTER_RUN;j+=4){uint32_t v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;n++;}
  if(n<4)continue;
  runs++;pointers+=n;
  for(j=0;j<n;j++){
   uint32_t v=dk_p33_be32(b+i+4*j);
   if(!dk_p35_add(seeds,&count,v,2))limited++;
   else {size_t t;for(t=0;t<count;t++)if(seeds[t].address==v){if(!seeds[t].pointer_references)seeds[t].first_pointer_run=(uint32_t)((uint64_t)base+i);seeds[t].pointer_references++;break;}}
  }
  if(pointers>=DK_P35_MAX_TOTAL_POINTERS)break;
 }
 traces=(dk_p37_trace*)calloc(count,sizeof(*traces));results=(dk_p35_result*)calloc(count,sizeof(*results));sites=(dk_p37_site*)calloc(count,sizeof(*sites));coverage=(unsigned char*)calloc(len,1);
 if(!traces||!results||!sites||!coverage){free(coverage);free(sites);free(results);free(traces);free(seeds);return 0;}
 fprintf(o,"POINTER_RUNS %lu\nPOINTER_ENTRIES %lu\nSEEDS_SELECTED %lu\nSEEDS_LIMITED %lu\n",(unsigned long)runs,(unsigned long)pointers,(unsigned long)count,(unsigned long)limited);
 for(i=0;i<count;i++){
  dk_p35_result r;int ok=dk_p37_check_trace(b,len,base,seeds[i].address,&r,&traces[i]);results[i]=r;
  source=seeds[i].sources;
  if(seeds[i].pointer_references)fprintf(o,"  POINTER_PROVENANCE SEED 0x%08X FIRST_RUN 0x%08X REFERENCES %u NOT_FUNCTION_PROOF\n",seeds[i].address,seeds[i].first_pointer_run,seeds[i].pointer_references);
  fprintf(o,"CANDIDATE 0x%08X SOURCE_%s%s STATUS %s INSTRUCTIONS %u RETURNS %u CALLS %u BRANCHES %u ENTRY_NOT_PROVEN\n",seeds[i].address,(source&1)?"USER_SEED":"POINTER_RUN",source==3?"_AND_POINTER_RUN":"",r.reason,r.insns,r.returns,r.calls,r.branches);
  if(!ok){size_t z,k;for(k=0;k<site_n;k++)if(sites[k].address==r.stop_address&&!strcmp(sites[k].reason,r.reason))break;
   if(k==site_n){sites[k].address=r.stop_address;sites[k].reason=r.reason;sites[k].count=r.stop_count;memcpy(sites[k].bytes,r.stop_bytes,r.stop_count);site_n++;}sites[k].references++;
   for(z=0;z<reason_n;z++)if(!strcmp(reason_names[z],r.reason))break;
   if(z==reason_n&&reason_n<32){reason_names[reason_n++]=r.reason;}if(z<32)reason_counts[z]++;
   fprintf(o,"  FAILURE_AT 0x%08X BYTES",r.stop_address);
   for(z=0;z<r.stop_count;z++)fprintf(o," %02X",r.stop_bytes[z]);
   fprintf(o," PARTIAL_CFG_ONLY\n");
  }
  if(ok){size_t k;bounded++;for(k=0;k<r.stored_calls;k++)fprintf(o,"  DIRECT_CALL 0x%08X NOT_REACHABILITY_PROOF\n",r.call_targets[k]);if(r.calls>r.stored_calls)fprintf(o,"  CALL_LIST_TRUNCATED %u\n",r.calls-r.stored_calls);}
  else unresolved++;
 }
 /* Relate actual decoded instruction starts, not mere overlapping windows. */
 for(i=0;i<count;i++){size_t k,jj;uint32_t a=seeds[i].address;
  for(k=0;k<DK_P35_WINDOW;k++)if(traces[i].starts[k]){uint64_t pos=(uint64_t)a-base+k;if(pos<len&&!coverage[pos]){coverage[pos]=1;unique_insns++;}}
  for(j=0;j<count;j++)if(i!=j){int overlap=0;uint32_t other=seeds[j].address;
   if(other>=a&&(uint64_t)other<(uint64_t)a+DK_P35_WINDOW&&traces[i].starts[other-a])contained++;
   for(k=0;k<DK_P35_WINDOW&&!overlap;k++)if(traces[i].starts[k]){uint64_t v=(uint64_t)a+k;if(v>=other&&v<(uint64_t)other+DK_P35_WINDOW&&traces[j].starts[v-other])overlap=1;}
   if(overlap&&j>i)overlap_pairs++;
   for(k=0;k<traces[i].branch_count;k++)if(traces[i].branches[k]==other){branch_entries++;break;}
   for(k=0;k<results[i].stored_calls;k++)if(results[i].call_targets[k]==other){call_entries++;break;}
   for(k=0;k<traces[i].return_count;k++){for(jj=0;jj<traces[j].return_count;jj++)if(traces[i].returns[k]==traces[j].returns[jj]){if(j>i)shared_exits++;goto p37_next_pair;}}
   p37_next_pair:;
  }
 }
 fprintf(o,"PASS37_RELATIONSHIP_AUDIT\nUNIQUE_DECODED_INSTRUCTION_STARTS %lu\nOVERLAPPING_CANDIDATE_PAIRS %lu\nENTRY_CONTAINMENT_RELATIONS %lu\nDIRECT_BRANCH_TO_CANDIDATE_RELATIONS %lu\nDIRECT_CALL_TO_CANDIDATE_RELATIONS %lu\nSHARED_RETURN_CANDIDATE_PAIRS %lu\n",(unsigned long)unique_insns,(unsigned long)overlap_pairs,(unsigned long)contained,(unsigned long)branch_entries,(unsigned long)call_entries,(unsigned long)shared_exits);
 for(i=0;i<count;i++){size_t j,k,contained_by=0,branched_to=0,called_by=0,shared_with=0;uint32_t a=seeds[i].address;
  for(j=0;j<count;j++)if(i!=j){uint32_t other=seeds[j].address;
   if(a>=other&&(uint64_t)a<(uint64_t)other+DK_P35_WINDOW&&traces[j].starts[a-other])contained_by++;
   for(k=0;k<traces[j].branch_count;k++)if(traces[j].branches[k]==a){branched_to++;break;}
   for(k=0;k<results[j].stored_calls;k++)if(results[j].call_targets[k]==a){called_by++;break;}
   for(k=0;k<traces[i].return_count;k++){unsigned t;for(t=0;t<traces[j].return_count;t++)if(traces[i].returns[k]==traces[j].returns[t]){shared_with++;goto p37_pair_done;}}
   p37_pair_done:;
  }
  if(contained_by||branched_to||called_by||shared_with)fprintf(o,"RELATION 0x%08X STATUS %s CONTAINED_BY %lu BRANCHED_TO_BY %lu CALLED_BY %lu SHARED_RETURN_WITH %lu ENTRY_NOT_PROVEN\n",a,results[i].reason,(unsigned long)contained_by,(unsigned long)branched_to,(unsigned long)called_by,(unsigned long)shared_with);
 }
 fprintf(o,"PASS37_UNIQUE_FAILURE_SITES %lu\n",(unsigned long)site_n);
 for(i=0;i<site_n;i++){size_t k;fprintf(o,"FAILURE_SITE 0x%08X STATUS %s SEED_REFERENCES %lu BYTES",sites[i].address,sites[i].reason,(unsigned long)sites[i].references);for(k=0;k<sites[i].count;k++)fprintf(o," %02X",sites[i].bytes[k]);fprintf(o," CLASSIFICATION_NOT_PROVEN\n");}
 fprintf(o,"SUMMARY_BOUNDED %lu\nSUMMARY_UNRESOLVED %lu\n",(unsigned long)bounded,(unsigned long)unresolved);
 for(i=0;i<reason_n;i++)fprintf(o,"SUMMARY_STATUS_%s %lu\n",reason_names[i],(unsigned long)reason_counts[i]);
 fprintf(o,"SUMMARY_ACCOUNTED %lu\nNO_WHOLE_IMAGE_CODE_PROOF\n",(unsigned long)(bounded+unresolved));
 free(coverage);free(sites);free(results);free(traces);free(seeds);return !ferror(o);
}
#endif
