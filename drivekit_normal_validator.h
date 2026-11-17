#ifndef DRIVEKIT_NORMAL_VALIDATOR_H
#define DRIVEKIT_NORMAL_VALIDATOR_H
/* Pass 32: bounded, conservative heuristic filtering. No entry or helper proof. */
#define DK_P32_WINDOW 256u
#define DK_P32_MAX_INSNS 128u
static int dk_p32_validate(const unsigned char *b,size_t len,size_t start,uint32_t base,
                           unsigned *insns,unsigned *returns){
 unsigned char state[DK_P32_WINDOW]={0},queued[DK_P32_WINDOW]={0};
 unsigned short q[DK_P32_WINDOW];unsigned head=0,tail=0,ret=0,count=0;
 if(start>=len||len-start<4)return 0;
 q[tail++]=0;queued[0]=1;
 while(head<tail){
  size_t at=q[head++],n,j,off=start+at;char op[192];int ht=0,ft=0;uint64_t dest=0;
  if(at>=DK_P32_WINDOW||off>=len||state[at]||count>=DK_P32_MAX_INSNS)return 0;
  n=dk_h8s_decode(b+off,len-off,op,sizeof(op));
  if(!n||n>DK_P32_WINDOW-at||strstr(op,".BYTE")||strstr(op,"UNIMPLEMENTED"))return 0;
  for(j=0;j<n;j++)if(state[at+j])return 0;
  state[at]=1;for(j=1;j<n;j++)state[at+j]=2;
  count++;
  /* No calls, indirect jumps, traps, sleeps or exception exits in this first filter. */
  if(b[off]==0x5e||b[off]==0x5d||b[off]==0x59||b[off]==0x5f||
     b[off]==0x55||b[off]==0x5c||b[off]==0x57||
     (b[off]==0x01&&b[off+1]==0x80)||
     (b[off]==0x54&&b[off+1]==0x70)){
   if(b[off]==0x54&&b[off+1]==0x70){ret++;continue;}
   return 0;
  }
  if(b[off]==0x56&&b[off+1]==0x70)return 0;
  dk_h8s_flow(b+off,n,base+(uint32_t)start,at,&ht,&dest,&ft);
  if(ht){size_t d;
   if(dest<base+(uint64_t)start||dest>=base+(uint64_t)start+DK_P32_WINDOW)return 0;
   d=(size_t)(dest-(base+(uint64_t)start));
   if(d&1u)return 0;
   if(!queued[d]){queued[d]=1;q[tail++]=(unsigned short)d;}
  }
  if(ft){size_t d=at+n;
   if(d>=DK_P32_WINDOW||d&1u)return 0;
   if(!queued[d]){queued[d]=1;q[tail++]=(unsigned short)d;}
  }
  if(!ht&&!ft)return 0;
 }
 if(!ret)return 0;
 *insns=count;*returns=ret;return 1;
}
static int dk_normal_validate_report(const unsigned char *b,size_t len,uint32_t base,FILE *o){
 size_t i,candidates=0,bounded=0,unresolved=0,known=0;
 if(!b||!o||base!=0x410000u||len!=0x1c9e00u)return 0;
 fprintf(o,"; DriveKit Pass 32 Normal bounded prologue candidate filter (offline read-only)\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nPOLICY EXACT_PUSH_PROLOGUE BOUNDED_CFG_HEURISTIC NOT_ENTRY_PROOF NOT_HELPER_CERTIFIED\nWINDOW_BYTES %u\nMAX_INSTRUCTIONS %u\n",base,(unsigned long)len,DK_P32_WINDOW,DK_P32_MAX_INSNS);
 for(i=0;i+4<=len;i+=2){unsigned reg,insns=0,returns=0;char op[192];size_t n;
  if(b[i]!=1||b[i+1]!=0||b[i+2]!=0x6d||(b[i+3]&0xf8)!=0xf0)continue;
  reg=b[i+3]&7u;if(reg==7)continue;
  n=dk_h8s_decode(b+i,len-i,op,sizeof(op));if(n!=4)continue;
  candidates++;
  if(dk_p32_validate(b,len,i,base,&insns,&returns)){
   bounded++;
   fprintf(o,"BOUNDED_CANDIDATE 0x%08X IDA_OFFSET 0x%08X PUSH_ER%u INSTRUCTIONS %u RETURNS %u NO_ENTRY_PROOF NO_HELPER_CERTIFICATE\n",base+(unsigned)i,(unsigned)i,reg,insns,returns);
   if(i==0x56a0u)known=1;
  }else{unresolved++;if(i==0x56a0u)known=2;}
 }
 fprintf(o,"TOTAL_PROLOGUE_CANDIDATES %lu\nTOTAL_BOUNDED_CANDIDATES %lu\nTOTAL_UNRESOLVED_CANDIDATES %lu\nKNOWN_IDA_SEED_0x004156A0 %s\nNO_WHOLE_IMAGE_REACHABILITY_CLAIM\n",(unsigned long)candidates,(unsigned long)bounded,(unsigned long)unresolved,known==1?"BOUNDED_HEURISTIC":known==2?"UNRESOLVED":"NOT_FOUND");
 return !ferror(o);
}
#endif
