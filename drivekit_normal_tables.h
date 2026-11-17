#ifndef DRIVEKIT_NORMAL_TABLES_H
#define DRIVEKIT_NORMAL_TABLES_H
/* Pass 33: address-shaped data is NOT a task table, code, or execution proof. */
static uint32_t dk_p33_be32(const unsigned char *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static int dk_normal_tables_report(const unsigned char *b,size_t len,uint32_t base,FILE *o){
 size_t i,j,tables=0,entries=0,overlaps=0,known=0;unsigned char *bounded;
 if(!b||!o||base!=0x410000u||len!=0x1c9e00u)return 0;
 bounded=(unsigned char*)calloc(len,1);if(!bounded)return 0;
 /* Strict bounded candidates are independent evidence, not proof of entry. */
 for(i=0;i+4<=len;i+=2){unsigned n=0,r=0;char op[192];
  if(b[i]!=1||b[i+1]!=0||b[i+2]!=0x6d||(b[i+3]&0xf8)!=0xf0||(b[i+3]&7)==7)continue;
  if(dk_h8s_decode(b+i,len-i,op,sizeof(op))!=4)continue;
  if(dk_p32_validate(b,len,i,base,&n,&r))bounded[i]=1;
 }
 fprintf(o,"; DriveKit Pass 33 Normal pointer-run discovery (offline read-only)\nIMAGE_BASE 0x%08X\nIMAGE_BYTES %lu\nPOLICY ALIGNED_BIG_ENDIAN_POINTER_RUN MINIMUM_4 NO_TASK_TABLE_PROOF NO_ENTRY_PROOF NO_HELPER_CERTIFICATE\n",base,(unsigned long)len);
 /* Non-overlapping maximal runs of 4-byte aligned address-shaped values. */
 for(i=0;i+16<=len;i+=4){size_t start=i,count=0,hits=0;uint32_t v;
  if(i>=4){v=dk_p33_be32(b+i-4);if(v>=base&&((uint64_t)v)<(uint64_t)base+len&&(v&1u)==0)continue;}
  for(j=i;j+4<=len;j+=4){v=dk_p33_be32(b+j);if(v<base||(uint64_t)v>=(uint64_t)base+len||(v&1u))break;count++;if(bounded[v-base])hits++;}
  if(count<4)continue;
  tables++;entries+=count;overlaps+=hits;
  fprintf(o,"POINTER_RUN_CANDIDATE 0x%08X IDA_OFFSET 0x%08X ENTRIES %lu BOUNDED_PROLOGUE_TARGETS %lu HEURISTIC_ONLY\n",base+(unsigned)start,(unsigned)start,(unsigned long)count,(unsigned long)hits);
  if(hits){size_t k;for(k=0;k<count;k++){v=dk_p33_be32(b+start+4*k);if(bounded[v-base])fprintf(o,"  TARGET 0x%08X BOUNDED_PROLOGUE_CORROBORATION NOT_ENTRY_PROOF\n",v);if(v==0x4156a0u)known++;}}
  i=j-4;
 }
 fprintf(o,"TOTAL_POINTER_RUN_CANDIDATES %lu\nTOTAL_POINTER_RUN_ENTRIES %lu\nTOTAL_BOUNDED_PROLOGUE_TARGET_MATCHES %lu\nKNOWN_IDA_TARGET_0x004156A0 %s\nNO_DISPATCH_SEMANTICS_PROVEN\nNO_WHOLE_IMAGE_REACHABILITY_CLAIM\n",(unsigned long)tables,(unsigned long)entries,(unsigned long)overlaps,known?"POINTER_RUN_REFERENCE":"NO_POINTER_RUN_REFERENCE");
 free(bounded);return !ferror(o);
}
#endif
