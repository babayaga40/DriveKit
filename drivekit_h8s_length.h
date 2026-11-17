#ifndef DRIVEKIT_H8S_LENGTH_H
#define DRIVEKIT_H8S_LENGTH_H
/* H8S/2600 encoding validator, adapted from Matthew Jackson's MIT-licensed
 * H8/300/H8S length.rs (Copyright (c) 2026 Matthew Jackson).
 * Returns 0 for invalid OR truncated encodings, otherwise byte length.
 * Restricted to H8S/2600 Advanced; no H8SX claims. */
#include <stddef.h>
#include <stdint.h>
static int dk_len_word(const uint8_t *p,size_t n,size_t off,unsigned *w) {
    if(off>n || n-off<2)return 0;
    *w=((unsigned)p[off]<<8)|p[off+1];return 1;
}
static size_t dk_len_ext(const uint8_t *p,size_t n,size_t off,size_t len){
    (void)p;return n>=len && off<=len?len:0;
}
static size_t dk_len_bit(const uint8_t *p,size_t n,size_t off,int write){
    unsigned w;if(!dk_len_word(p,n,off,&w))return 0;
    if(write) {
        if((w&0xff0f)==0x6000||(w&0xff0f)==0x6100||(w&0xff0f)==0x6200||(w&0xff0f)==0x6700||
           (w&0xff8f)==0x7000||(w&0xff8f)==0x7100||(w&0xff8f)==0x7200)return off+2;
    }else{
        if((w&0xff0f)==0x6300||(w&0xff0f)==0x7400||(w&0xff0f)==0x7500||
           (w&0xff0f)==0x7600||(w&0xff0f)==0x7700||(w&0xff8f)==0x7300)return off+2;
    }
    return 0;
}
static size_t dk_len_disp(const uint8_t *p,size_t n,size_t off,unsigned a,int lng,int control){
    unsigned b,mask,expected;int alias;
    if(!dk_len_word(p,n,off+2,&b))return 0;
    alias=lng&&!control&&(b&0xfff8)==0x6ba0;
    if((a&(alias?0xff0f:0xff8f))!=0x7800)return 0;
    mask=control?0xff7f:lng?0xff78:0xfe70;
    expected=(lng||control)?0x6b20:0x6a20;
    if((b&mask)!=expected)return 0;
    return dk_len_ext(p,n,off+4,off+8);
}
static size_t dk_len_prefmove(const uint8_t *p,size_t n,unsigned w,int control){
    if(w&(control?15:8))return 0;
    switch(w>>8){
    case 0x69:case 0x6d:return 4;
    case 0x6f:return n>=6?6:0;
    case 0x6b:
        switch(w&0xf0){case 0:case 0x80:return n>=6?6:0;
        case 0x20:case 0xa0:return dk_len_ext(p,n,4,8);default:return 0;}
    case 0x78:return dk_len_disp(p,n,2,w,1,control);
    default:return 0;
    }
}
static size_t dk_h8s2600_length(const uint8_t *p,size_t n){
    unsigned w,hi,lo,v,group,count,r,first;int valid=0;
    if(!dk_len_word(p,n,0,&w))return 0;
    hi=w>>8;lo=w&255;
    switch(hi){
    case 0x00:valid=w==0;break;
    case 0x01:
        if(w==0x0180||w==0x01a0)return 2;
        if(!dk_len_word(p,n,2,&v))return 0;
        switch(w){
        case 0x0100:return dk_len_prefmove(p,n,v,0);
        case 0x0140:return dk_len_prefmove(p,n,v,1);
        case 0x0141:
            if((v>>8)>=4&&(v>>8)<=7)return 4;
            return dk_len_prefmove(p,n,v,1);
        case 0x0110:case 0x0120:case 0x0130:
            count=(w>>4)&3;r=v&7;
            if((v&0xfff8)==0x6d70 && r>=count)first=r-count;
            else if((v&0xfff8)==0x6df0 && r+count<=7)first=r;
            else return 0;
            valid=(first%(count==1?2:4))==0;break;
        case 0x0160:valid=(v&0xff88)==0x6d00;break;
        case 0x01c0:valid=(v>>8)==0x50||(v&0xff08)==0x5200;break;
        case 0x01d0:valid=(v>>8)==0x51||(v&0xff08)==0x5300;break;
        case 0x01e0:valid=(v&0xffaf)==0x7b0c;break;
        case 0x01f0:valid=(v&0xff88)==0x6400||(v&0xff88)==0x6500||(v&0xff88)==0x6600;break;
        default:return 0;
        }
        return valid?4:0;
    case 0x02:case 0x03:valid=lo<32||(lo&0xe8)==0x20;break;
    case 0x04:case 0x05:case 0x06:case 0x07:case 0x08:case 0x0c:case 0x0e:
    case 0x14:case 0x15:case 0x16:case 0x18:case 0x1c:case 0x1e:valid=1;break;
    case 0x09:case 0x0d:case 0x19:case 0x1d:valid=1;break;
    case 0x0a:case 0x1a:case 0x0f:case 0x1f:valid=lo<16||(lo&0x88)==0x80;break;
    case 0x0b:case 0x1b:
        group=lo>>4;
        if(group==0||group==8||group==9||group==7||group==15)valid=(lo&8)==0;
        else if(group==5||group==13)valid=1;
        break;
    case 0x10:case 0x11:case 0x12:case 0x13:
        group=lo>>4;
        valid=group==0||group==8||group==1||group==9||group==4||group==5||group==12||group==13||
              ((group==3||group==11||group==7||group==15)&&!(lo&8));break;
    case 0x17:
        group=lo>>4;
        valid=group==0||group==8||group==1||group==5||group==9||group==13||
              ((group==3||group==7||group==11||group==15)&&!(lo&8));break;
    case 0x20:case 0x21:case 0x22:case 0x23:case 0x24:case 0x25:case 0x26:case 0x27:
    case 0x28:case 0x29:case 0x2a:case 0x2b:case 0x2c:case 0x2d:case 0x2e:case 0x2f:
    case 0x30:case 0x31:case 0x32:case 0x33:case 0x34:case 0x35:case 0x36:case 0x37:
    case 0x38:case 0x39:case 0x3a:case 0x3b:case 0x3c:case 0x3d:case 0x3e:case 0x3f:
    case 0x5b:case 0x5f:valid=1;break;
    case 0x40:case 0x41:case 0x42:case 0x43:case 0x44:case 0x45:case 0x46:case 0x47:
    case 0x48:case 0x49:case 0x4a:case 0x4b:case 0x4c:case 0x4d:case 0x4e:case 0x4f:
    case 0x55:valid=!(lo&1);break;
    case 0x50:case 0x51:case 0x52:case 0x53:valid=1;break;
    case 0x54:case 0x56:valid=lo==0x70;break;
    case 0x57:valid=(lo&0xcf)==0;break;
    case 0x58:
        if(lo&15)return 0;
        if(!dk_len_word(p,n,2,&v))return 0;
        return (v&1)?0:4;
    case 0x59:case 0x5d:valid=(lo&0x8f)==0;break;
    case 0x5a:case 0x5e:return n>=4?4:0;
    case 0x5c:
        if(lo)return 0;
        if(!dk_len_word(p,n,2,&v))return 0;
        return (v&1)?0:4;
    case 0x60:case 0x61:case 0x62:case 0x63:case 0x67:case 0x68:case 0x6c:
    case 0x64:case 0x65:case 0x66:case 0x69:case 0x6d:valid=1;break;
    case 0x6a:case 0x6b:
        switch(w&0xf0){
        case 0:case 0x80:case 0x40:case 0xc0:return n>=4?4:0;
        case 0x20:case 0xa0:return dk_len_ext(p,n,2,6);
        case 0x10:case 0x30:
            if(w&0x0107)return 0;
            return dk_len_bit(p,n,(w&0x20)?6:4,(w&8)!=0);
        default:return 0;
        }
    case 0x6e:case 0x6f:return n>=4?4:0;
    case 0x70:case 0x71:case 0x72:case 0x73:valid=(lo&0x80)==0;break;
    case 0x74:case 0x75:case 0x76:case 0x77:valid=1;break;
    case 0x78:return dk_len_disp(p,n,0,w,0,0);
    case 0x79:return lo<0x70&&n>=4?4:0;
    case 0x7a:return lo<0x70&&!(lo&8)&&n>=6?6:0;
    case 0x7b:
        if(lo!=0x5c&&lo!=0xd4)return 0;
        return dk_len_word(p,n,2,&v)&&v==0x598f?4:0;
    case 0x7c:case 0x7d:
        return (lo&0x8f)==0?dk_len_bit(p,n,2,hi==0x7d):0;
    case 0x7e:case 0x7f:return dk_len_bit(p,n,2,hi==0x7f);
    default:valid=hi>=0x80;break;
    }
    return valid?2:0;
}
#endif
