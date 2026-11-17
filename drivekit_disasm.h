#ifndef DRIVEKIT_DISASM_H
#define DRIVEKIT_DISASM_H
/*
 * DriveKit H8S/2600 offline disassembler - STAGE 8 (validated H8S/2600 instruction lengths and semantic coverage).
 * Native C adaptation informed by Matthew Jackson's H8 instruction library.
 * Original work Copyright (c) 2026 Matthew Jackson.
 * C adaptation for DriveKit (c) 2026 DriveKit contributors.
 *
 * MIT License
 *
 * Copyright (c) 2026 Matthew Jackson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * WARNING: This decoder still recognizes only a subset of H8S/2600 instructions.
 * Unknown aligned instruction units are emitted as .WORD, not guessed instructions.
 * Linear output does NOT prove that bytes are executable code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include "drivekit_h8s_length.h"

/* Renesas register spellings, as used by the original H8 decoder. */
static void dk_h8s_reg(char *s, size_t cap, unsigned int size, unsigned int r)
{
    if (size == 32) snprintf(s, cap, "ER%u", r & 7);
    else if (size == 16) snprintf(s, cap, "%c%u", (r & 8) ? 'E' : 'R', r & 7);
    else snprintf(s, cap, "R%u%c", r & 7, r & 8 ? 'L' : 'H');
}

static const char *dk_h8s_bit_name(unsigned int op, unsigned int lo)
{
    static const char *direct[] = {"BSET","BNOT","BCLR","BTST"};
    static const char *logic[] = {"BOR","BXOR","BAND","BLD"};
    static const char *ilogic[] = {"BIOR","BIXOR","BIAND","BILD"};
    if (op >= 0x70 && op <= 0x73) return direct[op-0x70];
    if (op >= 0x60 && op <= 0x63) return direct[op-0x60];
    if (op == 0x67) return lo & 0x80 ? "BIST" : "BST";
    if (op >= 0x74 && op <= 0x77) return lo & 0x80 ? ilogic[op-0x74] : logic[op-0x74];
    return NULL;
}

/* Returns recognized length, or 0 if unrecognized/truncated. */
static size_t dk_h8s_decode_semantic(const unsigned char *p, size_t n, char *out, size_t cap)
{
    unsigned int w, op, lo;
    static const char *conds[16] = {
        "BRA","BRN","BHI","BLS","BCC","BCS","BNE","BEQ",
        "BVC","BVS","BPL","BMI","BGE","BLT","BGT","BLE"
    };
    if (n < 2) return 0;
    w = ((unsigned int)p[0] << 8) | p[1];
    op = p[0]; lo = p[1];
    /* Renesas REJ09B0139-0400, sections 2.2.36 (LDM) and STM:
       01 10/20/30 6D 7n = LDM.L @SP+,(ERfirst-ERlast)
       01 10/20/30 6D Fn = STM.L (ERfirst-ERlast),@-SP
       Length validator already enforces the permitted aligned groups. */
    if (n >= 4 && op == 0x01 &&
        (lo == 0x10 || lo == 0x20 || lo == 0x30) &&
        p[2] == 0x6d && ((p[3] & 0xf8) == 0x70 || (p[3] & 0xf8) == 0xf0)) {
        unsigned int extra = lo >> 4;
        unsigned int r = p[3] & 7;
        if ((p[3] & 0xf8) == 0x70) {
            snprintf(out, cap, "LDM.L @SP+,(ER%u-ER%u)", r-extra, r);
        } else {
            snprintf(out, cap, "STM.L (ER%u-ER%u),@-SP", r, r+extra);
        }
        return 4;
    }
    /* Renesas H8S/2600 control-register word transfers, prefix 01 40/41.
       01 40 6D F0 = STC.W CCR,@-ER7 (not STM.L).
       The 01 40/41 prefix selects CCR/EXR, respectively. */
    if (n >= 4 && (w == 0x0140 || w == 0x0141) &&
        (p[2] == 0x69 || p[2] == 0x6d) && !(p[3] & 0x0f)) {
        unsigned int base=(p[3]>>4)&7, store=(p[3]&0x80)!=0;
        const char *cr=w==0x0140?"CCR":"EXR";
        if (p[2]==0x6d) {
            if(store)snprintf(out,cap,"STC.W %s,@-ER%u",cr,base);
            else snprintf(out,cap,"LDC.W @ER%u+,%s",base,cr);
        } else {
            if(store)snprintf(out,cap,"STC.W %s,@ER%u",cr,base);
            else snprintf(out,cap,"LDC.W @ER%u,%s",base,cr);
        }
        return 4;
    }
    /* Renesas H8S/2600: STC.B CCR/EXR,RnH/L and LDC.B inverse. */
    if ((op == 0x02 || op == 0x03) && lo < 0x20) {
        char r[12]; dk_h8s_reg(r,sizeof(r),8,lo&15);
        if (op == 0x02) snprintf(out,cap,"STC.B %s,%s",(lo&0x10)?"EXR":"CCR",r);
        else snprintf(out,cap,"LDC.B %s,%s",r,(lo&0x10)?"EXR":"CCR");
        return 2;
    }
    /* MOV.L displacement:32 prefixed 01 00 78 xy 6B zw dd dd dd dd.
       Validated by the independent 10-byte length recognizer. */
    if (w == 0x0100 && n >= 10 && p[2] == 0x78 &&
        (p[3]&0x8f)==0 && p[4]==0x6b && (p[5]&0x78)==0x20) {
        uint32_t d=((uint32_t)p[6]<<24)|((uint32_t)p[7]<<16)|((uint32_t)p[8]<<8)|p[9];
        unsigned int base=(p[3]>>4)&7,reg=p[5]&7,store=(p[5]&0x80)!=0;
        if(store)snprintf(out,cap,"MOV.L ER%u,@(H'%X:32,ER%u)",reg,(unsigned)d,base);
        else snprintf(out,cap,"MOV.L @(H'%X:32,ER%u),ER%u",(unsigned)d,base,reg);
        return 10;
    }
    /* H8S signed extended multiply/divide.  The independent length
       validator accepts 01 C0 50/52 and 01 D0 51/53 forms.
       Keep the same register operand convention as unsigned forms. */
    if (n >= 4 && (w == 0x01c0 || w == 0x01d0) &&
        ((w == 0x01c0 && (p[2] == 0x50 || (p[2] == 0x52 && !(p[3] & 8)))) ||
         (w == 0x01d0 && (p[2] == 0x51 || (p[2] == 0x53 && !(p[3] & 8)))))) {
        unsigned int bits=(p[2]&2)?16:8;
        char src[12],dst[12];
        dk_h8s_reg(src,sizeof(src),bits,p[3]>>4);
        dk_h8s_reg(dst,sizeof(dst),bits==8?16:32,p[3]&7);
        snprintf(out,cap,"%s.%c %s,%s",(p[2]&1)?"DIVXS":"MULXS",
                 bits==8?'B':'W',src,dst);
        return 4;
    }
    /* Renesas H8S/2600: MULXU/DIVXU byte-to-word and word-to-long.
       50/51 xy: source byte register x, destination word register y.
       52/53 xy: source word register x, destination long register y. */
    if (op >= 0x50 && op <= 0x53) {
        unsigned int bits=(op&2)?16:8;
        char src[12],dst[12];
        dk_h8s_reg(src,sizeof(src),bits,lo>>4);
        dk_h8s_reg(dst,sizeof(dst),bits==8?16:32,lo&15);
        snprintf(out,cap,"%s.%c %s,%s",(op&1)?"DIVXU":"MULXU",
                 bits==8?'B':'W',src,dst);
        return 2;
    }
    /* H8S/2600 prefixed long logical register forms:
       01 F0 64/65/66 xy, where x and y select ER0..ER7.
       Reject reserved register-selector high bits; the length validator
       applies the same mask (third/fourth byte & FF88 == 6400 etc.). */
    if (w == 0x01f0 && n >= 4 &&
        (p[2] == 0x64 || p[2] == 0x65 || p[2] == 0x66) &&
        (p[3] & 0x88) == 0) {
        const char *name = p[2] == 0x64 ? "OR" :
                           p[2] == 0x65 ? "XOR" : "AND";
        snprintf(out, cap, "%s.L ER%u,ER%u", name,
                 (unsigned)(p[3] >> 4), (unsigned)(p[3] & 7));
        return 4;
    }
    /* Two-byte register ALU, moves and long-register operations. */
    {
        static const struct { unsigned int op; const char *name; unsigned int bits; } pairs[] = {
            {0x08,"ADD",8},{0x0c,"MOV",8},{0x0e,"ADDX",8},
            {0x14,"OR",8},{0x15,"XOR",8},{0x16,"AND",8},
            {0x18,"SUB",8},{0x1c,"CMP",8},{0x1e,"SUBX",8},
            {0x09,"ADD",16},{0x0d,"MOV",16},{0x19,"SUB",16},
            {0x1d,"CMP",16},{0x64,"OR",16},{0x65,"XOR",16},
            {0x66,"AND",16},{0x0a,"ADD",32},{0x0f,"MOV",32},
            {0x1a,"SUB",32},{0x1f,"CMP",32}
        };
        size_t j;
        for (j=0;j<sizeof(pairs)/sizeof(pairs[0]);j++) {
            if (op == pairs[j].op && (pairs[j].bits != 32 || (lo & 0x88) == 0x80)) {
                char a[12], b[12];
                dk_h8s_reg(a,sizeof(a),pairs[j].bits,lo >> 4);
                dk_h8s_reg(b,sizeof(b),pairs[j].bits,lo & 15);
                snprintf(out,cap,"%s.%c %s,%s",pairs[j].name,
                         pairs[j].bits==32?'L':pairs[j].bits==16?'W':'B',a,b);
                return 2;
            }
        }
    }
    if ((op == 0x0b || op == 0x1b) && (lo >> 4) <= 9 && (lo & 7) == (lo & 15)) {
        unsigned int top = lo >> 4;
        if (top == 0 || top == 8 || top == 9) {
            snprintf(out,cap,"%s #%u,ER%u",op==0x0b?"ADDS":"SUBS",
                     top==0?1:top==8?2:4,lo&7);
            return 2;
        }
    }
    /* Renesas H8S/2600 programming manual, INC.W/DEC.W opcode tables:
       0B/1B 5r = #1,Rd; 0B/1B Dr = #2,Rd.  Register nibble r
       spans R0..R7 (0..7) and E0..E7 (8..F). */
    if ((op == 0x0b || op == 0x1b) &&
        ((lo >> 4) == 5 || (lo >> 4) == 13)) {
        char reg[12];
        dk_h8s_reg(reg, sizeof(reg), 16, lo & 15);
        snprintf(out, cap, "%s.W #%u,%s", op == 0x0b ? "INC" : "DEC",
                 (lo >> 4) == 5 ? 1 : 2, reg);
        return 2;
    }
    /* Renesas H8S/2600 INC.L / DEC.L: 0B/1B 7r = #1,ERr;
       0B/1B Fr = #2,ERr, with r restricted to 0..7. */
    if ((op == 0x0b || op == 0x1b) &&
        ((lo >> 4) == 7 || (lo >> 4) == 15) && !(lo & 8)) {
        snprintf(out, cap, "%s.L #%u,ER%u", op == 0x0b ? "INC" : "DEC",
                 (lo >> 4) == 7 ? 1 : 2, lo & 7);
        return 2;
    }
    if (op == 0x0a || op == 0x1a) {
        if (lo < 16) {
            char r[12]; dk_h8s_reg(r,sizeof(r),8,lo);
            snprintf(out,cap,"%s.B %s",op==0x0a?"INC":"DEC",r);
            return 2;
        }
        if ((lo & 0xf0) == 0x80 && !(lo & 8)) {
            snprintf(out,cap,"%s.L #1,ER%u",op==0x0a?"INC":"DEC",lo&7);
            return 2;
        }
    }
    /* H8S 24/32-bit displacement: 78 xx 6A/6B yy dd dd dd dd.
       The displacement and data register are part of ONE 8-byte instruction.
       Previously the 78xx word was emitted separately, creating a false MOV. */
    if (op == 0x78 && n >= 8 && (lo & 0x8f) == 0 &&
        (p[2] == 0x6a || p[2] == 0x6b) && (p[3] & 0x70) == 0x20) {
        unsigned int bits = p[2] == 0x6a ? 8 : 16;
        unsigned int store = (p[3] & 0x80) != 0;
        uint32_t d = ((uint32_t)p[4] << 24) | ((uint32_t)p[5] << 16) |
                     ((uint32_t)p[6] << 8) | p[7];
        char r[12];
        dk_h8s_reg(r, sizeof(r), bits, p[3] & 15);
        if (store)
            snprintf(out, cap, "MOV.%c %s,@(H'%X:32,ER%u)",
                     bits==8?'B':'W', r, (unsigned int)d, (lo>>4)&7);
        else
            snprintf(out, cap, "MOV.%c @(H'%X:32,ER%u),%s",
                     bits==8?'B':'W', (unsigned int)d, (lo>>4)&7, r);
        return 8;
    }
    /* Register indirect control transfers. */
    if ((op == 0x59 || op == 0x5d) && !(lo & 0x8f)) {
        snprintf(out,cap,"%s @ER%u",op==0x59?"JMP":"JSR",(lo>>4)&7);
        return 2;
    }
    if ((op == 0x5b || op == 0x5f)) {
        snprintf(out,cap,"%s @@H'%X:8",op==0x5b?"JMP":"JSR",lo);
        return 2;
    }
    /* Byte register bit operations. Note: 0x72 is BCLR, NOT BSET. */
    if ((op >= 0x60 && op <= 0x63) || op == 0x67 ||
        (op >= 0x70 && op <= 0x77)) {
        const char *name=dk_h8s_bit_name(op,lo);
        if (name) {
            char r[12]; dk_h8s_reg(r,sizeof(r),8,lo&15);
            if (op >= 0x60 && op <= 0x63) {
                char src[12]; dk_h8s_reg(src,sizeof(src),8,lo>>4);
                snprintf(out,cap,"%s %s,%s",name,src,r);
            } else snprintf(out,cap,"%s #%u,%s",name,(lo>>4)&7,r);
            return 2;
        }
    }
    /* H8S byte absolute 8-bit moves: 0x20..0x3F, verified against legacy.rs. */
    if (op >= 0x20 && op <= 0x3f) {
        char r[12]; dk_h8s_reg(r,sizeof(r),8,op&15);
        if (op < 0x30) snprintf(out,cap,"MOV.B @H'%X:8,%s",lo,r);
        else snprintf(out,cap,"MOV.B %s,@H'%X:8",r,lo);
        return 2;
    }
    /* H8S shifts and rotates, verified semantic selection against legacy.rs.
       Restrict operand-size fields to known forms to avoid invented mnemonics. */
    if (op >= 0x10 && op <= 0x13) {
        static const char *logical[]={"SHLL","SHLR","ROTXL","ROTXR"};
        static const char *arithmetic[]={"SHAL","SHAR","ROTL","ROTR"};
        unsigned int field=(lo>>4)&3, bits=field==0?8:field==1?16:32;
        char r[12]; dk_h8s_reg(r,sizeof(r),bits,lo&15);
        snprintf(out,cap,"%s.%c #%u,%s",(lo&0x80?arithmetic:logical)[op-0x10],
                 bits==8?'B':bits==16?'W':'L',(lo&0x40)?2:1,r);
        return 2;
    }
    /* EXTU/EXTS/NOT/NEG (size encoded in bits 5:4). */
    if (op == 0x17) {
        static const char *names[]={"NOT","EXTU","NEG","EXTS"};
        unsigned int bits=((lo>>4)&3)==0?8:((lo>>4)&3)==1?16:32;
        char r[12]; dk_h8s_reg(r,sizeof(r),bits,lo&15);
        snprintf(out,cap,"%s.%c %s",names[lo>>6],bits==8?'B':bits==16?'W':'L',r);
        return 2;
    }
    /* INC/DEC with explicit #1/#2, as opposed to the byte form. */
    if ((op == 0x0a || op == 0x1a) && (lo & 8) == 0) {
        unsigned int top=lo>>4;
        if (top==0x5 || top==0x7 || top==0x9 || top==0xb) {
            unsigned int bits=(top==0x5 || top==0x9)?16:32;
            char r[12]; dk_h8s_reg(r,sizeof(r),bits,lo&15);
            snprintf(out,cap,"%s.%c #%u,%s",op==0x0a?"INC":"DEC",
                     bits==16?'W':'L',top>=8?2:1,r);
            return 2;
        }
    }
    /* 16-bit/32-bit register-indirect, pre-decrement and post-increment moves. */
    if (op >= 0x68 && op <= 0x6f && op != 0x6a && op != 0x6b) {
        unsigned int bits=(op&1)?16:8;
        unsigned int store=(lo&0x80)!=0;
        char r[12]; dk_h8s_reg(r,sizeof(r),bits,lo&15);
        if (op==0x68 || op==0x69 || op==0x6c || op==0x6d) {
            if (op==0x6c || op==0x6d) {
                if (store) snprintf(out,cap,"MOV.%c %s,@-ER%u",bits==8?'B':'W',r,(lo>>4)&7);
                else snprintf(out,cap,"MOV.%c @ER%u+,%s",bits==8?'B':'W',(lo>>4)&7,r);
            } else {
                if (store) snprintf(out,cap,"MOV.%c %s,@ER%u",bits==8?'B':'W',r,(lo>>4)&7);
                else snprintf(out,cap,"MOV.%c @ER%u,%s",bits==8?'B':'W',(lo>>4)&7,r);
            }
            return 2;
        }
        if ((op==0x6e || op==0x6f) && n>=4) {
            int disp=(int16_t)(((unsigned int)p[2]<<8)|p[3]);
            if (store) snprintf(out,cap,"MOV.%c %s,@(%d:16,ER%u)",bits==8?'B':'W',r,disp,(lo>>4)&7);
            else snprintf(out,cap,"MOV.%c @(%d:16,ER%u),%s",bits==8?'B':'W',disp,(lo>>4)&7,r);
            return 4;
        }
    }
    /* Additional fixed/control instructions. */
    if (w==0x01a0) { snprintf(out,cap,"CLRMAC"); return 2; }
    if (op>=4 && op<=7) { snprintf(out,cap,"%s%s #H'%X:8,CCR",
         op==4?"ORC":op==5?"XORC":op==6?"ANDC":"LDC",op==7?".B":"",lo); return 2; }
    /* Prefix 01 00 selects MOV.L memory forms. The 16-bit absolute
       form is six bytes total; indirect forms are four. */
    if (w == 0x0100 && n >= 4) {
        unsigned int h=p[2], l=p[3], store=l&0x80;
        if ((h == 0x69 || h == 0x6d) && !(l&8)) {
            if (h == 0x6d) {
                if (store) snprintf(out,cap,"MOV.L ER%u,@-ER%u",l&7,(l>>4)&7);
                else snprintf(out,cap,"MOV.L @ER%u+,ER%u",(l>>4)&7,l&7);
            } else {
                if (store) snprintf(out,cap,"MOV.L ER%u,@ER%u",l&7,(l>>4)&7);
                else snprintf(out,cap,"MOV.L @ER%u,ER%u",(l>>4)&7,l&7);
            }
            return 4;
        }
        /* Renesas H8S/2600 MOV.L @(d:16,ERn),ERm and reverse.
           01 00 6F xy dd dd: the 6F word is prefixed, not MOV.W. */
        if (h == 0x6f && !(l&8) && n >= 6) {
            int disp=(int16_t)(((unsigned int)p[4]<<8)|p[5]);
            if (store) snprintf(out,cap,"MOV.L ER%u,@(%d:16,ER%u)",l&7,disp,(l>>4)&7);
            else snprintf(out,cap,"MOV.L @(%d:16,ER%u),ER%u",disp,(l>>4)&7,l&7);
            return 6;
        }
        if (h == 0x6b && !(l&0x48)) {
            if (!(l&0x20) && n >= 6) {
                unsigned int a=((unsigned int)p[4]<<8)|p[5];
                if (store) snprintf(out,cap,"MOV.L ER%u,@H'%X:16",l&7,a);
                else snprintf(out,cap,"MOV.L @H'%X:16,ER%u",a,l&7);
                return 6;
            }
            if ((l&0x20) && n>=8) {
                uint32_t a=((uint32_t)p[4]<<24)|((uint32_t)p[5]<<16)|((uint32_t)p[6]<<8)|p[7];
                if (store) snprintf(out,cap,"MOV.L ER%u,@H'%X:32",l&7,(unsigned int)a);
                else snprintf(out,cap,"MOV.L @H'%X:32,ER%u",(unsigned int)a,l&7);
                return 8;
            }
        }
    }
    /* Renesas REJ09B0139-0400, instruction-format tables pp. 265-267:
     * 6A 10/18 = bit operation on absolute 16-bit byte address (6 bytes);
     * 6A 30/38 = bit operation on absolute 32-bit byte address (8 bytes).
     * The final word supplies the operation and bit/register operand.
     * Length is validated independently by dk_h8s2600_length(). */
    if (op==0x6a && (lo==0x10 || lo==0x18 || lo==0x30 || lo==0x38)) {
        size_t len=(lo&0x20)?8:6;
        if(n>=len) {
            unsigned int bop=p[len-2], arg=p[len-1];
            uint32_t addr=(lo&0x20)?
                ((uint32_t)p[2]<<24)|((uint32_t)p[3]<<16)|((uint32_t)p[4]<<8)|p[5]:
                ((uint32_t)p[2]<<8)|p[3];
            const char *name=dk_h8s_bit_name(bop,arg);
            if(name) {
                if(bop>=0x60 && bop<=0x63) {
                    char reg[12];dk_h8s_reg(reg,sizeof(reg),8,arg>>4);
                    snprintf(out,cap,"%s %s,@H'%X:%u",name,reg,(unsigned int)addr,(lo&0x20)?32:16);
                } else {
                    snprintf(out,cap,"%s #%u,@H'%X:%u",name,(arg>>4)&7,(unsigned int)addr,(lo&0x20)?32:16);
                }
                return len;
            }
        }
    }
    /* Absolute byte/word memory moves (16- or 32-bit address). */
    if ((op==0x6a || op==0x6b) && !(lo&0x40)) {
        unsigned int bits=op==0x6a?8:16;
        unsigned int store=lo&0x80;
        unsigned int address_bits=(lo&0x20)?32:16;
        size_t length=address_bits==32?6:4;
        if (n>=length) {
            uint32_t address=address_bits==32?
                ((uint32_t)p[2]<<24)|((uint32_t)p[3]<<16)|((uint32_t)p[4]<<8)|p[5]:
                ((uint32_t)p[2]<<8)|p[3];
            char r[12]; dk_h8s_reg(r,sizeof(r),bits,lo&15);
            if (store) snprintf(out,cap,"MOV.%c %s,@H'%X:%u",bits==8?'B':'W',r,(unsigned int)address,address_bits);
            else snprintf(out,cap,"MOV.%c @H'%X:%u,%s",bits==8?'B':'W',(unsigned int)address,address_bits,r);
            return length;
        }
    }
    /* H8S bit manipulation against @ERn; length four bytes. */
    if ((op == 0x7c || op == 0x7d) && n>=4 && !(lo&0x8f)) {
        unsigned int b=p[2], v=p[3];
        const char *name=dk_h8s_bit_name(b,v);
        if (name) {
            if (b>=0x60 && b<=0x63) {
                char r[12]; dk_h8s_reg(r,sizeof(r),8,v>>4);
                snprintf(out,cap,"%s %s,@ER%u",name,r,(lo>>4)&7);
            } else snprintf(out,cap,"%s #%u,@ER%u",name,(v>>4)&7,(lo>>4)&7);
            return 4;
        }
    }
    if (op == 0x79 && (lo>>4)<7 && n>=4) {
        static const char *names[]={"MOV","ADD","CMP","SUB","OR","XOR","AND"};
        unsigned int imm=((unsigned int)p[2]<<8)|p[3];
        { char r[12]; dk_h8s_reg(r,sizeof(r),16,lo&15);
          snprintf(out,cap,"%s.W #H'%X:16,%s",names[lo>>4],imm,r); }
        return 4;
    }
    if (op>=0x80 && op<=0xff) {
        static const char *names[]={"ADD","ADDX","CMP","SUBX","OR","XOR","AND","MOV"};
        char r[12]; dk_h8s_reg(r,sizeof(r),8,op&15);
        snprintf(out,cap,"%s.B #H'%X:8,%s",names[(op>>4)-8],lo,r);
        return 2;
    }
    if (w == 0x0000) { snprintf(out, cap, "NOP"); return 2; }
    if (w == 0x0180) { snprintf(out, cap, "SLEEP"); return 2; }
    if (w == 0x5470) { snprintf(out, cap, "RTS"); return 2; }
    if (w == 0x5670) { snprintf(out, cap, "RTE"); return 2; }
    if (op >= 0x40 && op <= 0x4f && !(lo & 1)) {
        int delta = (int)(int8_t)lo + 2;
        snprintf(out, cap, "%s $%+d:8", conds[op - 0x40], delta);
        return 2;
    }
    if (op == 0x55 && !(lo & 1)) {
        snprintf(out, cap, "BSR $%+d:8", (int)(int8_t)lo + 2);
        return 2;
    }
    if (op == 0x7a && lo < 0x70 && !(lo & 8) && n >= 6) {
        uint32_t imm = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16) |
                       ((uint32_t)p[4] << 8) | p[5];
        static const char *names[7] = {"MOV", "ADD", "CMP", "SUB", "OR", "XOR", "AND"};
        unsigned int kind = lo >> 4;
        if (kind < 7) {
            snprintf(out, cap, "%s.L #H'%X:32,ER%u", names[kind], (unsigned int)imm, lo & 7);
            return 6;
        }
    }
    if ((op == 0x5a || op == 0x5e) && n >= 4) {
        uint32_t a = ((uint32_t)lo << 16) | ((uint32_t)p[2] << 8) | p[3];
        snprintf(out, cap, "%s @H'%X:24", op == 0x5a ? "JMP" : "JSR", (unsigned int)a);
        return 4;
    }
    if ((op == 0x58 && !(lo & 15)) && n >= 4) {
        unsigned int d = ((unsigned int)p[2] << 8) | p[3];
        int delta = (int)(int16_t)d + 4;
        if (!(d & 1)) {
            snprintf(out, cap, "%s $%+d:16", conds[lo >> 4], delta);
            return 4;
        }
    }
    if (op == 0x5c && lo == 0 && n >= 4) {
        unsigned int d = ((unsigned int)p[2] << 8) | p[3];
        if (!(d & 1)) {
            snprintf(out, cap, "BSR $%+d:16", (int)(int16_t)d + 4);
            return 4;
        }
    }
    return 0;
}


/* Only length-validated encodings can reach the semantic decoder.
 * An instruction with known length but unknown meaning is emitted as an
 * explicit opaque instruction, never silently misdecoded as .WORD. */
static size_t dk_h8s_decode(const unsigned char *p,size_t n,char *out,size_t cap)
{
    size_t valid=dk_h8s2600_length(p,n);
    size_t got;
    if(!valid)return 0;
    got=dk_h8s_decode_semantic(p,valid,out,cap);
    if(got==valid)return got;
    snprintf(out,cap,".BYTE ; VALID ENCODING, SEMANTICS UNIMPLEMENTED (%lu bytes)",(unsigned long)valid);
    return valid;
}


/* The decoder formats relative displacements as $+(signed displacement +
 * instruction length). Do not parse rendered text to determine control flow:
 * classify the encoded opcode and sign-extend the raw displacement instead. */
static int dk_h8s_flow(const unsigned char *p,size_t n,uint32_t base,size_t at,
                       int *has_target,uint64_t *target,int *fallthrough)
{
    unsigned op=p[0],lo=p[1];
    int64_t disp=0;
    *has_target=0;*target=0;*fallthrough=1;
    if (op>=0x40 && op<=0x4f && n==2 && !(lo&1)) {
        disp=(int8_t)lo;*has_target=1;
        if(op==0x40) *fallthrough=0; /* BRA */
        if(op==0x41) *has_target=0; /* BRN: never taken */
    } else if(op==0x55 && n==2 && !(lo&1)) {
        disp=(int8_t)lo;*has_target=1; /* BSR: also returns */
    } else if(op==0x58 && n==4 && !(lo&15) && !(p[3]&1)) {
        disp=(int16_t)(((unsigned)p[2]<<8)|p[3]);*has_target=1;
        if((lo>>4)==0) *fallthrough=0;
        if((lo>>4)==1) *has_target=0;
    } else if(op==0x5c && n==4 && lo==0 && !(p[3]&1)) {
        disp=(int16_t)(((unsigned)p[2]<<8)|p[3]);*has_target=1;
    } else if((op==0x5a || op==0x5e) && n==4) {
        *has_target=1;
        *target=((uint64_t)lo<<16)|((uint64_t)p[2]<<8)|p[3];
        if(op==0x5a)*fallthrough=0;
        return 1;
    } else if(op==0x59 || op==0x5d) {
        if(op==0x59)*fallthrough=0; /* indirect JMP */
    } else if((op==0x54 || op==0x56) && lo==0x70) {
        *fallthrough=0; /* RTS/RTE */
    } else if(op==0x01 && lo==0x80) {
        *fallthrough=0; /* SLEEP */
    }
    if(*has_target) {
        int64_t a=(int64_t)(uint64_t)base+(int64_t)at+(int64_t)n+disp;
        if(a>=0)*target=(uint64_t)a;
        else *has_target=0;
    }
    return 1;
}

/* mark: 0 unvisited, 1 instruction start, 2 instruction continuation,
 * 3 directly referenced candidate data, 4 reached but unrecognized start.
 * Reached unknowns are deliberately NOT silently relabeled unvisited. */
static int dk_h8s_reachable(const unsigned char *b,size_t len,uint32_t base,
                            unsigned char *mark,size_t *decoded,
                            size_t *reachable_unknown,size_t *outside_targets,
                            size_t *conflict_targets)
{
    size_t *queue=(size_t*)malloc((len+1)*sizeof(size_t));
    unsigned char *seen=(unsigned char*)calloc(len,1);
    size_t head=0,tail=0;
    if(!queue || !seen){free(queue);free(seen);return 0;}
    queue[tail++]=0;seen[0]=1;
    while(head<tail) {
        size_t at=queue[head++],n,i;
        char op[128];
        int has_target,fallthrough;
        uint64_t dest;
        if(at+1>=len){if(mark[at]==0)mark[at]=4;(*reachable_unknown)++;continue;}
        if(mark[at]==1)continue;
        if(mark[at]==2){(*conflict_targets)++;continue;}
        if(b[at]==0xff && b[at+1]==0xff){mark[at]=4;(*reachable_unknown)++;continue;}
        n=dk_h8s_decode(b+at,len-at,op,sizeof(op));
        if(!n || n>len-at){mark[at]=4;(*reachable_unknown)++;continue;}
        for(i=0;i<n;i++)if(mark[at+i]==1 || mark[at+i]==2 || mark[at+i]==4)break;
        if(i<n){(*conflict_targets)++;continue;}
        if(strstr(op,"SEMANTICS UNIMPLEMENTED")){mark[at]=4;(*reachable_unknown)++;continue;}
        mark[at]=1;for(i=1;i<n;i++)mark[at+i]=2;
        ++*decoded;
        {
            const char *mem=strstr(op,"@H'");
            if(mem && strncmp(op,"JMP ",4) && strncmp(op,"JSR ",4)) {
                char *e;unsigned long v=strtoul(mem+3,&e,16);
                if(e!=mem+3 && *e==':' && (uint64_t)v>=base &&
                   (uint64_t)v-(uint64_t)base<len) {
                    size_t off=(size_t)((uint64_t)v-base);
                    if(mark[off]==0)mark[off]=3;
                }
            }
        }
        dk_h8s_flow(b+at,n,base,at,&has_target,&dest,&fallthrough);
        if(has_target) {
            if(dest>=base && dest-(uint64_t)base<len) {
                size_t off=(size_t)(dest-base);
                if(!seen[off]){seen[off]=1;queue[tail++]=off;}
            } else (*outside_targets)++;
        }
        if(fallthrough && at+n<len && !seen[at+n]) {
            seen[at+n]=1;queue[tail++]=at+n;
        }
    }
    free(queue);free(seen);return 1;
}

static const char *dk_h8s_mark_name(unsigned v)
{
    switch(v){case 0:return "UNVISITED";case 1:return "CODE";
    case 2:return "INSTRUCTION_INTERIOR";case 3:return "REFERENCED_CANDIDATE";
    case 4:return "REACHED_UNKNOWN";default:return "INVALID_STATUS";}
}

/* Stage 9.1: deliberately narrow proof: an immediately preceding reached
 * MOV.L #imm32,ERn establishes the target for JSR/JMP @ERn. No instruction,
 * branch, or call may intervene; no ABI register-preservation assumptions. */
static int dk_h8s_adjacent_constant(const unsigned char *b,const unsigned char *mark,
                                     size_t len,size_t at,unsigned reg,uint32_t *value)
{
    size_t prev;
    if(at<6 || at>=len || reg>7)return 0;
    prev=at-6;
    if(mark[prev]!=1 || b[prev]!=0x7a || b[prev+1]!=(unsigned char)reg)return 0;
    if(dk_h8s2600_length(b+prev,len-prev)!=6)return 0;
    *value=((uint32_t)b[prev+2]<<24)|((uint32_t)b[prev+3]<<16)|
           ((uint32_t)b[prev+4]<<8)|b[prev+5];
    return 1;
}

/* Stage 9: conservative cross-reference inventory. Only instructions that have
 * already passed the length validator AND reachability classifier contribute.
 * No guessed vector entries, no fabricated indirect targets. */
static int dk_h8s_write_xrefs(const char *path,const unsigned char *buf,
                              const unsigned char *mark,size_t len,uint32_t base)
{
    FILE *f;size_t pos,direct=0,calls=0,jumps=0,branches=0,indirect=0,resolved=0;
    unsigned char *entry=(unsigned char*)calloc(len,1);
    if(!entry)return 0;
    if(len && mark[0]==1)entry[0]=1;
    f=fopen(path,"w");if(!f){free(entry);return 0;}
    fprintf(f,"; DriveKit Stage 9.3 - conservative H8S/2600 cross-reference inventory\n");
    fprintf(f,"; Only reached, length-validated instruction starts are analyzed.\n");
    fprintf(f,"; Indirect target proof requires adjacent MOV.L #imm32,ERn; others remain UNKNOWN.\n");
    fprintf(f,"; Base: 0x%08X; image size: 0x%lX\n\n",(unsigned)base,(unsigned long)len);
    fprintf(f,"; DIRECT CONTROL-FLOW REFERENCES\n");
    for(pos=0;pos<len;pos++)if(mark[pos]==1){
        char optext[128];size_t n=dk_h8s_decode(buf+pos,len-pos,optext,sizeof(optext));
        int has,fall;uint64_t dest;unsigned op=buf[pos];
        const char *kind;
        if(!n)continue;
        dk_h8s_flow(buf+pos,n,base,pos,&has,&dest,&fall);
        if(!has)continue;
        kind=(op==0x55 || op==0x5c || op==0x5e)?"CALL":
             (op==0x40 || op==0x5a || (op==0x58 && (buf[pos+1]>>4)==0))?"JUMP":"BRANCH";
        fprintf(f,"0x%08X -> 0x%08llX  %-6s  %s\n",(unsigned)(base+(uint32_t)pos),
                (unsigned long long)dest,kind,
                (dest>=base && dest-(uint64_t)base<len)?
                dk_h8s_mark_name(mark[(size_t)(dest-base)]):"OUTSIDE_IMAGE");
        direct++;
        if(kind[0]=='C'){
            calls++;
            if(dest>=base && dest-(uint64_t)base<len && mark[(size_t)(dest-base)]==1)
                entry[(size_t)(dest-base)]=1;
        }else if(kind[0]=='J')jumps++;else branches++;
    }
    fprintf(f,"\n; INDIRECT CONTROL-FLOW SITES (adjacent-constant proofs or unknown)\n");
    for(pos=0;pos<len;pos++)if(mark[pos]==1){
        unsigned op=buf[pos];char optext[128];size_t n;
        if(op!=0x59 && op!=0x5d)continue;
        n=dk_h8s_decode(buf+pos,len-pos,optext,sizeof(optext));
        if(!n)continue;
        {
            unsigned reg=(buf[pos+1]>>4)&7;
            uint32_t value=0;
            int proved=(n==2 && (buf[pos+1]&0x0f)==0 &&
                        dk_h8s_adjacent_constant(buf,mark,len,pos,reg,&value));
            if(proved){
                const char *status=((uint64_t)value>=base &&
                    (uint64_t)value-base<len)?
                    dk_h8s_mark_name(mark[(size_t)((uint64_t)value-base)]):"OUTSIDE_IMAGE";
                fprintf(f,"0x%08X  %s  -> 0x%08X  ADJACENT_CONSTANT  %s\n",
                        (unsigned)(base+(uint32_t)pos),optext,(unsigned)value,status);
                resolved++;
            }else fprintf(f,"0x%08X  %s  TARGET_UNKNOWN\n",
                           (unsigned)(base+(uint32_t)pos),optext);
        }
        indirect++;
    }
    fprintf(f,"\n; FUNCTION ENTRY CANDIDATES (image entry + reached direct CALL targets)\n");
    {
        size_t entries=0;
        for(pos=0;pos<len;pos++)if(entry[pos]){
            fprintf(f,"0x%08X  %s\n",(unsigned)(base+(uint32_t)pos),pos==0?"IMAGE_ENTRY":"DIRECT_CALL_TARGET");
            entries++;
        }
        fprintf(f,"\n; SUMMARY: %lu direct edges (%lu calls, %lu jumps, %lu branches)\n",
                (unsigned long)direct,(unsigned long)calls,(unsigned long)jumps,(unsigned long)branches);
        fprintf(f,"; SUMMARY: %lu indirect sites (%lu adjacent-constant resolved, %lu unknown); %lu direct entry candidates\n",
                (unsigned long)indirect,(unsigned long)resolved,
                (unsigned long)(indirect-resolved),(unsigned long)entries);
    }
    fprintf(f,"; LIMITATIONS: adjacent-only constant proof; no interprocedural propagation,\n");
    fprintf(f,"; pointer-table or interrupt-vector discovery; indirect seeds only when explicitly promoted.\n");
    fprintf(f,"; Function candidates are not proven function boundaries.\n");
    free(entry);
    if(fclose(f)){return 0;}
    return 1;
}

/* Stage 9.2: independent, read-only exploratory traversal from strictly proven
 * adjacent-constant indirect call targets. Never mutate the baseline mark map.
 * Candidate instruction boundaries are checked against BOTH baseline and other
 * discovery candidates. No speculative continuation through unknown encodings. */
static int dk_h8s_write_discovery(const char *path,const unsigned char *b,
                                  const unsigned char *mark,size_t len,uint32_t base)
{
    FILE *f;size_t pos,seed_count=0,accepted=0,unknown=0,conflicts=0,exits=0;
    unsigned char *candidate=(unsigned char*)calloc(len,1);
    unsigned char *seen=(unsigned char*)calloc(len,1);
    size_t *queue=(size_t*)malloc((len+1)*sizeof(size_t));
    size_t head=0,tail=0;
    if(!candidate || !seen || !queue){free(candidate);free(seen);free(queue);return 0;}
    f=fopen(path,"w");if(!f){free(candidate);free(seen);free(queue);return 0;}
    fprintf(f,"; DriveKit Stage 9.2 - read-only indirect-target discovery\n");
    fprintf(f,"; Seeds: reached adjacent MOV.L #imm32,ERn + JSR/JMP @ERn ONLY\n");
    fprintf(f,"; No baseline reclassification; candidates are NOT proven functions.\n");
    fprintf(f,"; Base: 0x%08X; image size: 0x%lX\n\n",(unsigned)base,(unsigned long)len);
    fprintf(f,"; SEEDS\n");
    for(pos=0;pos<len;pos++)if(mark[pos]==1 && (b[pos]==0x5d || b[pos]==0x59)){
        uint32_t target;unsigned reg=(b[pos+1]>>4)&7;
        if((b[pos+1]&15) || !dk_h8s_adjacent_constant(b,mark,len,pos,reg,&target))continue;
        if((uint64_t)target<base || (uint64_t)target-base>=len){
            fprintf(f,"0x%08X -> 0x%08X  OUTSIDE_IMAGE\n",(unsigned)(base+(uint32_t)pos),(unsigned)target);continue;
        }
        {
            size_t off=(size_t)((uint64_t)target-base);
            fprintf(f,"0x%08X -> 0x%08X  %s\n",(unsigned)(base+(uint32_t)pos),(unsigned)target,dk_h8s_mark_name(mark[off]));
            if(mark[off]==0 || mark[off]==3){
                seed_count++;
                if(!seen[off]){seen[off]=1;queue[tail++]=off;}
            }
        }
    }
    fprintf(f,"\n; DISCOVERED INSTRUCTIONS (read-only, unvisited baseline bytes)\n");
    while(head<tail){
        size_t at=queue[head++],n,i;char optext[128];int has,fall;uint64_t dest;
        if(mark[at]==1){fprintf(f,"0x%08X  JOIN_EXISTING_CODE\n",(unsigned)(base+(uint32_t)at));continue;}
        if(mark[at]==2 || candidate[at]==2 || candidate[at]==1 || candidate[at]==4){
            if(mark[at]==2 || candidate[at]==2){conflicts++;fprintf(f,"0x%08X  OVERLAP_START\n",(unsigned)(base+(uint32_t)at));}
            continue;
        }
        if(at+1>=len || (b[at]==0xff && b[at+1]==0xff) ||
           !(n=dk_h8s_decode(b+at,len-at,optext,sizeof(optext))) ||
           n>len-at || strstr(optext,"SEMANTICS UNIMPLEMENTED")){
            unknown++;candidate[at]=4;
            fprintf(f,"0x%08X  STOP_UNKNOWN  %02X\n",(unsigned)(base+(uint32_t)at),b[at]);continue;
        }
        for(i=0;i<n;i++)if(mark[at+i]==1 || mark[at+i]==2 || mark[at+i]==4 ||
                             candidate[at+i]==1 || candidate[at+i]==2 || candidate[at+i]==4)break;
        if(i<n){conflicts++;fprintf(f,"0x%08X  STOP_OVERLAP  +%lu\n",(unsigned)(base+(uint32_t)at),(unsigned long)i);continue;}
        candidate[at]=1;for(i=1;i<n;i++)candidate[at+i]=2;
        accepted++;
        fprintf(f,"0x%08X  %-40s  LEN %lu\n",(unsigned)(base+(uint32_t)at),optext,(unsigned long)n);
        dk_h8s_flow(b+at,n,base,at,&has,&dest,&fall);
        if(has){
            if(dest>=base && dest-(uint64_t)base<len){
                size_t off=(size_t)(dest-base);
                if(!seen[off]){seen[off]=1;queue[tail++]=off;}
            }else{exits++;fprintf(f,"  -> 0x%08llX OUTSIDE_IMAGE\n",(unsigned long long)dest);}
        }
        if(fall && at+n<len && !seen[at+n]){seen[at+n]=1;queue[tail++]=at+n;}
    }
    fprintf(f,"\n; SUMMARY: %lu unvisited indirect seeds; %lu candidate instructions; %lu stopped unknown; %lu overlap conflicts; %lu outside-image edges\n",
            (unsigned long)seed_count,(unsigned long)accepted,(unsigned long)unknown,(unsigned long)conflicts,(unsigned long)exits);
    fprintf(f,"; BASELINE UNCHANGED: no newly discovered bytes promoted to reachable code.\n");
    free(candidate);free(seen);free(queue);
    return fclose(f)==0;
}

/* Stage 9.3 opt-in promotion: independently traverse constant-proven seeds.
 * ALL-OR-NOTHING: reject promotion if ANY reached new path is undecodable,
 * overlaps an existing instruction, or leaves the image. The baseline remains
 * untouched on failure. No guesses about unresolved indirect transfers. */
static int dk_h8s_promote_indirect(const unsigned char *b,unsigned char *mark,
                                  size_t len,uint32_t base,size_t *added,
                                  size_t *seed_count)
{
    unsigned char *candidate=(unsigned char*)calloc(len,1);
    unsigned char *seen=(unsigned char*)calloc(len,1);
    size_t *queue=(size_t*)malloc((len+1)*sizeof(size_t));
    size_t head=0,tail=0,pos,added_local=0,seeds=0;
    int ok=1;
    if(!candidate || !seen || !queue){ok=0;goto finish;}
    for(pos=0;pos<len;pos++)if(mark[pos]==1 && pos+1<len &&
                                  (b[pos]==0x5d || b[pos]==0x59)){
        unsigned reg=(b[pos+1]>>4)&7;uint32_t target;
        if((b[pos+1]&15) || !dk_h8s_adjacent_constant(b,mark,len,pos,reg,&target))continue;
        if((uint64_t)target<base || (uint64_t)target-base>=len)continue;
        {
            size_t off=(size_t)((uint64_t)target-base);
            if(mark[off]!=0 && mark[off]!=3)continue;
            seeds++;
            if(!seen[off]){seen[off]=1;queue[tail++]=off;}
        }
    }
    while(head<tail){
        size_t at=queue[head++],n,i;char optext[128];int has,fall;uint64_t dest;
        if(mark[at]==1 || candidate[at]==1)continue;
        if(mark[at]==2 || mark[at]==4 || candidate[at]){ok=0;break;}
        if(at+1>=len || (b[at]==0xff && b[at+1]==0xff) ||
           !(n=dk_h8s_decode(b+at,len-at,optext,sizeof(optext))) ||
           n>len-at || strstr(optext,"SEMANTICS UNIMPLEMENTED")){ok=0;break;}
        for(i=0;i<n;i++)if(mark[at+i]==1 || mark[at+i]==2 || mark[at+i]==4 ||
                             candidate[at+i])break;
        if(i<n){ok=0;break;}
        candidate[at]=1;for(i=1;i<n;i++)candidate[at+i]=2;
        added_local++;
        dk_h8s_flow(b+at,n,base,at,&has,&dest,&fall);
        if(has){
            if(dest<base || dest-(uint64_t)base>=len){ok=0;break;}
            {
                size_t off=(size_t)(dest-base);
                if(!seen[off]){seen[off]=1;queue[tail++]=off;}
            }
        }
        if(fall){
            if(at+n>=len){ok=0;break;}
            if(!seen[at+n]){seen[at+n]=1;queue[tail++]=at+n;}
        }
    }
    if(ok){
        for(pos=0;pos<len;pos++)if(candidate[pos]==1 || candidate[pos]==2)
            mark[pos]=candidate[pos];
        *added=added_local;*seed_count=seeds;
    }
finish:
    free(candidate);free(seen);free(queue);return ok;
}


/* Stage 9.4: read-only register provenance audit. A prior immediate load is
 * evidence of origin, NOT proof across intervening instructions/calls.
 * Only a contiguous, reached instruction chain is inspected. */
static int dk_h8s_write_register_audit(const char *path,const unsigned char *b,
                                      const unsigned char *mark,size_t len,uint32_t base)
{
    FILE *f=fopen(path,"w");size_t pos,sites=0,adjacent=0,blocked=0,no_origin=0;
    if(!f)return 0;
    fprintf(f,"; DriveKit Stage 9.4 - read-only register provenance audit\n");
    fprintf(f,"; Nonadjacent loads are NOT resolved targets; no ABI assumptions.\n");
    fprintf(f,"; Every intervening call, branch, indirect transfer or unmodeled write blocks proof.\n\n");
    for(pos=0;pos+1<len;pos++)if(mark[pos]==1 && (b[pos]==0x5d || b[pos]==0x59) &&
                                 !(b[pos+1]&15)){
        unsigned reg=(b[pos+1]>>4)&7;uint32_t val=0;
        size_t at=pos,steps=0,calls=0,branches=0,other=0,origin=0;
        int found=0;
        if(dk_h8s2600_length(b+pos,len-pos)!=2)continue;
        sites++;
        if(dk_h8s_adjacent_constant(b,mark,len,pos,reg,&val)){
            adjacent++;
            fprintf(f,"0x%08X  ER%u  PROVEN_ADJACENT -> 0x%08X\n",
                    (unsigned)(base+(uint32_t)pos),reg,(unsigned)val);
            continue;
        }
        /* Walk backwards by locating a unique reached predecessor ending at
         * the current instruction. Any ambiguity terminates the audit. */
        while(at>0 && steps<128 && pos-at<512){
            size_t lo=at>8?at-8:0,prev=0,k,matches=0,n;
            for(k=lo;k<at;k++)if(mark[k]==1){
                n=dk_h8s2600_length(b+k,len-k);
                if(n && k+n==at){prev=k;matches++;}
            }
            if(matches!=1)break;
            at=prev;steps++;
            n=dk_h8s2600_length(b+at,len-at);
            if(n==6 && b[at]==0x7a && b[at+1]==reg){
                val=((uint32_t)b[at+2]<<24)|((uint32_t)b[at+3]<<16)|
                    ((uint32_t)b[at+4]<<8)|b[at+5];
                origin=at;found=1;break;
            }
            if(b[at]==0x5d || b[at]==0x5e || b[at]==0x55 || b[at]==0x5c)calls++;
            else if(b[at]==0x59 || b[at]==0x5a || b[at]==0x40 ||
                    (b[at]>=0x41 && b[at]<=0x4f) || b[at]==0x58)branches++;
            else other++;
        }
        if(found){
            blocked++;
            fprintf(f,"0x%08X  ER%u  PRIOR_LOAD 0x%08X at 0x%08X  NOT_PROVEN  intervening: %lu calls, %lu branches/jumps, %lu other instructions\n",
                    (unsigned)(base+(uint32_t)pos),reg,(unsigned)val,
                    (unsigned)(base+(uint32_t)origin),(unsigned long)calls,
                    (unsigned long)branches,(unsigned long)other);
        }else{
            no_origin++;
            fprintf(f,"0x%08X  ER%u  NO_CONTIGUOUS_IMMEDIATE_ORIGIN  TARGET_UNKNOWN\n",
                    (unsigned)(base+(uint32_t)pos),reg);
        }
    }
    fprintf(f,"\n; SUMMARY: %lu sites, %lu proven adjacent, %lu prior loads NOT proven, %lu no contiguous origin\n",
            (unsigned long)sites,(unsigned long)adjacent,(unsigned long)blocked,(unsigned long)no_origin);
    fprintf(f,"; No new reachability seeds or xref resolutions introduced.\n");
    return fclose(f)==0;
}

/* Stage 9.5: bounded, read-only CFG proof audit. Explore all forward paths
 * from each prior constant load to the indirect call. Unknown instructions,
 * calls, backedges and register writes invalidate the proof. This deliberately
 * proves only an immutable full-width ERn constant; no ABI assumptions. */
static int dk_h8s_cfg_constant_path(const unsigned char *b,const unsigned char *mark,
                                   size_t len,uint32_t base,size_t start,size_t goal,
                                   unsigned reg,uint32_t *value,unsigned *reason)
{
    unsigned char *seen=(unsigned char*)calloc(len,1);
    size_t *q=(size_t*)malloc((len+1)*sizeof(size_t));
    size_t head=0,tail=0;int good=1,arrived=0;
    if(!seen || !q){free(seen);free(q);*reason=8;return 0;}
    if(start>=goal || goal>=len){good=0;*reason=8;goto done;}
    q[tail++]=start;seen[start]=1;
    while(head<tail && good){
        size_t at=q[head++],n;int has,fall;uint64_t dest;
        if(at==goal){arrived=1;continue;}
        if(at>goal || mark[at]!=1){*reason=4;good=0;break;}
        n=dk_h8s2600_length(b+at,len-at);
        if(!n || at+n>goal){*reason=4;good=0;break;}
        /* Only explicitly modeled read-only instructions may preserve ERn.
         * Comparisons and conditional branches do not write general registers.
         * Every other instruction is a conservative barrier. */
        if((b[at]>=0x41 && b[at]<=0x4f) || b[at]==0x40 || b[at]==0x58 ||
           b[at]==0x5a){
            dk_h8s_flow(b+at,n,base,at,&has,&dest,&fall);
            if(has){
                size_t off;
                if(dest<base || dest-(uint64_t)base>=len){*reason=4;good=0;break;}
                off=(size_t)(dest-base);
                if(off<=at || off>goal){*reason=2;good=0;break;}
                if(!seen[off]){seen[off]=1;q[tail++]=off;}
            }
            if(fall && !seen[at+n]){seen[at+n]=1;q[tail++]=at+n;}
        }else if(b[at]==0x1c || b[at]==0x1d || b[at]==0x1f ||
                 (b[at]==0x7a && (b[at+1]&0xf0)==0x20) ||
                 (b[at]==0x0f && b[at+1]==(unsigned char)(0x80+reg*0x11))){
            /* Comparison, or MOV.L ERn,ERn identity (not a write to a new value). */
            if(!seen[at+n]){seen[at+n]=1;q[tail++]=at+n;}
        }else{
            *reason=(b[at]==0x5d || b[at]==0x5e || b[at]==0x55 || b[at]==0x5c)?3:1;
            good=0;
        }
    }
    if(!arrived && good){*reason=4;good=0;}
    if(good)*reason=0;
done:
    free(seen);free(q);(void)value;return good;
}

/* The CFG audit does not claim full register tracking: it first finds the
 * nearest prior immediate origin and then tests every traversed path. */
static int dk_h8s_write_cfg_audit(const char *path,const unsigned char *b,
                                  const unsigned char *mark,size_t len,uint32_t base)
{
    FILE *f=fopen(path,"w");size_t pos,sites=0,proved=0,blocked=0,none=0;
    if(!f)return 0;
    fprintf(f,"; DriveKit Stage 9.5 - conservative bounded CFG register audit\n");
    fprintf(f,"; Only proven adjacent targets are resolved in xrefs; CFG audit is diagnostic.\n");
    fprintf(f,"; Barriers: unmodeled writes, calls, backward/out-of-window edges, unknowns.\n\n");
    for(pos=0;pos+1<len;pos++)if(mark[pos]==1 && (b[pos]==0x5d || b[pos]==0x59) &&
       !(b[pos+1]&15) && dk_h8s2600_length(b+pos,len-pos)==2){
        unsigned reg=(b[pos+1]>>4)&7,reason=0;uint32_t value=0;
        size_t k,origin=(size_t)-1,low=pos>512?pos-512:0;
        sites++;
        if(dk_h8s_adjacent_constant(b,mark,len,pos,reg,&value)){
            proved++;fprintf(f,"0x%08X ER%u PROVEN_ADJACENT 0x%08X\n",(unsigned)(base+pos),reg,(unsigned)value);continue;
        }
        for(k=pos;k>low;){
            k--;
            if(mark[k]==1 && k+6<=pos && b[k]==0x7a && b[k+1]==reg &&
               dk_h8s2600_length(b+k,len-k)==6){origin=k;break;}
        }
        if(origin==(size_t)-1){none++;fprintf(f,"0x%08X ER%u NO_ORIGIN UNKNOWN\n",(unsigned)(base+pos),reg);continue;}
        value=((uint32_t)b[origin+2]<<24)|((uint32_t)b[origin+3]<<16)|
              ((uint32_t)b[origin+4]<<8)|b[origin+5];
        /* The load itself is already proven; start immediately afterward. */
        if(dk_h8s_cfg_constant_path(b,mark,len,base,origin+6,pos,reg,&value,&reason)){
            /* Diagnostic only: no xref or reachability mutation. */
            proved++;fprintf(f,"0x%08X ER%u CFG_PRESERVED_CANDIDATE 0x%08X origin 0x%08X (read-only)\n",
                (unsigned)(base+pos),reg,(unsigned)value,(unsigned)(base+origin));
        }else{
            const char *why=reason==1?"UNMODELED_WRITE_OR_INSTRUCTION":reason==2?"BACKEDGE_OR_WINDOW_EXIT":
                reason==3?"INTERVENING_CALL":"UNKNOWN_OR_UNREACHED_PATH";
            blocked++;fprintf(f,"0x%08X ER%u NOT_PROVEN prior 0x%08X origin 0x%08X reason %s\n",
                (unsigned)(base+pos),reg,(unsigned)value,(unsigned)(base+origin),why);
        }
    }
    fprintf(f,"\n; SUMMARY: %lu sites, %lu adjacent/CFG candidates, %lu blocked, %lu no origin\n",
       (unsigned long)sites,(unsigned long)proved,(unsigned long)blocked,(unsigned long)none);
    fprintf(f,"; NO NEW XREF RESOLUTIONS OR REACHABILITY SEEDS.\n");
    return fclose(f)==0;
}

/* Stage 9.6: fail-closed, read-only ER3 callee proof investigation.
 * A callee is not proven preserving ER3 merely because its own instructions
 * lack ER3 writes: every nested call and exit must also be accounted for.
 * Report concrete evidence, not speculative targets. */
static int dk_h8s_write_callee_audit(const char *path,const unsigned char *b,
                                     const unsigned char *mark,size_t len,uint32_t base)
{
    FILE *f=fopen(path,"w");
    const uint32_t entry[2]={0x405e02u,0x4069a0u};
    unsigned i;
    if(!f)return 0;
    fprintf(f,"; DriveKit Stage 9.6 - ER3 interprocedural preservation investigation\n");
    fprintf(f,"; Fail closed: unknown effects and out-of-image calls prevent proof.\n");
    fprintf(f,"; This report is diagnostic; xrefs and reachability are unchanged.\n\n");
    for(i=0;i<2;i++){
        size_t at,steps=0;int blocked=0,returns=0;
        if(entry[i]<base || (uint64_t)entry[i]-base>=len){
            fprintf(f,"0x%08X NOT_PROVEN ENTRY_OUTSIDE_IMAGE\n",(unsigned)entry[i]);continue;
        }
        at=(size_t)(entry[i]-base);
        fprintf(f,"0x%08X ER3 preservation evidence:\n",(unsigned)entry[i]);
        while(at<len && steps++<128 && mark[at]==1){
            size_t n=dk_h8s2600_length(b+at,len-at);
            char op[128];
            if(!n){blocked=1;fprintf(f,"  0x%08X UNKNOWN_ENCODING\n",(unsigned)(base+at));break;}
            dk_h8s_decode(b+at,len-at,op,sizeof(op));
            if((b[at]==0x5e && n==4) || (b[at]==0x5d && n==2) ||
               (b[at]==0x55) || (b[at]==0x5c)){
                uint32_t target=0;
                if(b[at]==0x5e && n==4)target=((uint32_t)b[at+1]<<16)|((uint32_t)b[at+2]<<8)|b[at+3];
                fprintf(f,"  0x%08X NESTED_CALL %s",(unsigned)(base+at),op);
                if(target){
                    fprintf(f," target=0x%08X %s",(unsigned)target,
                       target<base || (uint64_t)target-base>=len?"OUTSIDE_IMAGE_UNMODELED":"CALLEE_NOT_PROVEN");
                }
                fprintf(f,"\n");blocked=1;
            }
            /* A branch makes linear scanning insufficient for a whole-function proof. */
            if((b[at]>=0x40 && b[at]<=0x4f) || b[at]==0x58 || b[at]==0x5a || b[at]==0x59){
                fprintf(f,"  0x%08X CONTROL_FLOW_SPLIT_OR_TRANSFER %s\n",(unsigned)(base+at),op);
                blocked=1;
            }
            /* Full and partial writes to ER3 are proof barriers unless explicitly
             * modeled as save/restore; do not claim they are absent globally. */
            if((b[at]==0x0f && (b[at+1]&15)==3) ||
               (b[at]==0x7a && (b[at+1]&15)==3)){
                fprintf(f,"  0x%08X POSSIBLE_ER3_WRITE %s\n",(unsigned)(base+at),op);
                blocked=1;
            }
            if(n==2 && b[at]==0x54 && b[at+1]==0x70){returns++;break;}
            at+=n;
        }
        if(!returns){blocked=1;fprintf(f,"  EXIT_NOT_FULLY_ENUMERATED\n");}
        fprintf(f,"  RESULT %s%s\n\n",blocked?"NOT_PROVEN":"NOT_PROVEN",
                blocked?" (unresolved effects/paths)":" (linear scan alone is insufficient)");
    }
    fprintf(f,"CHAIN 0x00400126 MOV.L #0x00405E02,ER3\n");
    fprintf(f,"CHAIN 0x0040012C JSR @ER3 is PROVEN_ADJACENT\n");
    fprintf(f,"CHAIN 0x00400140,0x00400166,0x0040018C remain NOT_PROVEN\n");
    fprintf(f,"CONCLUSION: nested 0x004069B6 call to 0x001058DC is outside the 0x00400000 kernel window.\n");
    fprintf(f,"No ER3 preservation claim can be made without that callee's code or a justified contract.\n");
    fprintf(f,"NO NEW XREF RESOLUTIONS OR REACHABILITY SEEDS.\n");
    return fclose(f)==0;
}

/* Stage 9.7: read-only external dump evidence; mapping remains a hypothesis. */
static int dk_h8s_write_b0_er3_audit(const char *dump,const char *report)
{
    static const unsigned char entry[]={0x01,0x30,0x6d,0xf0,0x6d,0xf4};
    static const unsigned char exitseq[]={0x6d,0x74,0x01,0x30,0x6d,0x73,0x54,0x70};
    static const unsigned char call[]={0x5e,0x10,0x58,0xdc};
    static const unsigned char marker[]="AzHI2000/3";
    FILE *in=NULL,*out=NULL;
    unsigned char *b=NULL;
    long sz;size_t len,i,refs=0,lowrefs=0;
    int marker_low=0,marker_high=0,entry_ok=0,exit_ok=0,high_zero=0,rc=0;
    if(!dump || !report || !strcmp(dump,report))return 0;
    in=fopen(dump,"rb");if(!in)return 0;
    if(fseek(in,0,SEEK_END) || (sz=ftell(in))<0 || fseek(in,0,SEEK_SET))goto done;
    len=(size_t)sz;
    if(len<0x105944u || len>64u*1024u*1024u)goto done;
    b=(unsigned char*)malloc(len);if(!b)goto done;
    if(fread(b,1,len,in)!=len)goto done;
    marker_low=!memcmp(b+0x3018,marker,sizeof(marker)-1);
    marker_high=!memcmp(b+0x103018,marker,sizeof(marker)-1);
    entry_ok=!memcmp(b+0x58dc,entry,sizeof(entry));
    exit_ok=!memcmp(b+0x593c,exitseq,sizeof(exitseq));
    high_zero=1;for(i=0;i<0x68;i++)if(b[0x1058dc+i]){high_zero=0;break;}
    for(i=0;i+sizeof(call)<=len;i++)if(!memcmp(b+i,call,sizeof(call))){refs++;if(i<0x10000)lowrefs++;}
    out=fopen(report,"w");if(!out)goto done;
    fprintf(out,"; DriveKit Stage 9.7 - B0 evidence audit (read-only)\n");
    fprintf(out,"DUMP_SIZE 0x%lX\n",(unsigned long)len);
    fprintf(out,"MARKER_AT_OFFSET_0x003018 %s\n",marker_low?"MATCH":"NO_MATCH");
    fprintf(out,"MARKER_AT_OFFSET_0x103018 %s\n",marker_high?"MATCH":"NO_MATCH");
    fprintf(out,"ENTRY_AT_OFFSET_0x0058DC %s\n",entry_ok?"MATCH":"NO_MATCH");
    fprintf(out,"RESTORE_AND_RTS_AT_0x00593C %s\n",exit_ok?"MATCH":"NO_MATCH");
    fprintf(out,"OFFSET_0x1058DC_FIRST_0x68_BYTES_ZERO %s\n",high_zero?"YES":"NO");
    fprintf(out,"RAW_JSR_0x1058DC_PATTERN_COUNT %lu (LOW_64K %lu)\n",(unsigned long)refs,(unsigned long)lowrefs);
    fprintf(out,"MAPPING_0x1058DC_TO_0x0058DC %s\n",marker_low&&!marker_high&&entry_ok&&exit_ok&&lowrefs?"SUPPORTED_NOT_HARDWARE_PROVEN":"INSUFFICIENT_EVIDENCE");
    fprintf(out,"ER3_EXTERNAL_ROUTINE %s\n",entry_ok&&exit_ok?"SAVE_RESTORE_SIGNATURE_PRESENT_NOT_FULL_CFG_PROOF":"NOT_PROVEN");
    fprintf(out,"ER3_CHAIN_0x400140_0x400166_0x40018C NOT_PROMOTED\n");
    fprintf(out,"NOTE: raw call patterns may include data; full CFG and caller-path proof still required.\n");
    fprintf(out,"NO_NEW_XREF_RESOLUTIONS_OR_REACHABILITY_SEEDS\n");
    rc=fclose(out)==0;out=NULL;
done:
    if(out)fclose(out);
    if(in)fclose(in);
    free(b);
    return rc;
}


/* Stage 9.8: bounded, fail-closed CFG proof for the exact external routine.
 * This is intentionally a proof of one known routine, NOT a generic register
 * liveness engine. Every decoded instruction must match the independently
 * reviewed baseline; any modified byte, new edge or alternate exit fails. */
static int dk_h8s_b0_er3_cfg(const unsigned char *b,size_t len,FILE *f)
{
    static const unsigned char reference[]={
        0x01,0x30,0x6d,0xf0,0x6d,0xf4,0x73,0x09,0x47,0x08,0x6c,0x0b,0x68,0x9b,0x0b,0x01,
        0x1b,0x72,0x0d,0x24,0x11,0x32,0x73,0x08,0x47,0x22,0x11,0x32,0x47,0x14,0x6c,0x03,
        0x6c,0x0b,0x0d,0x3b,0x6c,0x03,0x6c,0x0b,0x01,0x00,0x69,0x93,0x0b,0x91,0x1b,0x72,
        0x46,0xec,0x73,0x1c,0x47,0x22,0x6c,0x03,0x6c,0x0b,0x40,0x18,0x11,0x32,0x47,0x0e,
        0x01,0x00,0x6d,0x03,0x01,0x00,0x69,0x93,0x0b,0x91,0x1b,0x72,0x46,0xf2,0x73,0x1c,
        0x47,0x06,0x6d,0x03,0x69,0x93,0x0b,0x81,0x73,0x0c,0x47,0x04,0x68,0x0b,0x68,0x9b,
        0x6d,0x74,0x01,0x30,0x6d,0x73,0x54,0x70};
    unsigned char start[sizeof(reference)]={0},visited[sizeof(reference)]={0};
    unsigned char state[sizeof(reference)]={0};
    size_t queue[sizeof(reference)*4],head=0,tail=0,off=0,insns=0,edges=0,returns=0;
    int ok=1;
    if(len<0x58dcu+sizeof(reference) || memcmp(b+0x58dc,reference,sizeof(reference))){
        fprintf(f,"EXTERNAL_CFG BYTE_BASELINE_MISMATCH FAIL_CLOSED\n");return 0;
    }
    /* First pass: exact instruction boundaries, including a strict entry/exit. */
    while(off<sizeof(reference)){
        size_t n=dk_h8s2600_length(reference+off,sizeof(reference)-off);
        if(!n || off+n>sizeof(reference)){ok=0;break;}
        start[off]=1;insns++;off+=n;
    }
    if(!ok || off!=sizeof(reference)){
        fprintf(f,"EXTERNAL_CFG DECODE_FAILED FAIL_CLOSED\n");return 0;
    }
    /* States: bit 0 = STM executed, bit 1 = R4 restored,
     * bit 2 = LDM executed. Merge different states separately. */
    queue[tail++]=0;state[0]=1;
    while(head<tail && ok){
        size_t at=queue[head++],n=dk_h8s2600_length(reference+at,sizeof(reference)-at);
        unsigned char flags=(unsigned char)(state[at]-1),newflags=flags;
        size_t succ[2],count=0,k;
        visited[at]=1;
        if(at==0){if(flags){ok=0;break;}newflags|=1;}
        if(at==0x60){if(!(flags&1)){ok=0;break;}newflags|=2;}
        if(at==0x62){if((flags&3)!=3){ok=0;break;}newflags|=4;}
        if(at==0x66){
            if(n!=2 || reference[at]!=0x54 || reference[at+1]!=0x70 || newflags!=7){ok=0;break;}
            returns++;continue;
        }
        if(reference[at]>=0x40 && reference[at]<=0x4f && n==2){
            int displacement=(signed char)reference[at+1];
            long target=(long)at+2+displacement;
            if(target<0 || (size_t)target>=sizeof(reference)){ok=0;break;}
            succ[count++]=(size_t)target;
            if(reference[at]!=0x40)succ[count++]=at+n;
        }else{
            succ[count++]=at+n;
        }
        for(k=0;k<count;k++){
            size_t dest=succ[k];edges++;
            if(dest>=sizeof(reference) || !start[dest]){ok=0;break;}
            if(!state[dest]){
                if(tail>=sizeof(queue)){ok=0;break;}
                state[dest]=(unsigned char)(newflags+1);queue[tail++]=dest;
            }else if(state[dest]!=(unsigned char)(newflags+1)){
                /* Different preservation states at a join are unsafe. */
                ok=0;break;
            }
        }
    }
    if(!returns)ok=0;
    fprintf(f,"EXTERNAL_CFG_DECODED_INSTRUCTIONS %lu\n",(unsigned long)insns);
    fprintf(f,"EXTERNAL_CFG_TRAVERSED_EDGES %lu\n",(unsigned long)edges);
    fprintf(f,"EXTERNAL_CFG_VALIDATED_RTS %lu\n",(unsigned long)returns);
    fprintf(f,"EXTERNAL_ER3_PRESERVATION %s\n",ok?"PROVEN_FOR_EXACT_B0_BYTES":"NOT_PROVEN_FAIL_CLOSED");
    fprintf(f,"EXTERNAL_CFG_SCOPE exact 0x0058DC-0x005943 bytes; mapping and callers not established by this proof\n");
    (void)visited;
    return ok;
}

static int dk_h8s_write_b0_er3_cfg(const char *dump,const char *report)
{
    FILE *in=NULL,*out=NULL;unsigned char *b=NULL;long sz;size_t len;
    int ok=0;
    if(!dump || !report || !strcmp(dump,report))return 0;
    in=fopen(dump,"rb");if(!in)return 0;
    if(fseek(in,0,SEEK_END) || (sz=ftell(in))<0 || fseek(in,0,SEEK_SET))goto done;
    len=(size_t)sz;if(len<0x5944u || len>64u*1024u*1024u)goto done;
    b=(unsigned char*)malloc(len);if(!b)goto done;
    if(fread(b,1,len,in)!=len)goto done;
    out=fopen(report,"w");if(!out)goto done;
    fprintf(out,"; DriveKit Stage 9.8 - external ER3 bounded CFG audit (read-only)\n");
    (void)dk_h8s_b0_er3_cfg(b,len,out);
    fprintf(out,"MAPPING_0x1058DC_TO_0x0058DC SUPPORTED_NOT_HARDWARE_PROVEN\n");
    fprintf(out,"KERNEL_CALLER_CHAIN NOT_PROVEN_BY_THIS_AUDIT\n");
    fprintf(out,"ER3_CHAIN_0x400140_0x400166_0x40018C NOT_PROMOTED\n");
    fprintf(out,"NO_NEW_XREF_RESOLUTIONS_OR_REACHABILITY_SEEDS\n");
    ok=fclose(out)==0;out=NULL;
done:
    if(out)fclose(out);
    if(in)fclose(in);
    free(b);return ok;
}


/* Stage 9.9: separate diagnostic ER3 chain audit. This intentionally does not
 * change the decoder, classification, xrefs, or promotion logic.  It checks
 * exact caller/callee bytes, tracks explicit R3 stack saves/restores, and
 * fails closed on unmodeled instructions and branches. */
static int dk99_scan_function(const unsigned char *b,size_t len,uint32_t base,
                              uint32_t entry,uint32_t end,FILE *f)
{
    unsigned char seen[256]={0}, start[256]={0};
    unsigned char state[256]={0};
    size_t q[1024],head=0,tail=0,off=0,insns=0,edges=0,returns=0;
    size_t span;int ok=1,clobber=0;
    if(entry<base || end<=entry || (uint64_t)end-base>len || end-entry>sizeof(seen)){
        fprintf(f,"FUNCTION_0x%06X UNKNOWN RANGE\n",(unsigned)entry);return 0;
    }
    span=(size_t)(end-entry);
    while(off<span){size_t n=dk_h8s2600_length(b+(entry-base)+off,span-off);
        if(!n || off+n>span){ok=0;break;}start[off]=1;off+=n;insns++;}
    if(!ok){fprintf(f,"FUNCTION_0x%06X UNKNOWN DECODE_BOUNDARY\n",(unsigned)entry);return 0;}
    q[tail++]=0;state[0]=1; /* state 1=original R3 live, 2=saved R3 with live value,
                               3=saved R3 with current R3 modified */
    while(head<tail && ok){
        size_t at=q[head++],n=dk_h8s2600_length(b+(entry-base)+at,span-at);
        const unsigned char *x=b+(entry-base)+at;
        unsigned char st=state[at],next=st;
        size_t dest[2],nd=0,k;
        if(seen[at])continue;
        seen[at]=1;
        if(n==2 && x[0]==0x6d && x[1]==0xf3){ /* MOV.W R3,@-ER7 */
            if(st!=1){ok=0;break;}next=2;
        }else if(n==2 && x[0]==0x6d && x[1]==0x73){ /* MOV.W @ER7+,R3 */
            if(st!=2 && st!=3){ok=0;break;}next=1;
        }else if(n==2 && x[0]==0x0d && x[1]==0x23){ /* MOV.W R2,R3 */
            if(st==1){clobber=1;ok=0;break;}else next=3;
        }else if(n==2 && x[0]==0xeb && x[1]==0x03){ /* AND.B #3,R3L */
            if(st==1){clobber=1;ok=0;break;}else next=3;
        }else if(n==2 && x[0]==0x1a && x[1]==0x0b){ /* DEC.B R3L */
            if(st==1){clobber=1;ok=0;break;}else next=3;
        }else if(n==2 && x[0]==0x54 && x[1]==0x70){
            returns++;if(st!=1)ok=0;continue;
        }else if(n==2 && x[0]>=0x40 && x[0]<=0x4f){
            /* handled below */
        }else if((n==2 && ((x[0]==0x0f && x[1]==0xa2) ||
                    (x[0]==0x0a && x[1]==0xa0) || (x[0]==0x73 && x[1]==0x08) ||
                    (x[0]==0x6c && x[1]==0x89) || (x[0]==0x1b && x[1]==0x72) ||
                    (x[0]==0x0c && x[1]==0x91) || (x[0]==0x0d && x[1]==0x19) ||
                    (x[0]==0x11 && x[1]==0x72))) ||
                 (n==4 && x[0]==0x01 && x[1]==0x00 && x[2]==0x6d && x[3]==0x81)){
            /* Exact observed non-ER3 instructions in 0x4069BE. */
        }else{
            fprintf(f,"  0x%06X UNKNOWN_EFFECT",(unsigned)(entry+at));
            {size_t j;for(j=0;j<n;j++)fprintf(f," %02X",x[j]);}fprintf(f,"\n");ok=0;break;
        }
        if(n==2 && x[0]>=0x40 && x[0]<=0x4f){
            long t=(long)at+2+(signed char)x[1];
            if(t<0 || (size_t)t>=span){ok=0;break;}
            dest[nd++]=(size_t)t;
            if(x[0]!=0x40)dest[nd++]=at+n;
        }else dest[nd++]=at+n;
        for(k=0;k<nd;k++){
            size_t d=dest[k];edges++;
            if(d>=span || !start[d]){ok=0;break;}
            if(state[d] && state[d]!=next){
                /* Both states carry the original R3 in the same saved stack
                 * slot. Join to the conservative modified-current state. */
                if((state[d]==2 && next==3) || (state[d]==3 && next==2)){
                    state[d]=3;
                }else{
                    fprintf(f,"  0x%06X UNKNOWN_MERGE states=%u/%u\n",
                            (unsigned)(entry+d),state[d],next);ok=0;break;
                }
            }
            if(!state[d]){state[d]=next;if(tail>=sizeof(q)/sizeof(q[0])){ok=0;break;}q[tail++]=d;}
        }
    }
    fprintf(f,"FUNCTION_0x%06X %s INSTRUCTIONS %lu EDGES %lu RETURNS %lu%s\n",
            (unsigned)entry,ok && returns && !clobber?"PRESERVES_ER3":"UNKNOWN",
            (unsigned long)insns,(unsigned long)edges,(unsigned long)returns,
            ok?"":" FAIL_CLOSED");
    return ok && returns && !clobber;
}

/* Stage 9.10: exact-byte wrapper contracts.  These are deliberately
 * independent of the decoder.  No summary is accepted if even one byte
 * differs, and a nested call requires an independently proven callee. */
static int dk910_exact(const unsigned char *b,size_t len,uint32_t base,
                       uint32_t addr,const unsigned char *expected,size_t n)
{
    return addr>=base && (uint64_t)(addr-base)+n<=len &&
           memcmp(b+(size_t)(addr-base),expected,n)==0;
}
static int dk910_wrappers(const unsigned char *b,size_t len,uint32_t base,
                          int helper,FILE *f)
{
    /* 405E1A: push R4, modify R4/R2/R1, call 4069BE, pop R4, RTS.
     * None of the local instructions writes ER3 or any of its aliases. */
    static const unsigned char w1[]={
        0x6d,0xf4,0x0d,0x24,0x0f,0x92,0x1a,0x82,0x0d,0x41,
        0x5e,0x40,0x69,0xbe,0x6d,0x74,0x54,0x70};
    /* 405E02: save ER4, shuffle ER0/ER1/ER2/ER4, call 4069A0,
     * restore ER4, RTS.  Callee 4069A0 has a direct external call. */
    static const unsigned char w2[]={
        0x01,0x00,0x6d,0xf4,0x0f,0xa4,0x1a,0x81,0x0f,0x92,
        0x0f,0x81,0x0f,0xc0,0x5e,0x40,0x69,0xa0,
        0x01,0x00,0x6d,0x74,0x54,0x70};
    /* 4069A0: branches, register swaps, save/restore ER2, direct
     * JSR 1058DC, RTS.  The external call contract is not established
     * for the running device by this Kernel-only audit. */
    static const unsigned char h0[]={
        0x1f,0x81,0x47,0x18,0x0f,0xa2,0x47,0x14,
        0x01,0x00,0x6d,0xf2,0x0f,0x82,0x0f,0x90,
        0x0f,0xa1,0x01,0x00,0x6d,0x72,
        0x5e,0x10,0x58,0xdc,0x0f,0x90,0x54,0x70};
    int a=dk910_exact(b,len,base,0x405e1a,w1,sizeof(w1));
    int c=dk910_exact(b,len,base,0x405e02,w2,sizeof(w2));
    int h=dk910_exact(b,len,base,0x4069a0,h0,sizeof(h0));
    fprintf(f,"WRAPPER_0x405E1A %s\n",a&&helper?
        "PRESERVES_ER3_EXACT_BYTES_CALLEE_0x4069BE_PROVEN":
        a?"UNKNOWN_CALLEE_0x4069BE":"UNKNOWN_BYTE_MISMATCH");
    fprintf(f,"WRAPPER_0x405E02 %s\n",c?
        "UNKNOWN_CALLEE_0x4069A0":"UNKNOWN_BYTE_MISMATCH");
    fprintf(f,"HELPER_0x4069A0 %s\n",h?
        "UNKNOWN_EXTERNAL_CALL_0x1058DC":"UNKNOWN_BYTE_MISMATCH");
    fprintf(f,"WRAPPER_SUMMARY_SCOPE EXACT_BYTES_ONLY_NO_GLOBAL_ABI_ASSUMPTIONS\n");
    return a&&helper;
}

static int dk99_write_audit(const char *path,const unsigned char *b,size_t len,uint32_t base)
{
    FILE *f=fopen(path,"w");int helper=0;
    static const uint32_t sites[]={0x40012c,0x400140,0x400166,0x40018c};
    size_t i;
    if(!f)return 0;
    fprintf(f,"; DriveKit Stage 9.10 - ER3 wrapper-chain diagnostic (read-only)\n");
    fprintf(f,"; UNKNOWN is deliberate: no speculative register contracts or promotion.\n");
    if(base!=0x400000 || len<0x6a00){
        fprintf(f,"KERNEL UNKNOWN BASE_OR_LENGTH\n");
    }else{
        const unsigned char *p=b+(0x400126-base);
        int load=!memcmp(p,"\x7a\x03\x00\x40\x5e\x02",6);
        fprintf(f,"ER3_ORIGIN_0x400126 %s\n",load?"IMMEDIATE_0x405E02":"UNKNOWN_BYTES");
        for(i=0;i<sizeof(sites)/sizeof(sites[0]);i++){
            uint32_t a=sites[i];size_t at=(size_t)(a-base);
            fprintf(f,"CALL_0x%06X %s\n",(unsigned)a,
                    at+2<=len && b[at]==0x5d && b[at+1]==0x30?"JSR_ER3_CONFIRMED":"UNKNOWN_BYTES");
        }
        helper=dk99_scan_function(b,len,base,0x4069be,0x4069f0,f);
        fprintf(f,"HELPER_0x4069BE %s\n",helper?"PRESERVES_ER3_EXACT_MODELED_PATHS":"UNKNOWN");
        (void)dk910_wrappers(b,len,base,helper,f);
    }
    fprintf(f,"CALLER_CHAIN_0x400140_0x400166_0x40018C UNKNOWN_NOT_PROMOTED\n");
    fprintf(f,"NOTE partial writes R3/R3H/R3L/E3 invalidate ER3 unless original value is restored.\n");
    fprintf(f,"NO_NEW_XREF_RESOLUTIONS_OR_REACHABILITY_SEEDS\n");
    return fclose(f)==0;
}

/* Stage 9.11: combine independent exact-byte Kernel and B0 evidence.
 * This is a CONDITIONAL preservation result, never a runtime mapping proof. */
static int dk911_link_audit(const char *dump,const char *report,
                            const unsigned char *kernel,size_t klen,uint32_t base)
{
    static const unsigned char w2[]={
        0x01,0x00,0x6d,0xf4,0x0f,0xa4,0x1a,0x81,0x0f,0x92,
        0x0f,0x81,0x0f,0xc0,0x5e,0x40,0x69,0xa0,
        0x01,0x00,0x6d,0x74,0x54,0x70};
    static const unsigned char h0[]={
        0x1f,0x81,0x47,0x18,0x0f,0xa2,0x47,0x14,
        0x01,0x00,0x6d,0xf2,0x0f,0x82,0x0f,0x90,
        0x0f,0xa1,0x01,0x00,0x6d,0x72,
        0x5e,0x10,0x58,0xdc,0x0f,0x90,0x54,0x70};
    static const unsigned char marker[]="AzHI2000/3";
    FILE *in=NULL,*f=NULL;unsigned char *b=NULL;
    long sz;size_t len,i;int external=0,mapping=0,helper=0,wrapper=0,rc=0;
    if(!dump||!report||!strcmp(dump,report))return 0;
    in=fopen(dump,"rb");if(!in)return 0;
    if(fseek(in,0,SEEK_END)||(sz=ftell(in))<0||fseek(in,0,SEEK_SET))goto done;
    len=(size_t)sz;if(len<0x105944u||len>64u*1024u*1024u)goto done;
    b=(unsigned char*)malloc(len);if(!b)goto done;
    if(fread(b,1,len,in)!=len)goto done;
    f=fopen(report,"w");if(!f)goto done;
    fprintf(f,"; DriveKit Stage 9.11 - conditional Kernel/B0 ER3 linkage (read-only)\n");
    helper=dk910_exact(kernel,klen,base,0x4069a0,h0,sizeof(h0));
    wrapper=dk910_exact(kernel,klen,base,0x405e02,w2,sizeof(w2));
    fprintf(f,"KERNEL_HELPER_0x4069A0_BYTES %s\n",helper?"MATCH":"MISMATCH");
    fprintf(f,"KERNEL_WRAPPER_0x405E02_BYTES %s\n",wrapper?"MATCH":"MISMATCH");
    external=dk_h8s_b0_er3_cfg(b,len,f);
    /* This is only evidence for a mapping, not proof that hardware executes it. */
    mapping=!memcmp(b+0x3018,marker,sizeof(marker)-1) &&
            memcmp(b+0x103018,marker,sizeof(marker)-1)!=0;
    for(i=0;i<0x68;i++)if(b[0x1058dc+i]!=0){mapping=0;break;}
    fprintf(f,"B0_LAYOUT_EVIDENCE %s\n",mapping?"CONSISTENT_WITH_MINUS_0x100000":"INSUFFICIENT");
    fprintf(f,"RUNTIME_MAPPING_0x1058DC_TO_B0_0x0058DC NOT_HARDWARE_PROVEN\n");
    fprintf(f,"HELPER_0x4069A0 %s\n",helper&&external?
        "CONDITIONALLY_PRESERVES_ER3_IF_RUNTIME_MAPPING_VALID":"UNKNOWN_FAIL_CLOSED");
    fprintf(f,"WRAPPER_0x405E02 %s\n",wrapper&&helper&&external?
        "CONDITIONALLY_PRESERVES_ER3_IF_RUNTIME_MAPPING_VALID":"UNKNOWN_FAIL_CLOSED");
    fprintf(f,"CALLER_CHAIN_0x400140_0x400166_0x40018C UNKNOWN_NOT_PROMOTED\n");
    fprintf(f,"NO_NEW_XREF_RESOLUTIONS_OR_REACHABILITY_SEEDS\n");
    rc=fclose(f)==0;f=NULL;
done:
    if(f)fclose(f);
    if(in)fclose(in);
    free(b);
    return rc;
}

static int dk_disasm_file(const char *input, const char *output, uint32_t base, size_t limit, int diagnostic, int classify, int branch_check, const char *xref_output, const char *discovery_output, const char *audit_output, const char *cfg_output, const char *callee_output, const char *b0_dump, const char *b0_report, const char *b0_cfg_dump, const char *b0_cfg_report, const char *er3_99_report, int promote_indirect)
{
    FILE *in = NULL, *out = NULL;
    unsigned char *buf = NULL, *mark = NULL;
    size_t reachable = 0, reachable_bytes = 0, unvisited_bytes = 0, referenced_bytes = 0;
    size_t reached_unknown=0,outside_targets=0,conflict_targets=0,branch_unvisited=0;
    size_t promoted=0,promotion_seeds=0;
    long sz;
    size_t len, at = 0, lines = 0, unknown_units = 0, unknown_bytes = 0, first_unknown = (size_t)-1;
    int rc = 1;
    if (!input || !output || !*input || !*output || strcmp(input, output) == 0) {
        fprintf(stderr, "disasm: provide different input and output paths\n"); return 1;
    }
    if(b0_cfg_dump && b0_cfg_report &&
       (!strcmp(b0_cfg_report,input) || !strcmp(b0_cfg_report,output) ||
        !strcmp(b0_cfg_report,b0_cfg_dump) || !strcmp(b0_cfg_dump,output))){
        fprintf(stderr,"disasm: B0 CFG path collision\n");return 1;
    }
    in = fopen(input, "rb");
    if (!in) { fprintf(stderr, "disasm: cannot open '%s': %s\n", input, strerror(errno)); goto done; }
    if (fseek(in, 0, SEEK_END) || (sz = ftell(in)) < 0 || fseek(in, 0, SEEK_SET)) {
        fprintf(stderr, "disasm: cannot determine input size\n"); goto done;
    }
    len = (size_t)sz;
    if (!len || (uint64_t)base + len > UINT32_MAX + (uint64_t)1) {
        fprintf(stderr, "disasm: empty input or address range exceeds 32 bits\n"); goto done;
    }
    buf = (unsigned char *)malloc(len);
    if (!buf) { fprintf(stderr, "disasm: allocation failed\n"); goto done; }
    if (fread(buf, 1, len, in) != len) { fprintf(stderr, "disasm: short read\n"); goto done; }
    fclose(in); in = NULL;
    if(classify) {
        mark=(unsigned char*)calloc(len,1);
        if(!mark || !dk_h8s_reachable(buf,len,base,mark,&reachable,&reached_unknown,&outside_targets,&conflict_targets)) {
            fprintf(stderr,"disasm: classification allocation failed\n");goto done;
        }
    }
    if(discovery_output && (!strcmp(discovery_output,input) || !strcmp(discovery_output,output) ||
                            (xref_output && !strcmp(discovery_output,xref_output)))) {
        fprintf(stderr,"disasm: discovery output must differ from other paths\n");goto done;
    }
    if(discovery_output && !dk_h8s_write_discovery(discovery_output,buf,mark,len,base)) {
        fprintf(stderr,"disasm: cannot write discovery report '%s'\n",discovery_output);goto done;
    }
    /* Write the read-only discovery report BEFORE optional promotion so the
     * original baseline and provenance remain independently inspectable. */
    if(promote_indirect && !dk_h8s_promote_indirect(buf,mark,len,base,&promoted,&promotion_seeds)) {
        fprintf(stderr,"disasm: Stage 9.3 promotion rejected: unknown, overlap, or outside-image path\n");goto done;
    }
    reachable+=promoted;
    if(xref_output && (!strcmp(xref_output,input) || !strcmp(xref_output,output))) {
        fprintf(stderr,"disasm: xref output must differ from input and assembly output\n");goto done;
    }
    if(audit_output && (!strcmp(audit_output,input) || !strcmp(audit_output,output) ||
       (xref_output && !strcmp(audit_output,xref_output)) ||
       (discovery_output && !strcmp(audit_output,discovery_output)))) {
        fprintf(stderr,"disasm: register audit path conflicts with another file\n");goto done;
    }
    if(audit_output && !dk_h8s_write_register_audit(audit_output,buf,mark,len,base)) {
        fprintf(stderr,"disasm: cannot write register audit\n");goto done;
    }
    if(cfg_output && (!strcmp(cfg_output,input) || !strcmp(cfg_output,output) ||
       (xref_output && !strcmp(cfg_output,xref_output)) ||
       (audit_output && !strcmp(cfg_output,audit_output)) ||
       (discovery_output && !strcmp(cfg_output,discovery_output)))){
        fprintf(stderr,"disasm: CFG audit path conflicts with another file\n");goto done;
    }
    if(cfg_output && !dk_h8s_write_cfg_audit(cfg_output,buf,mark,len,base)){
        fprintf(stderr,"disasm: cannot write CFG audit\n");goto done;
    }
    if(callee_output && (!strcmp(callee_output,input) || !strcmp(callee_output,output) ||
       (xref_output && !strcmp(callee_output,xref_output)) ||
       (audit_output && !strcmp(callee_output,audit_output)) ||
       (cfg_output && !strcmp(callee_output,cfg_output)) ||
       (discovery_output && !strcmp(callee_output,discovery_output)))){
        fprintf(stderr,"disasm: callee audit path conflicts with another file\n");goto done;
    }
    if(callee_output && !dk_h8s_write_callee_audit(callee_output,buf,mark,len,base)){
        fprintf(stderr,"disasm: cannot write callee audit\n");goto done;
    }
    if(b0_dump && (!b0_report || !strcmp(b0_dump,b0_report) || !strcmp(b0_report,input) || !strcmp(b0_report,output) || !strcmp(b0_dump,input) || (callee_output && !strcmp(b0_report,callee_output)) || (xref_output && !strcmp(b0_report,xref_output)) || (audit_output && !strcmp(b0_report,audit_output)) || (cfg_output && !strcmp(b0_report,cfg_output)) || (discovery_output && !strcmp(b0_report,discovery_output)))){
        fprintf(stderr,"disasm: B0 evidence audit path conflict or missing report\n");goto done;
    }
    if(b0_dump && !dk_h8s_write_b0_er3_audit(b0_dump,b0_report)){
        fprintf(stderr,"disasm: cannot inspect B0 dump or write evidence report\n");goto done;
    }
    if(b0_cfg_dump && !dk_h8s_write_b0_er3_cfg(b0_cfg_dump,b0_cfg_report)){
        fprintf(stderr,"disasm: cannot inspect B0 CFG or write report\n");goto done;
    }
    if(er3_99_report && (!strcmp(er3_99_report,input) || !strcmp(er3_99_report,output) ||
       (b0_cfg_dump && !strcmp(er3_99_report,b0_cfg_dump)) ||
       (b0_cfg_report && !strcmp(er3_99_report,b0_cfg_report)))){
        fprintf(stderr,"disasm: Stage 9.9 report path collision\n");goto done;
    }
    if(er3_99_report && !dk99_write_audit(er3_99_report,buf,len,base)){
        fprintf(stderr,"disasm: Stage 9.9 audit failed\n");goto done;
    }
    if(er3_99_report && b0_cfg_dump){
        /* Separate report, so the Stage 9.10 diagnostic remains unchanged. */
        if(!b0_report || !strcmp(b0_report,input) || !strcmp(b0_report,output) ||
           !strcmp(b0_report,b0_cfg_dump) || !strcmp(b0_report,b0_cfg_report) ||
           !strcmp(b0_report,er3_99_report) ||
           !dk911_link_audit(b0_cfg_dump,b0_report,buf,len,base)){
            fprintf(stderr,"disasm: Stage 9.11 linkage report failed\n");goto done;
        }
    }
    if(xref_output && !dk_h8s_write_xrefs(xref_output,buf,mark,len,base)) {
        fprintf(stderr,"disasm: cannot write xref report '%s'\n",xref_output);goto done;
    }
    out = fopen(output, "w");
    if (!out) { fprintf(stderr, "disasm: cannot create '%s': %s\n", output, strerror(errno)); goto done; }
    fprintf(out, "; DriveKit H8S/2600 Advanced - stage 9.9 length-validated partial disassembly\n");
    fprintf(out, "; Base: 0x%08X, size: 0x%lX; unknown units are .WORD (linear) or .BYTE (classified)\n", (unsigned int)base, (unsigned long)len);
    if(promote_indirect)fprintf(out,"; STAGE 9.3 PROMOTION: %lu indirect seeds, %lu newly reached instructions; opt-in, strict all-or-nothing\n",(unsigned long)promotion_seeds,(unsigned long)promoted);
    if(!classify) fprintf(out, "; WARNING: linear sweep does not distinguish executable code from data\n");
    fprintf(out, "; WARNING: invalid/truncated encodings are unknown; semantic decoding remains partial\n");
    if(classify) fprintf(out,"; CLASSIFY: only reachable decoded instructions shown as code; unvisited is NOT proven data\n; NOTE: diagnostic counts cover emitted code, not the whole firmware\n");
    if (diagnostic) fprintf(out, "; DIAGNOSTIC MODE: unknown units flagged with offset, opcode, and uncertain length\n");
    fputc('\n', out);
    while (at < len && lines < limit) {
        if(classify && mark[at]!=1 && mark[at]!=4) {
            size_t end=at, i;
            int referenced = mark[at]==3;
            /* Never combine a referenced byte with unreferenced bytes, or
             * accidentally consume the interior of a decoded instruction. */
            if(referenced) {
                fprintf(out,"%08X  %02X  .BYTE H'%02X ; directly referenced address (candidate data)\n",
                        (unsigned int)(base+(uint32_t)at),buf[at],buf[at]);
                at++;lines++;continue;
            }
            /* First collapse repeated unvisited bytes (not just FF). */
            while(end<len && mark[end]==0 && buf[end]==buf[at] && end-at<65536) end++;
            if(end-at>=16) {
                fprintf(out,"%08X  %02X x %lu  .FILL %lu,H'%02X ; unvisited, code/data unknown\n",
                        (unsigned int)(base+(uint32_t)at),buf[at],
                        (unsigned long)(end-at),(unsigned long)(end-at),buf[at]);
                at=end;lines++;continue;
            }
            /* Otherwise emit up to 16 bytes per row, stopping at a decoded
             * instruction, a directly referenced address, or a long fill. */
            end=at;
            while(end<len && mark[end]==0 && end-at<16) {
                size_t r=end;
                while(r<len && mark[r]==0 && buf[r]==buf[end] && r-end<16) r++;
                if(end>at && r-end>=16) break;
                end++;
            }
            fprintf(out,"%08X  ",(unsigned int)(base+(uint32_t)at));
            for(i=at;i<end;i++) fprintf(out,"%02X ",buf[i]);
            fputs(" .BYTE ",out);
            for(i=at;i<end;i++) fprintf(out,"%sH'%02X",i==at?"":",",buf[i]);
            fputs(" ; unvisited, code/data unknown\n",out);
            at=end;lines++;continue;
        }
        if(classify && mark[at]==4) {
            unknown_units++;unknown_bytes++;if(first_unknown==(size_t)-1)first_unknown=at;
            fprintf(out,"%08X  %02X  .BYTE H'%02X ; REACHED UNKNOWN: instruction length unverified\n",
                    (unsigned int)(base+(uint32_t)at),buf[at],buf[at]);
            at++;lines++;continue;
        }
        /* Collapse erased flash into one line without treating it as code. */
        if (buf[at] == 0xff) {
            size_t end=at;
            while (end<len && buf[end]==0xff) end++;
            if (end-at>=16) {
                fprintf(out,"%08X  FF x %lu  .FILL %lu,H'FF ; erased/padding region\n",
                        (unsigned int)(base+(uint32_t)at),(unsigned long)(end-at),(unsigned long)(end-at));
                at=end; lines++; continue;
            }
        }
        char asmtext[128];
        size_t i, count = dk_h8s_decode(buf + at, len - at, asmtext, sizeof(asmtext));
        if (!count) {
            if (first_unknown == (size_t)-1) first_unknown = at;
            unknown_units++;
            if (len-at>=2) {
                count=2;
                unknown_bytes+=2;
                snprintf(asmtext,sizeof(asmtext),".WORD H'%02X%02X ; unclassified, length not verified",buf[at],buf[at+1]);
            } else {
                count=1;
                unknown_bytes++;
                snprintf(asmtext,sizeof(asmtext),".BYTE H'%02X ; trailing byte",buf[at]);
            }
        }
        fprintf(out, "%08X  ", (unsigned int)(base + (uint32_t)at));
        for (i = 0; i < count; i++) fprintf(out, "%02X ", buf[at + i]);
        for (; i < 8; i++) fputs("   ", out);
        fprintf(out, " %s", asmtext);
        if (diagnostic && strstr(asmtext, "unclassified"))
            fprintf(out, " ; DIAG: unknown opcode at file+0x%lX; length UNCERTAIN",
                    (unsigned long)at);
        fputc('\n', out);
        at += count;
        lines++;
    }
    if(classify) {
        size_t j;
        for(j=0;j<len;j++) {
            if(mark[j]==1 || mark[j]==2) reachable_bytes++;
            else if(mark[j]==3) referenced_bytes++;
            else if(mark[j]==4) { unvisited_bytes++; /* separately reported reachable unknown */ }
            else unvisited_bytes++;
        }
        fprintf(out,"\n; CLASSIFICATION (entire input): %lu reachable candidate instructions\n",
                (unsigned long)reachable);
        fprintf(out,"; CLASSIFICATION BYTES: %lu decoded-code, %lu referenced-candidate, %lu unvisited/unknown\n",
                (unsigned long)reachable_bytes,(unsigned long)referenced_bytes,(unsigned long)unvisited_bytes);
        fprintf(out,"; REACHABILITY: %lu reached-unknown starts, %lu targets outside image, %lu overlapping targets\n",
                (unsigned long)reached_unknown,(unsigned long)outside_targets,(unsigned long)conflict_targets);
        fprintf(out,"; NOTE: unvisited/unknown bytes are not proven non-executable\n");
        if(branch_check) {
            size_t pos;
            for(pos=0;pos<len;pos++)if(mark[pos]==1) {
                char op[128];size_t n=dk_h8s_decode(buf+pos,len-pos,op,sizeof(op));
                int has_target,fallthrough;uint64_t dest;
                if(!n)continue;
                dk_h8s_flow(buf+pos,n,base,pos,&has_target,&dest,&fallthrough);
                if(has_target && dest>=base && dest-(uint64_t)base<len &&
                   mark[(size_t)(dest-base)]!=1) {
                    branch_unvisited++;
                    fprintf(out,"; BRANCH CHECK: 0x%08X -> 0x%08X (target status %s)\n",
                            (unsigned)(base+(uint32_t)pos),(unsigned)dest,
                            dk_h8s_mark_name(mark[(size_t)(dest-base)]));
                }
            }
            fprintf(out,"; BRANCH CHECK: %lu direct targets not classified as instruction starts\n",
                    (unsigned long)branch_unvisited);
        }
    }
    if (diagnostic) {
        fprintf(out, "\n; DIAGNOSTICS (%s, emitted entries only): %lu unknown units, %lu unknown bytes\n",
                classify?"reachable candidate code":"linear sweep",
                (unsigned long)unknown_units, (unsigned long)unknown_bytes);
        if (first_unknown != (size_t)-1)
            fprintf(out, "; FIRST UNKNOWN: file+0x%lX, address 0x%08X\n",
                    (unsigned long)first_unknown, (unsigned int)(base+(uint32_t)first_unknown));
        fprintf(stderr, "disasm: diagnostics (%s, emitted entries): %lu unknown units (%lu bytes); first file offset: ",
                classify?"reachable candidate code":"linear sweep",
                (unsigned long)unknown_units, (unsigned long)unknown_bytes);
        if (first_unknown == (size_t)-1) fprintf(stderr, "none\n");
        else fprintf(stderr, "0x%lX\n", (unsigned long)first_unknown);
    }
    if (ferror(out)) { fclose(out); out = NULL; fprintf(stderr, "disasm: output write failed\n"); goto done; }
    if (fclose(out)) { out = NULL; fprintf(stderr,"disasm: output close failed\n"); goto done; }
    out = NULL;
    printf("disasm: wrote %lu lines to %s (stage 9.9 length-validated partial decoder)\n", (unsigned long)lines, output);
    rc = 0;
done:
    if (out) fclose(out);
    if (in) fclose(in);
    free(mark);free(buf);
    return rc;
}

/* Standalone command parser; deliberately bypasses drive selection and SCSI. */
static int dk_disasm_command(int argc, char **argv)
{
    const char *input = NULL, *output = NULL, *xref_output = NULL, *discovery_output = NULL, *audit_output = NULL, *cfg_output = NULL, *callee_output = NULL, *b0_dump = NULL, *b0_report = NULL, *b0_cfg_dump = NULL, *b0_cfg_report = NULL, *er3_99_report = NULL;
    uint32_t base = 0;
    size_t count = (size_t)-1;
    int diagnostic = 0, classify = 0, branch_check = 0, promote_indirect = 0;
    int i;
    for (i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--file") && i + 1 < argc) input = argv[++i];
        else if ((!strcmp(argv[i], "--file2") || !strcmp(argv[i], "--out")) && i + 1 < argc) output = argv[++i];
        else if (!strcmp(argv[i], "--discover") && i + 1 < argc) { discovery_output=argv[++i]; classify=1; }
        else if (!strcmp(argv[i], "--xrefs") && i + 1 < argc) { xref_output=argv[++i]; classify=1; }
        else if (!strcmp(argv[i], "--er3-chain-audit") && i+1<argc) {er3_99_report=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--er3-link-report") && i+1<argc) {b0_report=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--b0-er3-cfg") && i+2<argc) {b0_cfg_dump=argv[++i];b0_cfg_report=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--b0-er3-audit") && i+2<argc) {b0_dump=argv[++i];b0_report=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--callee-audit") && i+1<argc) {callee_output=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--cfg-audit") && i+1<argc) {cfg_output=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--reg-audit") && i+1<argc) {audit_output=argv[++i];classify=1;}
        else if (!strcmp(argv[i], "--promote-indirect")) {promote_indirect=1;classify=1;}
        else if (!strcmp(argv[i], "--diagnostic")) diagnostic = 1;
        else if (!strcmp(argv[i], "--classify")) classify = 1;
        else if (!strcmp(argv[i], "--branch-check")) {branch_check=1;classify=1;}
        else if (!strcmp(argv[i], "--base") && i + 1 < argc) {
            char *end; unsigned long long v;
            errno = 0; v = strtoull(argv[++i], &end, 0);
            if (errno || !*argv[i] || *end || v > UINT32_MAX) { fprintf(stderr, "disasm: invalid --base\n"); return 1; }
            base = (uint32_t)v;
        } else if (!strcmp(argv[i], "--count") && i + 1 < argc) {
            char *end; unsigned long long v;
            errno = 0; v = strtoull(argv[++i], &end, 0);
            if (errno || !*argv[i] || *end || v == 0 || v > (unsigned long long)(size_t)-1) {
                fprintf(stderr, "disasm: invalid --count\n"); return 1;
            }
            count = (size_t)v;
        } else if (!strcmp(argv[i], "--help")) {
            printf("Usage: drivekit disasm --file input.bin --out output.asm --base 0x400000 [--count 100] [--diagnostic] [--classify] [--branch-check] [--xrefs report.txt] [--discover discovery.txt] [--promote-indirect] [--reg-audit report.txt] [--cfg-audit report.txt] [--callee-audit report.txt] [--b0-er3-audit dump.bin report.txt] [--b0-er3-cfg dump.bin report.txt] [--er3-chain-audit report.txt]\n");
            return 0;
        } else if (argv[i][0] != '-' && !input) input = argv[i];
        else { fprintf(stderr, "disasm: unknown/missing option '%s'\n", argv[i]); return 1; }
    }
    if (!input || !output) {
        fprintf(stderr, "Usage: drivekit disasm --file input.bin --out output.asm --base 0x400000 [--count 100] [--diagnostic] [--classify] [--branch-check] [--xrefs report.txt] [--discover discovery.txt] [--promote-indirect] [--reg-audit report.txt] [--cfg-audit report.txt] [--callee-audit report.txt] [--b0-er3-audit dump.bin report.txt] [--b0-er3-cfg dump.bin report.txt] [--er3-chain-audit report.txt]\n");
        return 1;
    }
    return dk_disasm_file(input, output, base, count, diagnostic, classify, branch_check, xref_output, discovery_output, audit_output, cfg_output, callee_output, b0_dump, b0_report, b0_cfg_dump, b0_cfg_report, er3_99_report, promote_indirect);
}
#endif
