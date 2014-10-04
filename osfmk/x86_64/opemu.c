/*   ** SINETEK **
 * This is called the Opcode Emulator: it traps invalid opcode exceptions
 *   and modifies the state of the running thread accordingly.
 * There are two entry points, one for user space exceptions, and another for
 *   exceptions coming from kernel space.
 *
 * STATUS
 *  . SSE3 is implemented.
 *  . SSSE3 is implemented.
 *  . SYSENTER is implemented.
 *  . SYSEXIT is implemented.
 *  . RDMSR is implemented.
 *
 */
#include <stdint.h>
#include "opemu.h"
#include "opemu_math.h"

#ifndef TESTCASE
#include <kern/sched_prim.h>

#define EMULATION_FAILED -1

// forward declaration for syscall handlers of mach/bsd (32+64 bit);
extern void mach_call_munger(x86_saved_state_t *state);
extern void unix_syscall(x86_saved_state_t *);
extern void mach_call_munger64(x86_saved_state_t *state);
extern void unix_syscall64(x86_saved_state_t *);

// forward declaration of panic handler for kernel traps;
extern void panic_trap(x86_saved_state64_t *regs);

// AnV - Implemented i386 version
#ifdef __x86_64__
unsigned char opemu_ktrap(x86_saved_state_t *state)
{
    x86_saved_state64_t *saved_state = saved_state64(state);
    
    uint8_t *code_buffer = (uint8_t *)saved_state->isf.rip;
    unsigned int bytes_skip = 0;
    
    
    bytes_skip = ssse3_run(code_buffer, state, 1, 1);
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_a(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_b(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_c(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = fisttp_run(code_buffer, state, 1, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = monitor_mwait_run(code_buffer, state, 1, 1);
    }
    
    if(!bytes_skip)
    {
        /* since this is ring0, it could be an invalid MSR read.
         * Instead of crashing the whole machine, report on it and keep running. */
        if((code_buffer[0]==0x0f) && (code_buffer[1]==0x32))
        {
            printf("[MSR] unknown location 0x%016llx\r\n", saved_state->rcx);
            // best we can do is return 0;
            saved_state->rdx = saved_state->rax = 0;
            bytes_skip = 2;
        }
    }
    
    saved_state->isf.rip += bytes_skip;
    
    if(!bytes_skip)
    {
        uint8_t *ripptr = (uint8_t *)&(saved_state->isf.rip);
        printf("invalid kernel opcode (64-bit): ");
        print_bytes(ripptr, 16);
        
        /* Fall through to trap */
        return 0;
    }
    
    
    
    return 1;
}
#else
unsigned char opemu_ktrap(x86_saved_state_t *state)
{
    x86_saved_state32_t *saved_state = saved_state32(state);
    uint64_t op = saved_state->eip;
    uint8_t *code_buffer = (uint8_t*)op ;
    unsigned int bytes_skip = 0;
    
    
    bytes_skip = ssse3_run(code_buffer, state, 0, 1);
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_a(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_b(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = sse3_run_c(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = fisttp_run(code_buffer, state, 0, 1);
    }
    
    if (!bytes_skip)
    {
        bytes_skip = monitor_mwait_run(code_buffer, state, 0, 1);
    }
    
    if(!bytes_skip)
    {
        /* since this is ring0, it could be an invalid MSR read.
         * Instead of crashing the whole machine, report on it and keep running. */
        if(code_buffer[0]==0x0f && code_buffer[1]==0x32)
        {
            printf("[MSR] unknown location 0x%016llx\r\n", saved_state->ecx);
            
            // best we can do is return 0;
            saved_state->edx = saved_state->eax = 0;
            bytes_skip = 2;
        }
    }
    
    saved_state->eip += bytes_skip;
    
    if(!bytes_skip)
    {
        uint8_t *eipptr = (uint8_t *)&(saved_state->eip);
        
        printf("invalid kernel opcode (32-bit): ");
        print_bytes(eipptr, 16);
        
        /* Fall through to trap */
        return 0;
    }
    
    return 1;
}
#endif

void opemu_utrap(x86_saved_state_t *state)
{
    
    int longmode;
    
    unsigned int bytes_skip = 0;
    vm_offset_t addr;
    
    if ((longmode = is_saved_state64(state)))
    {
        
        x86_saved_state64_t *saved_state = saved_state64(state);
        uint8_t *code_buffer = (uint8_t*)saved_state->isf.rip;
        
        addr = saved_state->isf.rip;
        uint16_t opcode;
        
        opcode = *(uint16_t *) addr;
        
        x86_saved_state64_t *regs;
        regs = saved_state64(state);
        if (opcode == 0x340f)
        {
            regs->isf.rip = regs->rdx;
            regs->isf.rsp = regs->rcx;
            
            if((signed int)regs->rax < 0) {
                //      printf("mach call 64\n");
                mach_call_munger64(state);
            } else {
                //      printf("unix call 64\n");
                unix_syscall64(state);
            }
            return;
        }
        
        if (opcode == 0x350f)
        {
            regs->isf.rip = regs->rdx;
            regs->isf.rsp = regs->rcx;
            // if (kernel_trap)
            // {
            //     addr = regs->rcx;
            //     return 0x7FFF;
            // } else {
            thread_exception_return();
            //}
            return;
        }
        
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_a(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_b(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_c(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = fisttp_run(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = monitor_mwait_run(code_buffer, state, longmode, 0);
        }
        
        regs->isf.rip += bytes_skip;
        
        if(!bytes_skip) {
            uint8_t *ripptr = (uint8_t *)&(regs->isf.rip);
            
            printf("invalid user opcode 64: ");
            print_bytes(ripptr, 16);
            /* Fall through to trap */
            return ;
        }
        
        
        
    }
    else
    {
        x86_saved_state32_t *saved_state = saved_state32(state);
        uint64_t op = saved_state->eip;
        uint8_t *code_buffer = (uint8_t*)op;
        
        addr = saved_state->eip;
        uint16_t opcode;
        
        opcode = *(uint16_t *) addr;
        
        x86_saved_state32_t *regs;
        regs = saved_state32(state);
        
       /* if (opcode == 0x340f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;
            
            if((signed int)regs->eax < 0) {
                mach_call_munger(state);
            } else {
                unix_syscall(state);
            }
            return;
            
        }*/
        
        if (opcode == 0x350f)
        {
            regs->eip = regs->edx;
            regs->uesp = regs->ecx;
            
            thread_exception_return();
            
            return;
        }
        
        bytes_skip = ssse3_run(code_buffer, state, longmode, 0);
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_a(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_b(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = sse3_run_c(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = fisttp_run(code_buffer, state, longmode, 0);
        }
        
        if (!bytes_skip)
        {
            bytes_skip = monitor_mwait_run(code_buffer, state, longmode, 0);
        }
        
        regs->eip += bytes_skip;
        
        if(!bytes_skip) {
            uint8_t *eipptr = (uint8_t *)&(regs->eip);
            
            printf("invalid user opcode 32: ");
            print_bytes(eipptr, 16);
            
            /* Fall through to trap */
            return ;
        }
        
    }
    
    thread_exception_return();
    /*** NOTREACHED ***/
    
   // return ;//EMULATION_FAILED;
}


/** Runs the sse3 emulator. returns the number of bytes consumed.
 **/
int sse3_run_a(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    XMM xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0xF2) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;
    
    
    
    switch (*bytep)
    {
        case 0x12:
            movddup(&xmmsrc,&xmmres);
            break;
        case 0x7C:
            haddps(&xmmsrc,&xmmdst,&xmmres);
            break;
        case 0x7D:
            hsubps(&xmmsrc,&xmmdst,&xmmres);
            break;
        case 0xD0:
            addsubps(&xmmsrc,&xmmdst,&xmmres);
            break;
        case 0xF0:
            lddqu(&xmmsrc,&xmmres);
            break;
        default:
            return 0;
    }
    
    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int sse3_run_b(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    XMM xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0xF3) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;
    
    
    
    switch (*bytep)
    {
        case 0x12:
            movsldup(&xmmsrc,&xmmres);
            break;
        case 0x16:
            movshdup(&xmmsrc,&xmmres);
            break;
        default:
            return 0;
    }
    
    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int sse3_run_c(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    XMM xmmsrc, xmmdst, xmmres;
    int src_higher = 0, dst_higher = 0;
    
    if(*bytep != 0x66) return 0;
    
    bytep++;
    ins_size++;
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    uint8_t *modrm = &bytep[1];
    ins_size += 1;
    int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
    ins_size += consumed;
    
    
    
    switch (*bytep)
    {
        case 0x7C:
            haddpd(&xmmsrc,&xmmdst,&xmmres);
            break;
        case 0x7D:
            hsubpd(&xmmsrc,&xmmdst,&xmmres);
            break;
        case 0xD0:
            addsubpd(&xmmsrc,&xmmdst,&xmmres);
            break;
        default:
            return 0;
    }
    
    storeresult128(*modrm, dst_higher, xmmres);
    
    return ins_size;
}

int fisttp_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int __unused kernel_trap)
{
    uint8_t *bytep = instruction;
    int ins_size = 0;
    uint8_t base = 0;
    uint8_t mod = 0;
    int8_t add = 0;
    uint8_t modrm = 0;
    uint64_t address = 0;
    uint64_t reg_sel[8];
    
    if (longmode)
    {
        x86_saved_state64_t* r64 = saved_state64(state);
        reg_sel[0] = r64->rax;
        reg_sel[1] = r64->rcx;
        reg_sel[2] = r64->rdx;
        reg_sel[3] = r64->rbx;
        reg_sel[4] = r64->isf.rsp;
        reg_sel[5] = r64->rbp;
        reg_sel[6] = r64->rsi;
        reg_sel[7] = r64->rdi;
    } else {
        x86_saved_state32_t* r32 = saved_state32(state);
        reg_sel[0] = r32->eax;
        reg_sel[1] = r32->ecx;
        reg_sel[2] = r32->edx;
        reg_sel[3] = r32->ebx;
        reg_sel[4] = r32->uesp;
        reg_sel[5] = r32->ebp;
        reg_sel[6] = r32->esi;
        reg_sel[7] = r32->edi;
    }
    
    if (*bytep == 0x66)
    {
        bytep++;
        ins_size++;
    }
    
    switch (*bytep)
    {
        case 0xDB:
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            fisttpl((double *)address);
            
            ins_size++;
            
            return(ins_size);
            break;
            
        case 0xDD:
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            fisttpq((long double *)address);
            
            ins_size++;
            
            return(ins_size);
            break;
            
        case 0xDF:
            bytep++;
            ins_size++;
            
            modrm = *bytep;
            base = modrm & 0x7;
            mod = (modrm & 0xC0) >> 6;
            
            if (mod == 0)
            {
                address = reg_sel[base];
            } else if (mod == 1) {
                bytep++;
                ins_size++;
                
                add = *bytep;
                address = reg_sel[base] + add;
            } else {
                return 0;
            }
            
            fisttps((float *)address);
            
            ins_size++;
            
            return(ins_size);
            break;
    }
    
    return 0;
}

int monitor_mwait_run(uint8_t *instruction, __unused x86_saved_state_t *  state, int __unused longmode, int __unused kernel_trap)
{
    uint8_t *bytep = instruction;
    
    if (*bytep != 0x0F)
    {
        return 0;
    }
    
    bytep++;
    
    if (*bytep != 0x01)
    {
        return 0;
    }
    
    bytep++;
    
    switch(*bytep)
    {
        case 0xC8:
        case 0xC9:
            return 3;
    }
    
    return 0;
}



/** Runs the ssse3 emulator. returns the number of bytes consumed.
 **/
int ssse3_run(uint8_t *instruction, x86_saved_state_t *state, int longmode, int kernel_trap)
{
    // pointer to the current byte we're working on
    uint8_t *bytep = instruction;
    int ins_size = 0;
    int is_128 = 0, src_higher = 0, dst_higher = 0;
    
    
    XMM xmmsrc, xmmdst, xmmres;
    MM mmsrc,mmdst, mmres;
    
    
    /** We can get a few prefixes, in any order:
     **  66 throws into 128-bit xmm mode.
     **  40->4f use higher xmm registers.
     **/
    if(*bytep == 0x66) {
        is_128 = 1;
        bytep++;
        ins_size++;
    }
    if((*bytep & 0xF0) == 0x40) {
        if(*bytep & 1) src_higher = 1;
        if(*bytep & 4) dst_higher = 1;
        bytep++;
        ins_size++;
    }
    
    if(*bytep != 0x0f) return 0;
    bytep++;
    ins_size++;
    
    /* Two SSSE3 instruction prefixes. */
    if((*bytep == 0x38 && bytep[1] != 0x0f) || (*bytep == 0x3a && bytep[1] == 0x0f)) {
        uint8_t opcode = bytep[1];
        uint8_t *modrm = &bytep[2];
        uint8_t operand;
        ins_size += 2; // not counting modRM byte or anything after.
        
        if(is_128) {
            int consumed = fetchoperands(modrm, src_higher, dst_higher, &xmmsrc, &xmmdst, longmode, state, kernel_trap, 1, ins_size);
            operand = bytep[2 + consumed];
            ins_size += consumed;
            
            switch(opcode) {
                case 0x00: pshufb128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x01: phaddw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x02: phaddd128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x03: phaddsw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x04: pmaddubsw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x05: phsubw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x06: phsubd128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x07: phsubsw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x08: psignb128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x09: psignw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x0A: psignd128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x0B: pmulhrsw128(&xmmsrc,&xmmdst,&xmmres); break;
                case 0x0F: palignr128(&xmmsrc, &xmmdst,&xmmres,operand);
                    ins_size++;
                    break;
                case 0x1C: pabsb128(&xmmsrc,&xmmres); break;
                case 0x1D: pabsw128(&xmmsrc,&xmmres); break;
                case 0x1E: pabsd128(&xmmsrc,&xmmres); break;
                default: return 0;
            }
            
            storeresult128(*modrm, dst_higher, xmmres);
        } else {
            int consumed = fetchoperands(modrm, src_higher, dst_higher, &mmsrc, &mmdst, longmode, state, kernel_trap, 0, ins_size);
            operand = bytep[2 + consumed];
            ins_size += consumed;
            
            switch(opcode) {
                case 0x00: pshufb64(&mmsrc,&mmdst,&mmres); break;
                case 0x01: phaddw64(&mmsrc,&mmdst,&mmres); break;
                case 0x02: phaddd64(&mmsrc,&mmdst,&mmres); break;
                case 0x03: phaddsw64(&mmsrc,&mmdst,&mmres); break;
                case 0x04: pmaddubsw64(&mmsrc,&mmdst,&mmres); break;
                case 0x05: phsubw64(&mmsrc,&mmdst,&mmres); break;
                case 0x06: phsubd64(&mmsrc,&mmdst,&mmres); break;
                case 0x07: phsubsw64(&mmsrc,&mmdst,&mmres); break;
                case 0x08: psignb64(&mmsrc,&mmdst,&mmres); break;
                case 0x09: psignw64(&mmsrc,&mmdst,&mmres); break;
                case 0x0A: psignd64(&mmsrc,&mmdst,&mmres); break;
                case 0x0B: pmulhrsw64(&mmsrc,&mmdst,&mmres); break;
                case 0x0F: palignr64(&mmsrc, &mmdst,&mmres, operand);
                    ins_size++;
                    break;
                case 0x1C: pabsb64(&mmsrc,&mmres); break;
                case 0x1D: pabsw64(&mmsrc,&mmres); break;
                case 0x1E: pabsd64(&mmsrc,&mmres); break;
                default: return 0;
            }
            
            storeresult64(*modrm, dst_higher, mmres);
        }
        
    } else {
        // opcode wasn't handled here
        return 0;
    }
    
    return ins_size;
}

void print_bytes(uint8_t *from, int size)
{
    int i;
    for(i = 0; i < size; ++i)
    {
        printf("%02x ", from[i]);
    }
    printf("\n");
}

/** Fetch SSSE3 operands (except immediate values, which are fetched elsewhere).
 * We depend on memory copies, which differs depending on whether we're in kernel space
 * or not. For this reason, need to pass in a lot of information, including the state of
 * registers.
 *
 * The return value is the number of bytes used, including the ModRM byte,
 * and displacement values, as well as SIB if used.
 */
int fetchoperands(uint8_t *ModRM, unsigned int hsrc, unsigned int hdst, void *src, void *dst, unsigned int longmode, x86_saved_state_t *saved_state, int kernel_trap, int size_128, __unused int  ins_size)
{
    unsigned int num_src = *ModRM & 0x7;
    unsigned int num_dst = (*ModRM >> 3) & 0x7;
    unsigned int mod = *ModRM >> 6;
    int consumed = 1;
    
    if(hsrc) num_src += 8;
    if(hdst) num_dst += 8;
    if(size_128) getxmm((XMM*)dst, num_dst);
    else getmm((MM*)dst, num_dst);
    
    if(mod == 3) {
        if(size_128) getxmm((XMM*)src, num_src);
        else getmm((MM*)src, num_src);
    } else if ((longmode = is_saved_state64(saved_state))) {
        uint64_t address;
        
        // DST is always an XMM register. decode for SRC.
        x86_saved_state64_t *r64 = saved_state64(saved_state);
        __uint64_t reg_sel[8] = {r64->rax, r64->rcx, r64->rdx,
            r64->rbx, r64->isf.rsp, r64->rbp,
            r64->rsi, r64->rdi};
        if(hsrc) printf("opemu error: high reg ssse\n"); // FIXME
        if(num_src == 4) {
            // Special case: SIB byte used TODO fix r8-r15? 
            uint8_t scale = ModRM[1] >> 6;
            uint8_t base = ModRM[1] & 0x7;
            uint8_t index = (ModRM[1] >> 3) & 0x7;
            consumed++;
            
            // meaning of SIB depends on mod
            if(mod == 0) {
                if(base == 5) printf("opemu error: mod0 disp32 not implemented\n"); // FIXME
                if(index == 4) address = reg_sel[base];
                else
				address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            } else {
                if(index == 4) 
				address = reg_sel[base];
                else 
				address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            }
        } else {
            address = reg_sel[num_src];
        }
        
        if((mod == 0) && (num_src == 5)) {
            // RIP-relative dword displacement
            // AnV - Warning from cast alignment fix
            __uint64_t ModRMVal = (__uint64_t)&ModRM[consumed];
            __int32_t *ModRMCast = (__int32_t *)ModRMVal;
            address = *(uint32_t*)&r64->isf.rip + *ModRMCast;
            //printf("opemu adress rip: %llu \n",address);
            
            consumed += 4;
        }
		if(mod == 1) {
            // byte displacement
            address +=(int8_t)ModRM[consumed];
            //printf("opemu adress byte : %llu \n",address);
            consumed++;
        } else if(mod ==2 ) {
            // dword displacement. can it be qword?
            // AnV - Warning from cast alignment fix
            __uint64_t ModRMVal = (__uint64_t)&ModRM[consumed];
            __int32_t *ModRMCast = (__int32_t *)ModRMVal;
            address +=  *ModRMCast;
            
            //printf("opemu adress byte : %llu \n",address);
            consumed += 4;
        }
        
        // address is good now, do read and store operands.
        if(kernel_trap) {
            if(size_128) ((XMM*)src)->ua128 = *((__uint128_t*)address);
            else ((MM*)src)->ua64 = *((uint64_t*)address);
        } else {
            //printf("xnu: da = %llx, rsp=%llx,  rip=%llx\n", address, reg_sel[4], r64->isf.rip);
            if(size_128) copyin(address, (char*)& ((XMM*)src)->ua128, 16);
            else copyin(address, (char*)& ((MM*)src)->ua64, 8);
        }
    }else {
        // AnV - Implemented 32-bit fetch
        uint32_t address;
        
        // DST is always an XMM register. decode for SRC.
        x86_saved_state32_t* r32 = saved_state32(saved_state);
        uint32_t reg_sel[8] = {r32->eax, r32->ecx, r32->edx,
            r32->ebx, r32->uesp, r32->ebp,
            r32->esi, r32->edi};
        if(hsrc) printf("opemu error: high reg ssse\n"); // FIXME
        if(num_src == 4) {
            /* Special case: SIB byte used TODO fix r8-r15? */
            uint8_t scale = ModRM[1] >> 6;
            uint8_t base = ModRM[1] & 0x7;
            uint8_t index = (ModRM[1] >> 3) & 0x7;
            consumed++;
            
            // meaning of SIB depends on mod
            if(mod == 0) {
                if(base == 5) printf("opemu error: mod0 disp32 not implemented\n"); // FIXME
                if(index == 4) address = reg_sel[base];
                else address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            } else {
                if(index == 4) address = reg_sel[base];
                else address = reg_sel[base] + (reg_sel[index] * (1<<scale));
            }
        } else {
            address = reg_sel[num_src];
        }
        
        if((mod == 0) && (num_src == 5)) {
            // RIP-relative dword displacement
            // AnV - Warning from cast alignment fix
            uint64_t ModRMVal = (uint64_t)&ModRM[consumed];
            int32_t *ModRMCast = (int32_t *)ModRMVal;
            address = r32->eip + *ModRMCast;
            
            //address = r32->eip + *((int32_t*)&ModRM[consumed]);
            consumed += 4;
        } if(mod == 1) {
            // byte displacement
            //int32_t mods = (int32_t)ModRM[consumed];
            //int8_t *Mods = (int8_t*)&mods;
            address += (int8_t)ModRM[consumed];
            // printf("opemu adress byte : %llu \n",address);
            consumed++;
        } else if(mod == 2) {
            // dword displacement. can it be qword?
            // AnV - Warning from cast alignment fix
            uint64_t ModRMVal = (uint64_t)&ModRM[consumed];
            int32_t *ModRMCast = (int32_t *)ModRMVal;
            address += *ModRMCast;
            
            //address += *((int32_t*)&ModRM[consumed]);
            consumed += 4;
        }
        
        // address is good now, do read and store operands.
        uint64_t addr = address;
        
        if(kernel_trap) {
            if(size_128) ((XMM*)src)->ua128 = *((__uint128_t*)addr);
            else ((MM*)src)->ua64 = *((uint64_t*)addr);
        } else {
            //printf("xnu: da = %llx, rsp=%llx,  rip=%llx\n", address, reg_sel[4], r32->eip);
            if(size_128) copyin(addr, (char*) &((XMM*)src)->ua128, 16);
            else copyin(addr, (char*) &((MM*)src)->ua64, 8);
        }
    }
    
    return consumed;
}

void storeresult128(uint8_t ModRM, unsigned int hdst, XMM res)
{
    unsigned int num_dst = (ModRM >> 3) & 0x7;
    if(hdst) num_dst += 8;
    movxmm(&res, num_dst);
}
void storeresult64(uint8_t ModRM, unsigned int __unused hdst, MM res)
{
    unsigned int num_dst = (ModRM >> 3) & 0x7;
    movmm(&res, num_dst);
}

#endif /* TESTCASE */

/* get value from the xmm register i */
void getxmm(XMM *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movdqu %%xmm0, %0" : "=m" (*v->a8));
            break;
        case 1:
            asm __volatile__ ("movdqu %%xmm1, %0" : "=m" (*v->a8));
            break;
        case 2:
            asm __volatile__ ("movdqu %%xmm2, %0" : "=m" (*v->a8));
            break;
        case 3:
            asm __volatile__ ("movdqu %%xmm3, %0" : "=m" (*v->a8));
            break;
        case 4:
            asm __volatile__ ("movdqu %%xmm4, %0" : "=m" (*v->a8));
            break;
        case 5:
            asm __volatile__ ("movdqu %%xmm5, %0" : "=m" (*v->a8));
            break;
        case 6:
            asm __volatile__ ("movdqu %%xmm6, %0" : "=m" (*v->a8));
            break;
        case 7:
            asm __volatile__ ("movdqu %%xmm7, %0" : "=m" (*v->a8));
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %%xmm8, %0" : "=m" (*v->a8));
            break;
        case 9:
            asm __volatile__ ("movdqu %%xmm9, %0" : "=m" (*v->a8));
            break;
        case 10:
            asm __volatile__ ("movdqu %%xmm10, %0" : "=m" (*v->a8));
            break;
        case 11:
            asm __volatile__ ("movdqu %%xmm11, %0" : "=m" (*v->a8));
            break;
        case 12:
            asm __volatile__ ("movdqu %%xmm12, %0" : "=m" (*v->a8));
            break;
        case 13:
            asm __volatile__ ("movdqu %%xmm13, %0" : "=m" (*v->a8));
            break;
        case 14:
            asm __volatile__ ("movdqu %%xmm14, %0" : "=m" (*v->a8));
            break;
        case 15:
            asm __volatile__ ("movdqu %%xmm15, %0" : "=m" (*v->a8));
            break;
#endif
    }
}

/* get value from the mm register i  */
void getmm(MM *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %%mm0, %0" : "=m" (*v->a8));
            break;
        case 1:
            asm __volatile__ ("movq %%mm1, %0" : "=m" (*v->a8));
            break;
        case 2:
            asm __volatile__ ("movq %%mm2, %0" : "=m" (*v->a8));
            break;
        case 3:
            asm __volatile__ ("movq %%mm3, %0" : "=m" (*v->a8));
            break;
        case 4:
            asm __volatile__ ("movq %%mm4, %0" : "=m" (*v->a8));
            break;
        case 5:
            asm __volatile__ ("movq %%mm5, %0" : "=m" (*v->a8));
            break;
        case 6:
            asm __volatile__ ("movq %%mm6, %0" : "=m" (*v->a8));
            break;
        case 7:
            asm __volatile__ ("movq %%mm7, %0" : "=m" (*v->a8));
            break;
    }
}

/* move value over to xmm register i */
void movxmm(XMM *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movdqu %0, %%xmm0" :: "m" (*v->a8) );
            break;
        case 1:
            asm __volatile__ ("movdqu %0, %%xmm1" :: "m" (*v->a8) );
            break;
        case 2:
            asm __volatile__ ("movdqu %0, %%xmm2" :: "m" (*v->a8) );
            break;
        case 3:
            asm __volatile__ ("movdqu %0, %%xmm3" :: "m" (*v->a8) );
            break;
        case 4:
            asm __volatile__ ("movdqu %0, %%xmm4" :: "m" (*v->a8) );
            break;
        case 5:
            asm __volatile__ ("movdqu %0, %%xmm5" :: "m" (*v->a8) );
            break;
        case 6:
            asm __volatile__ ("movdqu %0, %%xmm6" :: "m" (*v->a8) );
            break;
        case 7:
            asm __volatile__ ("movdqu %0, %%xmm7" :: "m" (*v->a8) );
            break;
#ifdef __x86_64__
        case 8:
            asm __volatile__ ("movdqu %0, %%xmm8" :: "m" (*v->a8) );
            break;
        case 9:
            asm __volatile__ ("movdqu %0, %%xmm9" :: "m" (*v->a8) );
            break;
        case 10:
            asm __volatile__ ("movdqu %0, %%xmm10" :: "m" (*v->a8) );
            break;
        case 11:
            asm __volatile__ ("movdqu %0, %%xmm11" :: "m" (*v->a8) );
            break;
        case 12:
            asm __volatile__ ("movdqu %0, %%xmm12" :: "m" (*v->a8) );
            break;
        case 13:
            asm __volatile__ ("movdqu %0, %%xmm13" :: "m" (*v->a8) );
            break;
        case 14:
            asm __volatile__ ("movdqu %0, %%xmm14" :: "m" (*v->a8) );
            break;
        case 15:
            asm __volatile__ ("movdqu %0, %%xmm15" :: "m" (*v->a8) );
            break;
#endif
    }
}

/* move value over to mm register i */
void movmm(MM *v, unsigned int i)
{
    switch(i) {
        case 0:
            asm __volatile__ ("movq %0, %%mm0" :: "m" (*v->a8) );
            break;
        case 1:
            asm __volatile__ ("movq %0, %%mm1" :: "m" (*v->a8) );
            break;
        case 2:
            asm __volatile__ ("movq %0, %%mm2" :: "m" (*v->a8) );
            break;
        case 3:
            asm __volatile__ ("movq %0, %%mm3" :: "m" (*v->a8) );
            break;
        case 4:
            asm __volatile__ ("movq %0, %%mm4" :: "m" (*v->a8) );
            break;
        case 5:
            asm __volatile__ ("movq %0, %%mm5" :: "m" (*v->a8) );
            break;
        case 6:
            asm __volatile__ ("movq %0, %%mm6" :: "m" (*v->a8) );
            break;
        case 7:
            asm __volatile__ ("movq %0, %%mm7" :: "m" (*v->a8) );
            break;
    }
}

/****************************************/
/* Bronzovka: Correcting for old amd    */
/****************************************/

/*********************************************/
/** AnV - SSE3 instructions implementation  **/
/*********************************************/

// TODO: Implement fetch mechanism
void fisttps(float *res)
{
    float value = opemu_truncf(*res);
    __asm__ ("fistps %0" : : "m" (value));
    *res = value;
}

void fisttpl(double *res)
{
    double value = opemu_trunc(*res);
    __asm__ ("fistpl %0" : : "m" (value));
    *res = value;
}

void fisttpq(long double *res)
{
    // AnV - Truncl doesn't work but fistpq has same result in this case... (tested)
    long double value = *res; /*opemu_truncl(*res);*/
    __asm__ ("fistpq %0" : : "m" (value));
    *res = value;
}

void addsubpd(XMM *src, XMM *dst, XMM *res)
{
    res->fa64[0] = src->fa64[0] - dst->fa64[0];
    res->fa64[1] = src->fa64[1] + dst->fa64[1];
}

void addsubps(XMM *src, XMM *dst, XMM *res)
{
    res->fa32[0] = src->fa32[0] - dst->fa32[0];
    res->fa32[1] = src->fa32[1] + dst->fa32[1];
    res->fa32[2] = src->fa32[2] - dst->fa32[2];
    res->fa32[3] = src->fa32[3] + dst->fa32[3];
}

void haddpd(XMM *src, XMM *dst, XMM *res)
{
    res->fa64[0] = src->fa64[0] + src->fa64[1];
    res->fa64[1] = dst->fa64[0] + dst->fa64[1];
}

void haddps(XMM *src, XMM *dst, XMM *res)
{
    res->fa32[0] = src->fa32[0] + src->fa32[1];
    res->fa32[1] = src->fa32[2] + src->fa32[3];
    res->fa32[2] = dst->fa32[0] + dst->fa32[1];
    res->fa32[3] = dst->fa32[2] + dst->fa32[3];
}

void hsubpd(XMM *src, XMM *dst, XMM *res)
{
    res->fa64[0] = src->fa64[0] - src->fa64[1];
    res->fa64[1] = dst->fa64[0] - dst->fa64[1];
}

void hsubps(XMM *src, XMM *dst, XMM *res)
{
    res->fa32[0] = src->fa32[0] - src->fa32[1];
    res->fa32[1] = src->fa32[2] - src->fa32[3];
    res->fa32[2] = dst->fa32[0] - dst->fa32[1];
    res->fa32[3] = dst->fa32[2] - dst->fa32[3];
}

void lddqu(XMM *src, XMM *res)
{
    res->fa64[0] = src->fa64[0];
    res->fa64[1] = src->fa64[1];
}

void movddup(XMM *src, XMM *res)
{
    res->fa64[0] = src->fa64[0];
    res->fa64[1] = src->fa64[0];
}

void movshdup(XMM *src, XMM *res)
{
    res->fa32[0] = src->fa32[1];
    res->fa32[1] = src->fa32[1];
    res->fa32[2] = src->fa32[3];
    res->fa32[3] = src->fa32[3];
}

void movsldup(XMM *src, XMM *res)
{
    res->fa32[0] = src->fa32[0];
    res->fa32[1] = src->fa32[0];
    res->fa32[2] = src->fa32[2];
    res->fa32[3] = src->fa32[2];
}


/***************************************/
/** SSSE3 instructions implementation **/
/***************************************/

//#define SATSW(x) ((x > 32767)? 32767 : ((x < -32768)? -32768 : x) )
/*static inline int SATSW(int x)
{
    if (x < -32768)
        return -32768;
    else if (x > 32767)
        return 32767;
    else
        return x;
}
*/

static short
signed_saturate_to_word (int x)
{
	if (x > (int) 0x7fff)
		return 0x7fff;
	if (x < (int) 0xffff8000)
		return 0x8000;
	return (short) x;
}


/** complex byte shuffle **/
void pshufb128(XMM *src, XMM *dst, XMM *res)
{
    int i;
	
	for (i = 0; i < 16; i++)
    {
		if (src->a8[i] & 0x80)
			res->a8[i] = 0;
		else
			res->a8[i] = dst->a8[src->a8[i] & 0xf];
    }
}

void pshufb64(MM *src, MM *dst, MM *res)
{
    int i;
	
	for (i = 0; i < 8; i++){
		if (src->ua8[i] & 0x80){
			res->ua8[i] =  0;
		}
		else
		{
			res->ua8[i] = dst->ua8[src->ua8[i] & 0x07];
		}
	}
}

/** packed horizontal add word **/
void phaddw128(XMM *src, XMM *dst, XMM *res)
{
	
	
	int i;
	
	for (i = 0; i < 4; i++)
		res->a16[i] = dst->a16[2 * i] + dst->a16[2 * i + 1];
	
	for (i = 0; i < 4; i++)
		res->a16[i + 4] = src->a16[2 * i] + src->a16[2 * i + 1];
	
}

void phaddw64(MM *src, MM *dst, MM *res)
{
    res->a16[0] = dst->a16[0] + dst->a16[1];
    res->a16[1] = dst->a16[2] + dst->a16[3];
    res->a16[2] = src->a16[0] + src->a16[1];
    res->a16[3] = src->a16[2] + src->a16[3];
}

/** packed horizontal add double **/
void phaddd128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 2; ++i) {
        res->a32[i  ] = dst->a32[2*i] + dst->a32[2*i+1];
    }
    for(i = 0; i < 2; ++i)
        res->a32[i+2] = src->a32[2*i] + src->a32[2*i+1];
}

void phaddd64(MM *src, MM *dst, MM *res)
{
    res->a32[0] = dst->a32[0] + dst->a32[1];
    res->a32[1] = src->a32[0] + src->a32[1];
}

/** packed horizontal add and saturate word **/
void phaddsw128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 4; ++i)
        res->a16[i] = signed_saturate_to_word( dst->a16[2*i] + dst->a16[2*i+1] );
    for(i = 0; i < 4; ++i)
        res->a16[i+4] = signed_saturate_to_word( src->a16[2*i] + src->a16[2*i+1] );
}

void phaddsw64(MM *src, MM *dst, MM *res)
{
	res->a16[0] = signed_saturate_to_word( dst->a16[0] + dst->a16[1] );
    res->a16[1] = signed_saturate_to_word( dst->a16[2] + dst->a16[3] );
    res->a16[2] = signed_saturate_to_word( src->a16[0] + src->a16[1] );
    res->a16[3] = signed_saturate_to_word( src->a16[2] + src->a16[3] );
    
}

/** multiply and add packed signed and unsigned bytes **/
void pmaddubsw128(XMM *src, XMM *dst, XMM *res)
{
	
	
	int t0;
	int i;
	for (i = 0; i < 8; i++)
    {
		t0 = ((int) dst->ua8[2 * i] * (int) src->a8[2 * i] +
			  (int) dst->ua8[2 * i + 1] * (int) src->a8[2 * i + 1]);
		res->a16[i] = signed_saturate_to_word (t0);
    }
}


void pmaddubsw64(MM *src, MM *dst, MM *res)
{
    int t0;
	int i;
	for (i = 0; i < 4; i++)
    {
		t0 = ((int) dst->ua8[2 * i] * (int) src->a8[2 * i] +
			  (int) dst->ua8[2 * i + 1] * (int) src->a8[2 * i + 1]);
		res->a16[i] = signed_saturate_to_word (t0);
    }
	
}

/** packed horizontal subtract word **/
void phsubw128(XMM *src, XMM *dst, XMM *res)
{
	
	int i;
	for (i = 0; i < 4; i++)
		res->a16[i] = dst->a16[2 * i] - dst->a16[2 * i + 1];
	for (i = 0; i < 4; i++)
		res->a16[i + 4] = src->a16[2 * i] - src->a16[2 * i + 1];
	}

void phsubw64(MM *src, MM *dst, MM *res)
{
    res->a16[0] = dst->a16[0] - dst->a16[1];
    res->a16[1] = dst->a16[2] - dst->a16[3];
    res->a16[2] = src->a16[0] - src->a16[1];
    res->a16[3] = src->a16[2] - src->a16[3];
}

/** packed horizontal subtract double **/
void phsubd128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 2; i++)
        res->a32[i  ] = dst->a32[2*i] - dst->a32[2*i+1];
    for(i = 0; i < 2; i++)
        res->a32[i+2] = src->a32[2*i] - src->a32[2*i+1];
}

void phsubd64(MM *src, MM *dst, MM *res)
{
    res->a32[0] = dst->a32[0] - dst->a32[1];
    res->a32[1] = src->a32[0] - src->a32[1];
}

/** packed horizontal subtract and saturate word **/
void phsubsw128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 4; i++)
        res->a16[i] = signed_saturate_to_word( dst->a16[2*i] - dst->a16[2*i+1] );
    for(i = 0; i < 4; i++)
        res->a16[i+4] = signed_saturate_to_word( src->a16[2*i] - src->a16[2*i+1] );
}

void phsubsw64(MM *src, MM *dst, MM *res)
{
	res->a16[0] = signed_saturate_to_word( dst->a16[0] - dst->a16[1] );
    res->a16[1] = signed_saturate_to_word( dst->a16[2] - dst->a16[3] );
    res->a16[2] = signed_saturate_to_word( src->a16[0] - src->a16[1] );
    res->a16[3] = signed_saturate_to_word( src->a16[2] - src->a16[3] );
    
}

/** packed sign byte **/
void psignb128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 16; i++) {
        if(src->a8[i] < 0) res->a8[i] = -dst->a8[i];
        else if(src->a8[i] == 0) res->a8[i] = 0;
        else res->a8[i] = dst->a8[i];
    }
}

void psignb64(MM *src, MM *dst, MM *res)
{
    int i;
    for(i = 0; i < 8; i++) {
        if(src->a8[i] < 0) res->a8[i] = -dst->a8[i];
        else if(src->a8[i] == 0) res->a8[i] = 0;
        else res->a8[i] = dst->a8[i];
    }
}

/** packed sign word **/
void psignw128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 8; i++) {
        if(src->a16[i] < 0) res->a16[i] = -dst->a16[i];
        else if(src->a16[i] == 0) res->a16[i] = 0;
        else res->a16[i] = dst->a16[i];
    }
}

void psignw64(MM *src, MM *dst, MM *res)
{
    int i;
    for(i = 0; i < 4; i++) {
        if(src->a16[i] < 0) res->a16[i] = -dst->a16[i];
        else if(src->a16[i] == 0) res->a16[i] = 0;
        else res->a16[i] = dst->a16[i];
    }
}

/** packed sign double **/
void psignd128(XMM *src, XMM *dst, XMM *res)
{
    int i;
    for(i = 0; i < 4; i++) {
        if(src->a32[i] < 0) res->a32[i] = -dst->a32[i];
        else if(src->a32[i] == 0) res->a32[i] = 0;
        else res->a32[i] = dst->a32[i];
    }
}

void psignd64(MM *src, MM *dst, MM *res)
{
    int i;
    for(i = 0; i < 2; i++) {
        if(src->a32[i] < 0) res->a32[i] = -dst->a32[i];
        else if(src->a32[i] == 0) res->a32[i] = 0;
        else res->a32[i] = dst->a32[i];
    }
}

/** packed multiply high with round and scale word **/
void pmulhrsw128(XMM *src, XMM *dst, XMM *res)
{
	int t0;
	int i;
	for (i = 0; i < 8; i++)
    {
		t0 = (((int) dst->a16[i] * (int) src->a16[i]) >> 14) + 1;
		res->a16[i] = (short) (t0 >> 1);
    }
   
}

void pmulhrsw64(MM *src, MM *dst, MM *res)
{
	int t0;
	int i;
	for (i = 0; i < 4; i++)
    {
		t0 = (((int) dst->a16[i] * (int) src->a16[i]) >> 14) + 1;
		res->a16[i] = (short) (t0 >> 1);
    }
    
}

/** packed absolute value byte **/
void pabsb128(XMM *src, XMM *res)
{
    int i;
    for(i = 0; i < 16; i++)
        if(src->a8[i] < 0) res->a8[i] = -src->a8[i];
        else res->a8[i] = src->a8[i];
}

void pabsb64(MM *src, MM *res)
{
    int i;
    for(i = 0; i < 8; i++)
        if(src->a8[i] < 0) res->a8[i] = -src->a8[i];
        else res->a8[i] = src->a8[i];
}

/** packed absolute value word **/
void pabsw128(XMM *src, XMM *res)
{
    int i;
    for(i = 0; i < 8; i++)
        if(src->a16[i] < 0) res->a16[i] = -src->a16[i];
        else res->a16[i] = src->a16[i];
}

void pabsw64(MM *src, MM *res)
{
    int i;
    for(i = 0; i < 4; i++)
        if(src->a16[i] < 0) res->a16[i] = -src->a16[i];
        else res->a16[i] = src->a16[i];
}

/** packed absolute value double **/
void pabsd128(XMM *src, XMM *res)
{
    int i;
    for(i = 0; i < 4; i++)
        if(src->a32[i] < 0) res->a32[i] = -src->a32[i];
        else res->a32[i] = src->a32[i];
}

void pabsd64(MM *src, MM *res)
{
    int i;
    for(i = 0; i < 2; i++)
        if(src->a32[i] < 0) res->a32[i] = -src->a32[i];
        else res->a32[i] = src->a32[i];
}

/** packed align right **/
void palignr128(XMM *src, XMM *dst, XMM *res, uint8_t IMM)
{
    
    char buf [32];
    int i;
    
    memcpy (&buf[0], src->a32, 16);
    memcpy (&buf[16], dst->a32, 16);
    
    for (i = 0; i < 16; i++)
        if (IMM >= 32 || IMM + i >= 32)
            res->a8[i] = 0;
        else
            res->a8[i] = buf[IMM + i];
	
	

}

void palignr64(MM *src, MM *dst, MM *res, uint8_t IMM)
{
	char buf [16];
    int i;
    
    /* Handle the first half */
    memcpy (&buf[0], src->a32, 8);
    memcpy (&buf[8], dst->a32, 8);
    
    for (i = 0; i < 8; i++)
        if (IMM >= 16 || IMM + i >= 16)
            res->a8[i] = 0;
        else
            res->a8[i] = buf[IMM + i];
    
    /* Handle the second half */
    memcpy (&buf[0], &src->a32[2], 8);
    memcpy (&buf[8], &dst->a32[2], 8);
    
    for (i = 0; i < 8; i++)
        if (IMM >= 16 || IMM + i >= 16)
            res->a8[i + 8] = 0;
        else
            res->a8[i + 8] = buf[IMM + i];
	
	
   }