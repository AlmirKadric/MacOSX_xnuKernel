/*
 * Copyright (c) 2005-2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

/*
 *	File:		i386/tsc.c
 *	Purpose:	Initializes the TSC and the various conversion
 *			factors needed by other parts of the system.
 */

#include <platforms.h>

#include <mach/mach_types.h>

#include <kern/cpu_data.h>
#include <kern/cpu_number.h>
#include <kern/clock.h>
#include <kern/host_notify.h>
#include <kern/macro_help.h>
#include <kern/misc_protos.h>
#include <kern/spl.h>
#include <kern/assert.h>
#include <mach/vm_prot.h>
#include <vm/pmap.h>
#include <vm/vm_kern.h>		/* for kernel_map */
#include <architecture/i386/pio.h>
#include <i386/machine_cpu.h>
#include <i386/cpuid.h>
#include <i386/mp.h>
#include <i386/machine_routines.h>
#include <i386/proc_reg.h>
#include <i386/tsc.h>
#include <i386/misc_protos.h>
#include <pexpert/pexpert.h>
#include <machine/limits.h>
#include <machine/commpage.h>
#include <sys/kdebug.h>
#include <pexpert/device_tree.h>

uint64_t	busFCvtt2n = 0;
uint64_t	busFCvtn2t = 0;
uint64_t	tscFreq = 0;
uint64_t	tscFCvtt2n = 0;
uint64_t	tscFCvtn2t = 0;
uint64_t	tscGranularity = 0;
uint64_t	bus2tsc = 0;
uint64_t	busFreq = 0;
uint32_t	flex_ratio = 0;
uint32_t	flex_ratio_min = 0;
uint32_t	flex_ratio_max = 0;

uint64_t	tsc_at_boot = 0;
uint64_t cpuFreqCOF = 0;

#define bit(n)		(1ULL << (n))
#define bitmask(h,l)	((bit(h)|(bit(h)-1)) & ~(bit(l)-1))
#define bitfield(x,h,l)	(((x) & bitmask(h,l)) >> l)

/* Decimal powers: */
#define kilo (1000ULL)
#define Mega (kilo * kilo)
#define Giga (kilo * Mega)
#define Tera (kilo * Giga)
#define Peta (kilo * Tera)

#define CPU_FAMILY_PENTIUM_M	(0x6)

static const char	FSB_Frequency_prop[] = "FSBFrequency";
static const char	TSC_at_boot_prop[]   = "InitialTSC";
static const char  FSB_CPUFrequency_prop[] = "CPUFrequency";


static  uint64_t cpuMultAmd(void);
static  uint64_t cpuFreqAmd(void);

static uint64_t
EFI_CPU_Frequency(void)
{
	uint64_t	frequency = 0;
	DTEntry		entry;
	void		*value;
	unsigned int	size;
	
	if (DTLookupEntry(0, "/efi/platform", &entry) != kSuccess) {
		kprintf("EFI_CPU_Frequency: didn't find /efi/platform\n");
		return 0;
	}
	if (DTGetProperty(entry,FSB_CPUFrequency_prop,&value,&size) != kSuccess) {
		kprintf("EFI_CPU_Frequency: property %s not found\n",
				FSB_Frequency_prop);
		return 0;
	}
	if (size == sizeof(uint64_t)) {
		frequency = *(uint64_t *) value;
		kprintf("EFI_CPU_Frequency: read %s value: %llu\n",
				FSB_Frequency_prop, frequency);
		if (!(10*Mega < frequency && frequency < 50*Giga)) {
			kprintf("EFI_Fake_MSR: value out of range\n");
			frequency = 0;
		}
	} else {
		kprintf("EFI_CPU_Frequency: unexpected size %d\n", size);
	}
	return frequency;
}

/*
 * This routine extracts the bus frequency in Hz from the device tree.
 * Also reads any initial TSC value at boot from the device tree.
 */
static uint64_t
EFI_FSB_frequency(void)
{
	uint64_t	frequency = 0;
	DTEntry		entry;
	void		*value;
	unsigned int	size;

    if (IsIntelCPU())
	{
		
		int  res;
		if (PE_parse_boot_argn("fsb", &res,sizeof(res))) return res * Mega;
        
	if (DTLookupEntry(0, "/efi/platform", &entry) != kSuccess) {
		kprintf("EFI_FSB_frequency: didn't find /efi/platform\n");
		return 0;
	}
	if (DTGetProperty(entry,FSB_Frequency_prop,&value,&size) != kSuccess) {
		kprintf("EFI_FSB_frequency: property %s not found\n",
			FSB_Frequency_prop);
		return 0;
	}
	if (size == sizeof(uint64_t)) {
		frequency = *(uint64_t *) value;
		kprintf("EFI_FSB_frequency: read %s value: %llu\n",
			FSB_Frequency_prop, frequency);
		if (!(90*Mega < frequency && frequency < 10*Giga)) {
			kprintf("EFI_FSB_frequency: value out of range\n");
			frequency = 0;
		}
	} else {
		kprintf("EFI_FSB_frequency: unexpected size %d\n", size);
	}
        
        /*
         * While we're here, see if EFI published an initial TSC value.
         */
        if (DTGetProperty(entry,TSC_at_boot_prop,&value,&size) == kSuccess) {
            if (size == sizeof(uint64_t)) {
                tsc_at_boot = *(uint64_t *) value;
                kprintf("EFI_FSB_frequency: read %s value: %llu\n",
                        TSC_at_boot_prop, tsc_at_boot);
            }
        }
    }
    
    if (IsAmdCPU())
	{
		int  res;
		uint64_t cpuMult,cpuMultN2,Mult_N2;
		uint64_t cpuFreq,cpuFreqN2,cpuFreq_NT;
		
		
		if (PE_parse_boot_argn("fsb", &res,sizeof(res))) return res * Mega;
		
		cpuMult	= cpuMultAmd();
		cpuFreq = cpuFreqAmd();
		
		switch (cpuid_info()->cpuid_family) {
			case 0xF:
			{
				
				uint64_t prfsts;
				prfsts	= rdmsr64(AMD_PERF_STS);
				cpuMultN2 = (prfsts & bit(0)) != 0;
			}
				break;
			default :
			{
				uint64_t prfsts;
				prfsts = rdmsr64(AMD_COFVID_STS);
				cpuMultN2 = (prfsts & bit(0)) != 0;
			}
				break;
				
		}
		
		
		if(cpuMultN2)
		{
			printf("FSB Detection: from BIOS calculated Mult_N2 %llu, cpuFreq %lld \n", cpuMult, cpuFreq);
			
			cpuFreqN2 = ((1 * Giga)  << 32) / (cpuFreq) ;
			cpuFreq_NT = cpuFreqN2 * 2  /(100*(1+2*cpuMult));
			Mult_N2 =  cpuFreqN2 /  cpuFreq_NT;
			
			frequency = ((1 * Giga) << 32) / cpuFreqN2 / ( Mult_N2 ) ;
			
			return frequency * 100;
		}
		//Else try to autodetect
		else{
			printf("FSB Detection: from BIOS calculated Mult %llu, cpuFreq %lld \n", cpuMult, cpuFreq);
			if (cpuMult == 0 || cpuFreq == 0)
			{
				//  if (DetectFSB_NonClocked()) return DetectFSB_NonClocked() * Mega;
				return frequency = 200 * Mega;
			}
			else
			{
				frequency = cpuFreq / cpuMult;
				if (frequency) return frequency;
				else return frequency = 200 * Mega;
			}
		}
	}
    
	

	return frequency;
}

typedef unsigned long long vlong;

static uint64_t cpuMultAmd(void)
{
	
	switch (cpuid_info()->cpuid_family) {
			
		case 0xF:
		{
			
			uint64_t CoolnQuiet = 0;
			uint32_t reg[4];
			uint64_t curMP;
			uint64_t prfsts;
			
			
			do_cpuid(0x80000007, reg);
			CoolnQuiet = ((reg[edx] & 0x6) == 0x6) ;
			if (CoolnQuiet)
			{
				prfsts	= rdmsr64(AMD_PERF_STS);
				printf("rtclock_init: Athlon's MSR 0x%x \n", AMD_PERF_STS);
				
				curMP = ((prfsts & 0x3F) + 8)/2;
				//printf("curMP:  0d \n", curMP);
				
				//Mhz = (800 + 200*((prfsts>>1) & 0x1f)) * 1000000ll;
				//printf("Mhz: %lld\n",  Mhz );
				cpuFreqCOF = curMP ;
				printf("cpuFreqCOF: %lld\n",  cpuFreqCOF );
			}
			else
			{
				prfsts = rdmsr64(0xC0010015);
				cpuFreqCOF = (uint32_t)bitfield(prfsts, 29, 24);
				
			}
			
		}
			break;
			
		case 0x10:
		case 0x11:
		{
			// 8:6 CpuDid: current core divisor ID
			// 5:0 CpuFid: current core frequency ID
			
			uint64_t prfsts,CpuFid,CpuDid;
			prfsts = rdmsr64(AMD_PSTATE0_STS);
			
			CpuDid = bitfield(prfsts, 8, 6) ;
			CpuFid = bitfield(prfsts, 5, 0) ;
			/*switch (CpuDid) {
			 case 0: divisor = 1; break;
			 case 1: divisor = 2; break;
			 case 2: divisor = 4; break;
			 case 3: divisor = 8; break;
			 case 4: divisor = 16; break;
			 default: divisor = 1; break;
			 }*/
			cpuFreqCOF = (CpuFid + 0x10) / (2^CpuDid);
		}
			break;
			
		case 0x15:
		case 0x16:
		case 0x06:
		{
			
			uint64_t prfsts,CpuFid,CpuDid;
			prfsts = rdmsr64(AMD_COFVID_STS);
			uint64_t prfsts_2 = rdmsr64(0xC0010066);
			CpuDid = bitfield(prfsts, 8, 6) & prfsts_2;
			CpuFid = bitfield(prfsts, 5, 0) & prfsts_2;
			
			cpuFreqCOF = (CpuFid + 0x10) / (2^CpuDid);
		}
			break;
		case 0x12: {
			// 8:4 CpuFid: current CPU core frequency ID
			// 3:0 CpuDid: current CPU core divisor ID
			uint64_t prfsts,CpuFid,CpuDid;
			prfsts = rdmsr64(AMD_COFVID_STS);
			
			CpuDid = bitfield(prfsts, 3, 0) ;
			CpuFid = bitfield(prfsts, 8, 4) ;
			uint64_t divisor;
			switch (CpuDid) {
				case 0: divisor = 1; break;
				case 1: divisor = (3/2); break;
				case 2: divisor = 2; break;
				case 3: divisor = 3; break;
				case 4: divisor = 4; break;
				case 5: divisor = 6; break;
				case 6: divisor = 8; break;
				case 7: divisor = 12; break;
				case 8: divisor = 16; break;
				default: divisor = 1; break;
			}
			cpuFreqCOF = (CpuFid + 0x10) / divisor;
			
		}
			break;
		case 0x14: {
			// 8:4: current CPU core divisor ID most significant digit
			// 3:0: current CPU core divisor ID least significant digit
			uint64_t prfsts;
			prfsts = rdmsr64(AMD_COFVID_STS);
			
			uint64_t CpuDidMSD,CpuDidLSD;
			CpuDidMSD = bitfield(prfsts, 8, 4) ;
			CpuDidLSD  = bitfield(prfsts, 3, 0) ;
			
			uint64_t frequencyId = 0x10;
			cpuFreqCOF = (frequencyId + 0x10) /
			(CpuDidMSD + (CpuDidLSD /4 /** 0.25*/) + 1);
		}
			break;
			
			
		default:
		{
			uint64_t prfsts;
			prfsts = rdmsr64(AMD_COFVID_STS);
			vlong hz,r;
			r = (prfsts>>6) & 0x07;
			hz = (((prfsts & 0x3f)+0x10)*100000000ll)/(1<<r);
			printf("family %hhu \n",cpuid_info()->cpuid_family);
			
			cpuFreqCOF = hz / (200 * Mega);
		}
			
	}
	return cpuFreqCOF;
}

static uint64_t cpuFreqAmd(void)
{
	uint64_t cpuFreqMhz;
	
	uint8_t  dummyvar;
	if (PE_parse_boot_argn("-cpuEFI", &dummyvar, sizeof(dummyvar))) return EFI_CPU_Frequency() ;
	
	switch (cpuid_info()->cpuid_family) {
		case 0xF:
		{
			
			uint64_t prfsts;
			prfsts	= rdmsr64(AMD_PERF_STS);
			cpuFreqMhz = (800 + 200*((prfsts>>1) & 0x1f)) * 1000000ll;
		}
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x14:
		{
			uint64_t prfsts,r;
			prfsts = rdmsr64(AMD_PSTATE0_STS);
			//CpuDid = bitfield(prfsts, 8, 6) ;
			//CpuFid = bitfield(prfsts, 5, 0) ;
			r = (prfsts>>6) & 0x07;
			cpuFreqMhz = (((prfsts & 0x3f)+0x10)*100000000ll)/(1<<r);
			//(100 * Mega) * ((CpuFid + 0x10) /(1^CpuDid));
		}
			break;
			
		case 0x15:
		case 0x16:
		case 0x6:
		{
			uint64_t prfsts,CpuDid,CpuFid;
			prfsts = rdmsr64(0xC0010066);
			CpuDid = bitfield(prfsts, 8, 6) ;
			CpuFid = bitfield(prfsts, 5, 0) ;
			cpuFreqMhz = (100 * Mega) * ((CpuFid + 0x10) >> (CpuDid));
		}
			break;
			
		default:
			return cpuFreqMhz = EFI_CPU_Frequency();
	}
	return cpuFreqMhz;
}

/*
 * Initialize the various conversion factors needed by code referencing
 * the TSC.
 */
void
tsc_init(void)
{
	boolean_t	N_by_2_bus_ratio = FALSE;

	if (cpuid_vmm_present()) {
		kprintf("VMM vendor %u TSC frequency %u KHz bus frequency %u KHz\n",
				cpuid_vmm_info()->cpuid_vmm_family,
				cpuid_vmm_info()->cpuid_vmm_tsc_frequency,
				cpuid_vmm_info()->cpuid_vmm_bus_frequency);

		if (cpuid_vmm_info()->cpuid_vmm_tsc_frequency &&
			cpuid_vmm_info()->cpuid_vmm_bus_frequency) {

			busFreq = (uint64_t)cpuid_vmm_info()->cpuid_vmm_bus_frequency * kilo;
			busFCvtt2n = ((1 * Giga) << 32) / busFreq;
			busFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / busFCvtt2n;
			
			tscFreq = (uint64_t)cpuid_vmm_info()->cpuid_vmm_tsc_frequency * kilo;
			tscFCvtt2n = ((1 * Giga) << 32) / tscFreq;
			tscFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / tscFCvtt2n;
			
			tscGranularity = tscFreq / busFreq;
			
			bus2tsc = tmrCvt(busFCvtt2n, tscFCvtn2t);

			return;
		}
	}

	/*
	 * Get the FSB frequency and conversion factors from EFI.
	 */
	busFreq = EFI_FSB_frequency();

	if (IsIntelCPU())
	{
    
    switch (cpuid_cpufamily()) {
	case CPUFAMILY_INTEL_HASWELL:
	case CPUFAMILY_INTEL_IVYBRIDGE:
	case CPUFAMILY_INTEL_SANDYBRIDGE:
	case CPUFAMILY_INTEL_WESTMERE:
	case CPUFAMILY_INTEL_NEHALEM: {
		uint64_t msr_flex_ratio;
		uint64_t msr_platform_info;

		/* See if FLEX_RATIO is being used */
		msr_flex_ratio = rdmsr64(MSR_FLEX_RATIO);
		msr_platform_info = rdmsr64(MSR_PLATFORM_INFO);
		flex_ratio_min = (uint32_t)bitfield(msr_platform_info, 47, 40);
		flex_ratio_max = (uint32_t)bitfield(msr_platform_info, 15, 8);
		/* No BIOS-programed flex ratio. Use hardware max as default */
		tscGranularity = flex_ratio_max;
		if (msr_flex_ratio & bit(16)) {
		 	/* Flex Enabled: Use this MSR if less than max */
			flex_ratio = (uint32_t)bitfield(msr_flex_ratio, 15, 8);
			if (flex_ratio < flex_ratio_max)
				tscGranularity = flex_ratio;
		}

		/* If EFI isn't configured correctly, use a constant 
		 * value. See 6036811.
		 */
		if (busFreq == 0)
		    busFreq = BASE_NHM_CLOCK_SOURCE;

        if (PE_parse_boot_argn("busratio", &tscGranularity, sizeof(tscGranularity)))
        {
            if (tscGranularity == 0) tscGranularity = 1; // avoid div by zero
            N_by_2_bus_ratio = (tscGranularity > 30) && ((tscGranularity % 10) != 0);
            if (N_by_2_bus_ratio) tscGranularity /= 10; // Scale it back to normal
        }
        
		break;
            }
            break;
            switch (cpuid_info()->cpuid_family) {
                    
                case 0x6:
                {
                    if (cpuid_info()->cpuid_model >= 0xD)
                    {
                        uint64_t prfsts = 0;
                        prfsts = rdmsr64(IA32_PERF_STS);
                        tscGranularity	= (uint32_t)bitfield(prfsts, 44, 40);
                        N_by_2_bus_ratio= (prfsts & bit(46))!=0;
                    }
                    if (PE_parse_boot_argn("busratio", &tscGranularity, sizeof(tscGranularity)))
                    {
                        if (tscGranularity == 0) tscGranularity = 1; // avoid div by zero
                        N_by_2_bus_ratio = (tscGranularity > 30) && ((tscGranularity % 10) != 0);
                        if (N_by_2_bus_ratio) tscGranularity /= 10; // Scale it back to normal
                    }
                }
                    break;
                    
                case 15:
                {
                    if (cpuid_info()->cpuid_model == CPU_MODEL_PENTIUM_4)
                    {
                        
                        //busFreq = EFI_FSB_frequency();
                        uint64_t prfsts = 0;
                        prfsts = rdmsr64(IA32_PERF_STS);
                        tscGranularity	= (uint32_t)bitfield(prfsts, 44, 40);
                        N_by_2_bus_ratio= (prfsts & bit(46))!=0;
                        
                    }
                    
                    else
                    {
                        if (cpuid_info()->cpuid_model == CPU_MODEL_PENTIUM_4_M2)
                        {
                            uint64_t prfsts = 0;
                            prfsts		= rdmsr64(0x2C); // TODO: Add to header
                            tscGranularity	= bitfield(prfsts, 31, 24);
                        }
                    }
                    if (PE_parse_boot_argn("busratio", &tscGranularity, sizeof(tscGranularity)))
                    {
                        if (tscGranularity == 0) tscGranularity = 1; // avoid div by zero
                        N_by_2_bus_ratio = (tscGranularity > 30) && ((tscGranularity % 10) != 0);
                        if (N_by_2_bus_ratio) tscGranularity /= 10; // Scale it back to normal
                    }
                }
                    break;
            }
            break;
            
            
	default: {
		uint64_t	prfsts;

		prfsts = rdmsr64(IA32_PERF_STS);
		tscGranularity = (uint32_t)bitfield(prfsts, 44, 40);
		N_by_2_bus_ratio = (prfsts & bit(46)) != 0;
	    }
	}
    }
    
    if (IsAmdCPU())
	{
		uint64_t prfsts;
		
		switch (cpuid_info()->cpuid_family) {
			case 0xF:
			{
				prfsts	= rdmsr64(AMD_PERF_STS);
			}
				break;
			default :
			{
				prfsts = rdmsr64(AMD_COFVID_STS);
			}
		}
		
		if (PE_parse_boot_argn("busratio", &tscGranularity, sizeof(tscGranularity)))
		{
			if (tscGranularity == 0) tscGranularity = 1; // avoid div by zero
			N_by_2_bus_ratio = (tscGranularity > 30) && ((tscGranularity % 10) != 0);
			if (N_by_2_bus_ratio) tscGranularity /= 10; // Scale it back to normal
		}
		else
		{
			N_by_2_bus_ratio = (prfsts & bit(0)) != 0;
			tscGranularity = cpuMultAmd();
			
			if (tscGranularity == 0) tscGranularity = 1;
			
			
			if(!N_by_2_bus_ratio)
			{
				N_by_2_bus_ratio = (tscGranularity > 30) && ((tscGranularity % 10) != 0);
				if (N_by_2_bus_ratio) tscGranularity /= 10; // Scale it back to normal
				
			}
		}
		
	}
    
	if (busFreq != 0) {
		busFCvtt2n = ((1 * Giga) << 32) / busFreq;
		busFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / busFCvtt2n;
	} else {
		panic("tsc_init: EFI not supported!\n");
	}

	kprintf(" BUS: Frequency = %6d.%06dMHz, "
		"cvtt2n = %08X.%08X, cvtn2t = %08X.%08X\n",
		(uint32_t)(busFreq / Mega),
		(uint32_t)(busFreq % Mega), 
		(uint32_t)(busFCvtt2n >> 32), (uint32_t)busFCvtt2n,
		(uint32_t)(busFCvtn2t >> 32), (uint32_t)busFCvtn2t);

	/*
	 * Get the TSC increment.  The TSC is incremented by this
	 * on every bus tick.  Calculate the TSC conversion factors
	 * to and from nano-seconds.
	 * The tsc granularity is also called the "bus ratio". If the N/2 bit
	 * is set this indicates the bus ration is 0.5 more than this - i.e.
	 * that the true bus ratio is (2*tscGranularity + 1)/2. If we cannot
	 * determine the TSC conversion, assume it ticks at the bus frequency.
	 */
	if (tscGranularity == 0)
		tscGranularity = 1;

	if (N_by_2_bus_ratio)
		tscFCvtt2n = busFCvtt2n * 2 / (1 + 2*tscGranularity);
	else
		tscFCvtt2n = busFCvtt2n / tscGranularity;

	tscFreq = ((1 * Giga)  << 32) / tscFCvtt2n;
	tscFCvtn2t = 0xFFFFFFFFFFFFFFFFULL / tscFCvtt2n;

	kprintf(" TSC: Frequency = %6d.%06dMHz, "
		"cvtt2n = %08X.%08X, cvtn2t = %08X.%08X, gran = %lld%s\n",
		(uint32_t)(tscFreq / Mega),
		(uint32_t)(tscFreq % Mega), 
		(uint32_t)(tscFCvtt2n >> 32), (uint32_t)tscFCvtt2n,
		(uint32_t)(tscFCvtn2t >> 32), (uint32_t)tscFCvtn2t,
		tscGranularity, N_by_2_bus_ratio ? " (N/2)" : "");

	/*
	 * Calculate conversion from BUS to TSC
	 */
	bus2tsc = tmrCvt(busFCvtt2n, tscFCvtn2t);
}

void
tsc_get_info(tscInfo_t *info)
{
	info->busFCvtt2n     = busFCvtt2n;
	info->busFCvtn2t     = busFCvtn2t;
	info->tscFreq        = tscFreq;
	info->tscFCvtt2n     = tscFCvtt2n;
	info->tscFCvtn2t     = tscFCvtn2t;
	info->tscGranularity = tscGranularity;
	info->bus2tsc        = bus2tsc;
	info->busFreq        = busFreq;
	info->flex_ratio     = flex_ratio;
	info->flex_ratio_min = flex_ratio_min;
	info->flex_ratio_max = flex_ratio_max;
}
