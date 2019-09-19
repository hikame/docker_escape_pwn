/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ARM_KVM_ASM_H__
#define __ARM_KVM_ASM_H__

#include <asm/virt.h>

#define ARM_EXIT_WITH_SERROR_BIT  31
#define ARM_EXCEPTION_CODE(x)	  ((x) & ~(1U << ARM_EXIT_WITH_SERROR_BIT))
#define ARM_SERROR_PENDING(x)	  !!((x) & (1U << ARM_EXIT_WITH_SERROR_BIT))

#define ARM_EXCEPTION_IRQ	  0
#define ARM_EXCEPTION_EL1_SERROR  1
#define ARM_EXCEPTION_TRAP	  2
/* The hyp-stub will return this for any kvm_call_hyp() call */
#define ARM_EXCEPTION_HYP_GONE	  HVC_STUB_ERR

#define KVM_ARM64_DEBUG_DIRTY_SHIFT	0
#define KVM_ARM64_DEBUG_DIRTY		(1 << KVM_ARM64_DEBUG_DIRTY_SHIFT)

#define	VCPU_WORKAROUND_2_FLAG_SHIFT	0
#define	VCPU_WORKAROUND_2_FLAG		(_AC(1, UL) << VCPU_WORKAROUND_2_FLAG_SHIFT)

/* Translate a kernel address of @sym into its equivalent linear mapping */
#define kvm_ksym_ref(sym)						\
	({								\
		void *val = &sym;					\
		if (!is_kernel_in_hyp_mode())				\
			val = phys_to_virt((u64)&sym - kimage_voffset);	\
		val;							\
	 })

#ifndef __ASSEMBLY__
struct kvm;
struct kvm_vcpu;

extern char __kvm_hyp_init[];
extern char __kvm_hyp_init_end[];

extern char __kvm_hyp_vector[];

extern void __kvm_flush_vm_context(void);
extern void __kvm_tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa);
extern void __kvm_tlb_flush_vmid(struct kvm *kvm);
extern void __kvm_tlb_flush_local_vmid(struct kvm_vcpu *vcpu);

extern void __kvm_timer_set_cntvoff(u32 cntvoff_low, u32 cntvoff_high);

extern int __kvm_vcpu_run(struct kvm_vcpu *vcpu);

extern u64 __vgic_v3_get_ich_vtr_el2(void);
extern u64 __vgic_v3_read_vmcr(void);
extern void __vgic_v3_write_vmcr(u32 vmcr);
extern void __vgic_v3_init_lrs(void);

extern u32 __kvm_get_mdcr_el2(void);

extern u32 __init_stage2_translation(void);

extern void __qcom_hyp_sanitize_btac_predictors(void);

/* Home-grown __this_cpu_{ptr,read} variants that always work at HYP */
#define __hyp_this_cpu_ptr(sym)						\
	({								\
		void *__ptr = hyp_symbol_addr(sym);			\
		__ptr += read_sysreg(tpidr_el2);			\
		(typeof(&sym))__ptr;					\
	 })

#define __hyp_this_cpu_read(sym)					\
	({								\
		*__hyp_this_cpu_ptr(sym);				\
	 })

#else /* __ASSEMBLY__ */

.macro hyp_adr_this_cpu reg, sym, tmp
	adr_l	\reg, \sym
	mrs	\tmp, tpidr_el2
	add	\reg, \reg, \tmp
.endm

.macro hyp_ldr_this_cpu reg, sym, tmp
	adr_l	\reg, \sym
	mrs	\tmp, tpidr_el2
	ldr	\reg,  [\reg, \tmp]
.endm

.macro get_host_ctxt reg, tmp
	hyp_adr_this_cpu \reg, kvm_host_cpu_state, \tmp
.endm

.macro get_vcpu_ptr vcpu, ctxt
	get_host_ctxt \ctxt, \vcpu
	ldr	\vcpu, [\ctxt, #HOST_CONTEXT_VCPU]
	kern_hyp_va	\vcpu
.endm

#endif

#endif /* __ARM_KVM_ASM_H__ */
