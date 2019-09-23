#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/socket.h>
#include <netinet/ip.h>
#include <sys/klog.h>
#include <sys/mman.h>
#include <sys/utsname.h>

#include "./kernel_infos.h"

#define ENABLE_KASLR_BYPASS		1
#define ENABLE_SMEP_BYPASS		1

#if ENABLE_KASLR_BYPASS
#include "./kaslr_bypass.h"
#endif

#if ENABLE_SMEP_BYPASS
#include "./smep_bypass.h"
#endif