#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SYS_check_kernel_mem 548

int main(int argc, char** argv) {
    if(argc != 3){
        printf("Wrong argvs, exit...\n");
        return -1;
    }
    unsigned long start = strtoul(argv[1], 0, 16);
    unsigned long end = strtoul(argv[2], 0, 16);
    if(start == 0 || end == 0){
        printf("Invalid argvs, exit...\n");
        return -1;
    }

	syscall(SYS_check_kernel_mem, start, end);
}