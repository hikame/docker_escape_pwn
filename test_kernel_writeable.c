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
    unsigned long start = atol(argv[1]);
    unsigned long end = atol(argv[2]);
	syscall(SYS_check_kernel_mem, start, end);
}