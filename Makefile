obj-m = hello.o

all: pwn hello.ko

pwn: pwn.c pwn.h kaslr_bypass.h kernel_infos.h smep_bypass.h toolset.h test.h docker_escape.h
	gcc -g ./pwn.c -o ./pwn

hello.ko: hello.c
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

clean:
	rm -rf ./pwn ./hello.ko ./hello.mod.c ./hello.mod.o ./hello.o