obj-m = hello.o

all: pwn hello.ko mitigation_bypass/kaslr_bypass tkw

pwn: pwn.c pwn.h kaslr_bypass.h kernel_infos.h smep_bypass.h toolset.h test.h docker_escape.h
	gcc -g ./pwn.c -o ./pwn -lpthread

tkw: test_kernel_writeable.c
	gcc -g ./test_kernel_writeable.c -o ./tkw

hello.ko: hello.c
	make -C /lib/modules/$(shell uname -r)/build/ M=$(PWD) modules

mitigation_bypass/kaslr_bypass:
	gcc ./mitigation_bypass/kaslr_bypass.c -o ./mitigation_bypass/kaslr_bypass

clean:
	rm -rf ./pwn ./hello.ko ./hello.mod.c ./hello.mod.o ./hello.o ./mitigation_bypass/kaslr_bypass tkw