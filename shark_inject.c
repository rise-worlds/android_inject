#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <android/log.h>
#include <sys/uio.h>

#if defined(__i386__) || defined(__x86_64__)
#define pt_regs         user_regs_struct
#elif defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs	regs
#define ARM_pc	pc
#define ARM_sp	sp
#define ARM_cpsr	pstate
#define ARM_lr		regs[30]
#define ARM_r0		regs[0]
#define PTRACE_GETREGS PTRACE_GETREGSET
#define PTRACE_SETREGS PTRACE_SETREGSET
#endif

#define CPSR_T_MASK     ( 1u << 5 )

#if defined(__aarch64__) || defined(__x86_64__)
const char *libc_path = "/system/lib64/libc.so";
const char *linker_path = "/system/bin/linker64";
#elif defined(__arm__) || defined(__i386__)
const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";
#endif

//读取进程数据
int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size) {
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = buf;

    for (i = 0; i < j; i++) {
        //拷贝src指向的数据
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

//往进程写入数据
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size) {
    uint32_t i, j, remain;
    uint8_t *laddr;

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / 4;
    remain = size % 4;

    laddr = data;

    for (i = 0; i < j; i++) {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest += 4;
        laddr += 4;
    }

    if (remain > 0) {
        for (i = 0; i < remain; i++) {
            d.chars[i] = *laddr++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

#if defined(__arm__) || defined(__aarch64__)
int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs)
{
    uint32_t i;
#if defined(__arm__)
    int num_param_registers = 4;
#elif defined(__aarch64__)
    int num_param_registers = 8;
#endif
    //前4个参数放入寄存器
    for (i = 0; i < num_params && i < num_param_registers; i ++) {
        regs->uregs[i] = params[i];
    }

    //后面的参数从右往左依次入栈
    if (i < num_params) {
        //栈空间大小
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        //写入栈中
        ptrace_writedata(pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    //那么如何notify进程我们mmp执行完了。就是通过下面这句话。
    //原因是当函数调用时候，当我们使用bl或者bx，链接寄存器指向的是下一条返回地址，
    //如果把下条返回地址赋值成0，返回时候pc=0，就会产生异常。相当于一个notify，
    //然后用下面那个waitpid得到异常模式，确定mmp执行完。所以其实下面不一定是0，只要是无效即可。
    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue(pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#elif defined(__i386__)
long ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->esp -= (num_params) * sizeof(long) ;
    ptrace_writedata(pid, (void *)regs->esp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->esp -= sizeof(long);
    ptrace_writedata(pid, regs->esp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->eip = addr;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#elif  defined(__x86_64__)
long ptrace_call(pid_t pid, uint64_t addr, long *params, uint32_t num_params, struct user_regs_struct * regs)
{
    regs->rsp -= (num_params) * sizeof(long) ;
    ptrace_writedata(pid, (void *)regs->rsp, (uint8_t *)params, (num_params) * sizeof(long));

    long tmp_addr = 0x00;
    regs->rsp -= sizeof(unsigned long);
    ptrace_writedata(pid, regs->rsp, (char *)&tmp_addr, sizeof(tmp_addr));

    regs->rip = addr;

    if (ptrace_setregs(pid, regs) == -1
            || ptrace_continue( pid) == -1) {
        printf("error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}
#endif


//读取进程寄存器数据
int ptrace_getregs(pid_t pid, struct pt_regs *regs) {
#if defined (__aarch64__)
        int regset = NT_PRSTATUS;
        struct iovec ioVec;

        ioVec.iov_base = regs;
        ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_getregs: Can not get register values");
        printf(" io %llx, %d\n", ioVec.iov_base, ioVec.iov_len);
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_getregs: Can not get register values\n");
        return -1;
    }

    return 0;
#endif
}

//设置进程寄存器
int ptrace_setregs(pid_t pid, struct pt_regs *regs) {
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("ptrace_setregs: Can not get register values\n");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("ptrace_setregs: Can not set register values\n");
        return -1;
    }

    return 0;
#endif
}

//进程继续指向
int ptrace_continue(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

//挂载到目标进程
int ptrace_attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status, WUNTRACED);

    return 0;
}

//从目标进程中卸载
int ptrace_detach(pid_t pid) {
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}

//获取目标进程模块基址
void *get_module_base(pid_t pid, const char *module_name) {
    FILE *fp;
    long addr = 0;
    char *pch;
    char filename[32];
    char line[1024];

    if (pid < 0) {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    } else {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    fp = fopen(filename, "r");

    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);

                if (addr == 0x8000)
                    addr = 0;

                break;
            }
        }

        fclose(fp);
    }

    return (void *) addr;
}

//获取远程模块基址
void *get_remote_addr(pid_t target_pid, const char *module_name, void *local_addr) {
    void *local_handle, *remote_handle;

    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(target_pid, module_name);

    printf("[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle);

    void *ret_addr = (void *) ((uint32_t) local_addr + (uint32_t) remote_handle - (uint32_t) local_handle);

#if defined(__i386__)
    if (!strcmp(module_name, libc_path)) {
        ret_addr += 2;
    }
#endif

    return ret_addr;
}


long ptrace_retval(struct pt_regs *regs) {
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_r0;
#elif defined(__x86_64__)
    return regs->rax;
#elif defined(__i386__)
    return regs->eax;
#endif
}

long ptrace_ip(struct pt_regs *regs) {
#if defined(__arm__) || defined(__aarch64__)
    return regs->ARM_pc;
#elif defined(__x86_64__)
    return regs->rip;
#elif defined(__i386__)
    return regs->eip;
#endif
}

int ptrace_call_wrapper(pid_t target_pid, const char *func_name, void *func_addr, long *parameters,
                        int param_num, struct pt_regs *regs) {
    printf("[+] Calling %s in target process.\n", func_name);
    if (ptrace_call(target_pid, func_addr, parameters, param_num, regs) == -1)
        return -1;

    if (ptrace_getregs(target_pid, regs) == -1)
        return -1;
    printf("[+] Target process returned from %s, return value=%x, pc=%x \n",
                func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

//注入远程进程数据
int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name,
                          const char *param, size_t param_size) {
    int ret = -1;
    void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *dlerror_addr;
    void *local_handle, *remote_handle, *dlhandle;
    uint8_t *map_base = 0;
    uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

    struct pt_regs regs, original_regs;
    extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
 _dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
 _saved_cpsr_s, _saved_r0_pc_s;

    uint32_t code_length;
    long parameters[10];

    printf("[+] Injecting process: %d\n", target_pid);
    //1.首先挂载到目标进程
    if (ptrace_attach(target_pid) == -1)
        goto exit;
    //2.读取目标进程寄存器数据
    if (ptrace_getregs(target_pid, &regs) == -1)
        goto exit;

    /*3.保存原来的寄存器数据*/
    memcpy(&original_regs, &regs, sizeof(regs));
    //获取目标进程mmap函数的地址
    mmap_addr = get_remote_addr(target_pid, libc_path, (void *) mmap);
     //获取目标进程 dlopen 函数的地址
    dlopen_addr = get_remote_addr(target_pid, linker_path, (void *) dlopen);
    //获取目标进程 dlsym 函数的地址
    dlsym_addr = get_remote_addr(target_pid, linker_path, (void *) dlsym);
    //获取目标进程 dlclose 函数的地址
    dlclose_addr = get_remote_addr(target_pid, linker_path, (void *) dlclose);
    //获取目标进程 dlerror 函数的地址
    dlerror_addr = get_remote_addr(target_pid, linker_path, (void *) dlerror);

    printf("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
                dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);
    printf("[+] Remote mmap address: %x\n", mmap_addr);

    //4.使用mmap函数分配字符串内存
    /* call mmap 准备mmap参数 这里分配0x4000大小的内存*/
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    //在目标进程中调用mmap函数
    if (ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
        goto exit;

    map_base = ptrace_retval(&regs);

    printf("library path = %s\n", library_path);
    //5.往目标进程写入library_path中的字符串
    ptrace_writedata(target_pid, map_base, library_path, strlen(library_path) + 1);

    parameters[0] = map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    //6.让目标进程调用 dlopen 函数
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
        goto exit;

    void *sohandle = ptrace_retval(&regs);
		//7.往目标进程写入function_name中的字符串 (这里分配到0x100后面 一般上面的字符串不会超过)
#define FUNCTION_NAME_ADDR_OFFSET       0x100
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name,
                     strlen(function_name) + 1);
    parameters[0] = sohandle;
    parameters[1] = map_base + FUNCTION_NAME_ADDR_OFFSET;
    //8.让目标进程调用 dlsym 函数(得到我们需要调用的函数地址)
    if (ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
        goto exit;

    void *hook_entry_addr = ptrace_retval(&regs);
    printf("hook_entry_addr = %p\n", hook_entry_addr);
    //9.为调用的函数参数，拷贝字符串 (这里分配到0x200后面 一般上面的字符串不会超过)
#define FUNCTION_PARAM_ADDR_OFFSET      0x200
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, strlen(param) + 1);
    parameters[0] = map_base + FUNCTION_PARAM_ADDR_OFFSET;

    //10.让目标进程调用hook_entry 函数
    if (ptrace_call_wrapper(target_pid, function_name, hook_entry_addr, parameters, 1, &regs) == -1)
        goto exit;

    printf("Press enter to dlclose and detach\n");


    /* 11.恢复寄存器*/
    ptrace_setregs(target_pid, &original_regs);
    //12.卸载目标进程
    ptrace_detach(target_pid);
    ret = 0;

    exit:
    return ret;
}
