#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>

// Add PAGE_SIZE definition if not defined elsewhere
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline int is_user_address(uint64 addr) {
    return addr < USER_TOP;  // 假设 USER_TOP 是用户地址空间的上限
}

// Add a more robust validation function
static inline int is_valid_user_address(uint64 addr, uint64 size) {
    return is_user_address(addr) && 
           is_user_address(addr + size - 1) && 
           addr >= PAGE_SIZE && 
           addr % 8 == 0;  // Check alignment for RISC-V
}

/**
 * @brief init the signal struct inside a PCB.
 * 
 * @param p 
 * @return int 
 */
int siginit(struct proc *p) {
    // Initialize all signal actions to default
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = NULL;
    }
    
    // Initialize signal mask and pending signals
    p->signal.sigmask = 0;
    p->signal.sigpending = 0;
    
    // Initialize siginfo structures (zero them out)
    memset(p->signal.siginfos, 0, sizeof(p->signal.siginfos));
    p->signal.ctx_stack.top = -1;  // 栈初始化为空
    
    return 0;
}

int siginit_fork(struct proc *parent, struct proc *child) {
    // Copy parent's sigactions and signal mask
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        child->signal.sa[i] = parent->signal.sa[i];
    }
    child->signal.sigmask = parent->signal.sigmask;
    
    // Clear all pending signals in child
    child->signal.sigpending = 0;
    
    return 0;
}

int siginit_exec(struct proc *p) {
    // Reset all sigactions (except ignored) to default
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        if (p->signal.sa[i].sa_sigaction != SIG_IGN) {
            p->signal.sa[i].sa_sigaction = SIG_DFL;
            p->signal.sa[i].sa_mask = 0;
            p->signal.sa[i].sa_restorer = NULL;
        }
    }
    
    // Signal mask and pending signals are preserved across exec
    return 0;
}

int do_signal(void) {
    struct proc *p = curr_proc();
    sigset_t pending = p->signal.sigpending & ~p->signal.sigmask;
    
    if (pending == 0) {
        return -EFAULT;
    }
    
    // Find the highest priority pending signal
    int signo;
    for (signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (pending & sigmask(signo)) {
            break;
        }
    }
    
    // Clear the pending bit
    p->signal.sigpending &= ~sigmask(signo);
    
    // Get the signal action
    sigaction_t *sa = &p->signal.sa[signo];
    
    // Handle default actions
    if (sa->sa_sigaction == SIG_DFL) {
        switch (signo) {
            case SIGKILL:
            case SIGTERM:
            case SIGSEGV:
            case SIGINT:
            case SIGUSR0:
            case SIGUSR1:
            case SIGUSR2:
                setkilled(p, -10 - signo);
                break;
            case SIGCHLD:
                // Ignore by default
                break;
            case SIGSTOP:
            case SIGCONT:
                // Not implemented in base checkpoint
                break;
        }
        return 0;
    }
    
    // Handle ignored signals
    if (sa->sa_sigaction == SIG_IGN) {
        return 0;
    }
    
    // Prepare user stack for signal handler
    struct trapframe *tf = p->trapframe;
    uint64 sp = tf->sp;
    
    // Allocate space for siginfo and ucontext on user stack
    // sp -= sizeof(siginfo_t);
    // siginfo_t *info = (siginfo_t *)sp;
    // memset(info, 0, sizeof(siginfo_t));
    // info->si_signo = signo;
    
    // sp -= sizeof(struct ucontext);
    // struct ucontext *uc = (struct ucontext *)sp;
    sp = sp & ~0xF;
    uint64 user_uc_addr = sp - sizeof(struct ucontext);
    uint64 user_info_addr = user_uc_addr - sizeof(siginfo_t);

    // 2. 检查用户地址合法
    if (!is_user_address(user_info_addr) ||
    !is_user_address(user_info_addr + sizeof(siginfo_t) - 1) ||
    !is_user_address(user_uc_addr) ||
    !is_user_address(user_uc_addr + sizeof(struct ucontext) - 1)) {
    return -EFAULT;
}

    // 3. 构造内核临时结构体
    siginfo_t kinfo;
    memset(&kinfo, 0, sizeof(siginfo_t));
    kinfo.si_signo = signo;

    struct ucontext kuc;
    kuc.uc_mcontext.epc = tf->epc;
    kuc.uc_mcontext.regs[0] = 0;
    kuc.uc_mcontext.regs[1] = tf->ra;
    kuc.uc_mcontext.regs[2] = tf->sp;
    kuc.uc_mcontext.regs[3] = tf->gp;
    kuc.uc_mcontext.regs[4] = tf->tp;
    kuc.uc_mcontext.regs[5] = tf->t0;
    kuc.uc_mcontext.regs[6] = tf->t1;
    kuc.uc_mcontext.regs[7] = tf->t2;
    kuc.uc_mcontext.regs[8] = tf->s0;
    kuc.uc_mcontext.regs[9] = tf->s1;
    kuc.uc_mcontext.regs[10] = tf->a0;
    kuc.uc_mcontext.regs[11] = tf->a1;
    kuc.uc_mcontext.regs[12] = tf->a2;
    kuc.uc_mcontext.regs[13] = tf->a3;
    kuc.uc_mcontext.regs[14] = tf->a4;
    kuc.uc_mcontext.regs[15] = tf->a5;
    kuc.uc_mcontext.regs[16] = tf->a6;
    kuc.uc_mcontext.regs[17] = tf->a7;
    kuc.uc_mcontext.regs[18] = tf->s2;
    kuc.uc_mcontext.regs[19] = tf->s3;
    kuc.uc_mcontext.regs[20] = tf->s4;
    kuc.uc_mcontext.regs[21] = tf->s5;
    kuc.uc_mcontext.regs[22] = tf->s6;
    kuc.uc_mcontext.regs[23] = tf->s7;
    kuc.uc_mcontext.regs[24] = tf->s8;
    kuc.uc_mcontext.regs[25] = tf->s9;
    kuc.uc_mcontext.regs[26] = tf->s10;
    kuc.uc_mcontext.regs[27] = tf->s11;
    kuc.uc_mcontext.regs[28] = tf->t3;
    kuc.uc_mcontext.regs[29] = tf->t4;
    kuc.uc_mcontext.regs[30] = tf->t5;
    kuc.uc_mcontext.regs[31] = tf->t6;
    
    kuc.uc_sigmask = p->signal.sigmask;

    if (p->signal.ctx_stack.top + 1 >= MAX_SIGNAL_DEPTH)
        panic("signal context stack overflow");

    p->signal.ctx_stack.top++;
    p->signal.ctx_stack.context_addrs[p->signal.ctx_stack.top] = user_uc_addr;
    
    // Update signal mask (block current signal and signals in sa_mask)
    p->signal.sigmask |= sigmask(signo) | sa->sa_mask;
    
    // Set up trapframe for signal handler
    acquire(&p->mm->lock);
    if (copy_to_user(p->mm, user_info_addr, (char *)&kinfo, sizeof(siginfo_t)) < 0) {
        release(&p->mm->lock);
        return -EFAULT;
    }
    if (copy_to_user(p->mm, user_uc_addr, (char *)&kuc, sizeof(struct ucontext)) < 0) {
        release(&p->mm->lock);
        return -EFAULT;
    }
    release(&p->mm->lock);

// 5. 设置 trapframe
    tf->sp = user_info_addr; // 栈顶
    tf->a0 = signo;
    tf->a1 = user_info_addr;
    tf->a2 = user_uc_addr;
    tf->epc = (uint64)sa->sa_sigaction;
    tf->ra = (uint64)sa->sa_restorer;

    // p->signal.last_context_addr = user_uc_addr;
    // printf("[do_signal] Set context at user_uc_addr=%p, info=%p\n", user_uc_addr, user_info_addr);

    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p = curr_proc();

    // Validate signal number
    if (signo < SIGMIN || signo > SIGMAX) {
        return -EINVAL;
    }

    // SIGKILL and SIGSTOP cannot be caught or ignored
    if (signo == SIGKILL || signo == SIGSTOP) {
        return -EINVAL;
    }

    acquire(&p->mm->lock);  // 加锁

    // Save old action if requested
    if (oldact != NULL) {
        if (copy_to_user(p->mm, (uint64)oldact, (char *)&p->signal.sa[signo], sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);  // 解锁
            return -EFAULT;
        }
    }

    // Set new action if provided
    if (act != NULL) {
        if (copy_from_user(p->mm, (char *)&p->signal.sa[signo], (uint64)act, sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);  // 解锁
            return -EFAULT;
        }
    }

    release(&p->mm->lock);  // 解锁

    return 0;
}

int sys_sigreturn() {
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;

    // Get ucontext from a2 register
    // uint64 context_addr = p->signal.last_context_addr;
    if (p->signal.ctx_stack.top < 0)
        return -EFAULT;

    uint64 context_addr = p->signal.ctx_stack.context_addrs[p->signal.ctx_stack.top--];
    
    // Additional safety check - compare with a2 and log discrepancies
    // if (context_addr != tf->a2) {
    //     printf("[sigreturn] Warning: saved context addr %p differs from a2 %p\n", 
    //            context_addr, tf->a2);
    // }

    // Validate user pointer
    struct ucontext kuc;
    acquire(&p->mm->lock);
    
    // More robust validation - check for realistic memory addresses
    if (!is_user_address((uint64)context_addr) ||
        !is_user_address((uint64)context_addr + sizeof(struct ucontext) - 1) ||
        (uint64)context_addr < PAGE_SIZE) {  // Ensure address is at least beyond first page (NULL page)
        // printf("[sigreturn] Invalid context address: %p\n", context_addr);
        release(&p->mm->lock);
        return -EFAULT;
    }
    
    // Print info but don't try to access memory yet
    // printf("[sigreturn] tf->a2 = %p, sizeof(ucontext) = %d\n", tf->a2, sizeof(struct ucontext));
    
    // Only try to access memory after proper validation
    if (copy_from_user(p->mm, (char *)&kuc, context_addr, sizeof(struct ucontext)) < 0) {
        // printf("[sigreturn] copy_from_user failed\n");
        release(&p->mm->lock);
        return -EFAULT;
    }
    
    // After successful copy, now we can print some content safely
    // printf("[sigreturn] Restored context: epc=%p\n", kuc.uc_mcontext.epc);

    tf->epc = kuc.uc_mcontext.epc;
    tf->ra = kuc.uc_mcontext.regs[1];
    tf->sp = kuc.uc_mcontext.regs[2];
    tf->gp = kuc.uc_mcontext.regs[3];
    tf->tp = kuc.uc_mcontext.regs[4];
    tf->t0 = kuc.uc_mcontext.regs[5];
    tf->t1 = kuc.uc_mcontext.regs[6];
    tf->t2 = kuc.uc_mcontext.regs[7];
    tf->s0 = kuc.uc_mcontext.regs[8];
    tf->s1 = kuc.uc_mcontext.regs[9];
    tf->a0 = kuc.uc_mcontext.regs[10];
    tf->a1 = kuc.uc_mcontext.regs[11];
    tf->a2 = kuc.uc_mcontext.regs[12];
    tf->a3 = kuc.uc_mcontext.regs[13];
    tf->a4 = kuc.uc_mcontext.regs[14];
    tf->a5 = kuc.uc_mcontext.regs[15];
    tf->a6 = kuc.uc_mcontext.regs[16];
    tf->a7 = kuc.uc_mcontext.regs[17];
    tf->s2 = kuc.uc_mcontext.regs[18];
    tf->s3 = kuc.uc_mcontext.regs[19];
    tf->s4 = kuc.uc_mcontext.regs[20];
    tf->s5 = kuc.uc_mcontext.regs[21];
    tf->s6 = kuc.uc_mcontext.regs[22];
    tf->s7 = kuc.uc_mcontext.regs[23];
    tf->s8 = kuc.uc_mcontext.regs[24];
    tf->s9 = kuc.uc_mcontext.regs[25];
    tf->s10 = kuc.uc_mcontext.regs[26];
    tf->s11 = kuc.uc_mcontext.regs[27];
    tf->t3 = kuc.uc_mcontext.regs[28];
    tf->t4 = kuc.uc_mcontext.regs[29];
    tf->t5 = kuc.uc_mcontext.regs[30];
    tf->t6 = kuc.uc_mcontext.regs[31];

    p->signal.sigmask = kuc.uc_sigmask;

    release(&p->mm->lock);  // 解锁

    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    struct proc *p = curr_proc();

    acquire(&p->mm->lock);  // 加锁
    if (copy_to_user(p->mm, (uint64)set, (char *)&p->signal.sigpending, sizeof(sigset_t)) < 0) {
        release(&p->mm->lock);  // 解锁
        return -EFAULT;
    }
    release(&p->mm->lock);  // 解锁

    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    // Validate signal number
    if (signo < SIGMIN || signo > SIGMAX) {
        return -EINVAL;
    }
    
    // Find the target process
    struct proc *target = NULL;
    for (int i = 0; i < NPROC; i++) {
        if (pool[i]->pid == pid) {
            target = pool[i];
            break;
        }
    }
    
    if (target == NULL) {
        return -EINVAL;
    }
    
    // Set the signal as pending
    acquire(&target->lock);
    target->signal.sigpending |= sigmask(signo);
    
    // For SIGKILL, terminate immediately
    if (signo == SIGKILL) {
        setkilled(target, -10 - signo);
    }
    
    release(&target->lock);
    
    return 0;
}