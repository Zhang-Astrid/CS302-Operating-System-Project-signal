#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>

static inline int is_user_address(uint64 addr) {
    return addr < USER_TOP;  // 假设 USER_TOP 是用户地址空间的上限
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
        return 0;
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
    sp -= sizeof(siginfo_t);
    siginfo_t *info = (siginfo_t *)sp;
    memset(info, 0, sizeof(siginfo_t));
    info->si_signo = signo;
    
    sp -= sizeof(struct ucontext);
    struct ucontext *uc = (struct ucontext *)sp;
    
    // Save current context
    uc->uc_mcontext.epc = tf->epc;
    // Save all general purpose registers (x0-x31)
    uc->uc_mcontext.regs[0] = 0; // x0 is always zero
    uc->uc_mcontext.regs[1] = tf->ra;
    uc->uc_mcontext.regs[2] = tf->sp;
    uc->uc_mcontext.regs[3] = tf->gp;
    uc->uc_mcontext.regs[4] = tf->tp;
    uc->uc_mcontext.regs[5] = tf->t0;
    uc->uc_mcontext.regs[6] = tf->t1;
    uc->uc_mcontext.regs[7] = tf->t2;
    uc->uc_mcontext.regs[8] = tf->s0;
    uc->uc_mcontext.regs[9] = tf->s1;
    uc->uc_mcontext.regs[10] = tf->a0;
    uc->uc_mcontext.regs[11] = tf->a1;
    uc->uc_mcontext.regs[12] = tf->a2;
    uc->uc_mcontext.regs[13] = tf->a3;
    uc->uc_mcontext.regs[14] = tf->a4;
    uc->uc_mcontext.regs[15] = tf->a5;
    uc->uc_mcontext.regs[16] = tf->a6;
    uc->uc_mcontext.regs[17] = tf->a7;
    uc->uc_mcontext.regs[18] = tf->s2;
    uc->uc_mcontext.regs[19] = tf->s3;
    uc->uc_mcontext.regs[20] = tf->s4;
    uc->uc_mcontext.regs[21] = tf->s5;
    uc->uc_mcontext.regs[22] = tf->s6;
    uc->uc_mcontext.regs[23] = tf->s7;
    uc->uc_mcontext.regs[24] = tf->s8;
    uc->uc_mcontext.regs[25] = tf->s9;
    uc->uc_mcontext.regs[26] = tf->s10;
    uc->uc_mcontext.regs[27] = tf->s11;
    uc->uc_mcontext.regs[28] = tf->t3;
    uc->uc_mcontext.regs[29] = tf->t4;
    uc->uc_mcontext.regs[30] = tf->t5;
    uc->uc_mcontext.regs[31] = tf->t6;
    
    uc->uc_sigmask = p->signal.sigmask;
    
    // Update signal mask (block current signal and signals in sa_mask)
    p->signal.sigmask |= sigmask(signo) | sa->sa_mask;
    
    // Set up trapframe for signal handler
    tf->epc = (uint64)sa->sa_sigaction;  // Handler address
    tf->sp = sp;                         // New stack pointer
    tf->a0 = signo;                      // First argument (signo)
    tf->a1 = (uint64)info;               // Second argument (siginfo)
    tf->a2 = (uint64)uc;                 // Third argument (ucontext)
    tf->ra = (uint64)sa->sa_restorer;    // Return address (sigreturn)
    
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
    struct ucontext *uc = (struct ucontext *)tf->a2;

    // Validate user pointer
    if (!is_user_address((uint64)uc)) {
        return -EFAULT;
    }

    // Restore registers
    tf->epc = uc->uc_mcontext.epc;
    tf->ra = uc->uc_mcontext.regs[1];
    tf->sp = uc->uc_mcontext.regs[2];
    tf->gp = uc->uc_mcontext.regs[3];
    tf->tp = uc->uc_mcontext.regs[4];
    tf->t0 = uc->uc_mcontext.regs[5];
    tf->t1 = uc->uc_mcontext.regs[6];
    tf->t2 = uc->uc_mcontext.regs[7];
    tf->s0 = uc->uc_mcontext.regs[8];
    tf->s1 = uc->uc_mcontext.regs[9];
    tf->a0 = uc->uc_mcontext.regs[10];
    tf->a1 = uc->uc_mcontext.regs[11];
    tf->a2 = uc->uc_mcontext.regs[12];
    tf->a3 = uc->uc_mcontext.regs[13];
    tf->a4 = uc->uc_mcontext.regs[14];
    tf->a5 = uc->uc_mcontext.regs[15];
    tf->a6 = uc->uc_mcontext.regs[16];
    tf->a7 = uc->uc_mcontext.regs[17];
    tf->s2 = uc->uc_mcontext.regs[18];
    tf->s3 = uc->uc_mcontext.regs[19];
    tf->s4 = uc->uc_mcontext.regs[20];
    tf->s5 = uc->uc_mcontext.regs[21];
    tf->s6 = uc->uc_mcontext.regs[22];
    tf->s7 = uc->uc_mcontext.regs[23];
    tf->s8 = uc->uc_mcontext.regs[24];
    tf->s9 = uc->uc_mcontext.regs[25];
    tf->s10 = uc->uc_mcontext.regs[26];
    tf->s11 = uc->uc_mcontext.regs[27];
    tf->t3 = uc->uc_mcontext.regs[28];
    tf->t4 = uc->uc_mcontext.regs[29];
    tf->t5 = uc->uc_mcontext.regs[30];
    tf->t6 = uc->uc_mcontext.regs[31];

    // Restore signal mask
    p->signal.sigmask = uc->uc_sigmask;

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