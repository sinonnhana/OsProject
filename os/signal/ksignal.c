#include "ksignal.h"

#include <defs.h>
#include <proc.h>
#include <trap.h>

/**
 * @brief init the signal struct inside a PCB.
 * 
 * @param p 
 * @return int 
 */
int siginit(struct proc *p) {
    // 初始化信号掩码和挂起信号集合
    p->signal.sigmask = 0;
    p->signal.sigpending = 0;

    // 初始化所有信号的处理器为默认（SIG_DFL）
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.sa[i].sa_sigaction = SIG_DFL;
        p->signal.sa[i].sa_mask = 0;
        p->signal.sa[i].sa_restorer = 0;
    }

    // 初始化 siginfos 为 0
    for (int i = SIGMIN; i <= SIGMAX; i++) {
        p->signal.siginfos[i].si_signo = 0;
        p->signal.siginfos[i].si_code = 0;
        p->signal.siginfos[i].si_pid = 0;
        p->signal.siginfos[i].si_status = 0;
        p->signal.siginfos[i].addr = 0;
    }

    return 0;
}


int siginit_fork(struct proc *parent, struct proc *child) {
    // copy parent's sigactions and signal mask
    // but clear all pending signals
    return 0;
}

int siginit_exec(struct proc *p) {
    // inherit signal mask and pending signals.
    // but reset all sigactions (except ignored) to default.
    return 0;
}

int do_signal(void) {
    assert(!intr_get());

    return 0;
}

// syscall handlers:
//  sys_* functions are called by syscall.c

// ============= START OF CHECKPOINT1 sys_sigaction ====================
int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    struct proc *p = curr_proc();

    // 1. 检查信号编号是否合法
    if (signo < SIGMIN || signo > SIGMAX) {
        return -EINVAL;
    }

    acquire(&p->lock); // 获取进程锁，确保对进程信号处理结构的访问是安全的

    // 如果 oldact 不为空，需要把旧的 sigaction 写回给用户
    if (oldact) {
        if (copy_to_user(p->mm, (uint64)oldact,
                         (char *)&p->signal.sa[signo],
                         sizeof(sigaction_t)) < 0) {
            release(&p->lock);
            return -EINVAL;
        }
    }

    // 如果 act 不为空，需要更新新的 sigaction
    if (act) {
        sigaction_t new_sa;
        if (copy_from_user(p->mm, (char *)&new_sa,
                           (uint64)act,
                           sizeof(sigaction_t)) < 0) {
            release(&p->lock);
            return -EINVAL;
        }
        
        // 检查信号处理函数是否合法
        if (signo == SIGKILL || signo == SIGSTOP) {
            if (new_sa.sa_sigaction == SIG_IGN || 
                (new_sa.sa_sigaction != SIG_DFL && new_sa.sa_sigaction != SIG_IGN)) { // SIG_DFL is okay, anything else (handler) is not
                release(&p->lock);
                return -EINVAL; // Cannot ignore or catch SIGKILL/SIGSTOP
            }
        }

        // 更新内核记录的 sigaction
        p->signal.sa[signo] = new_sa;

        // 如果新的处理函数是 SIG_IGN，并且当前有挂起的信号，则需要清除挂起的信号
        if (new_sa.sa_sigaction == SIG_IGN && sigismember(&p->signal.sigpending, signo)) {
            sigdelset(&p->signal.sigpending, signo);
            // TODO: clear its siginfo if we were storing it per signal
            // memset(&p->signal.siginfos[signo], 0, sizeof(siginfo_t)); // Optional for now
        }

        // 如果新的处理函数是 SIG_DFL，并且当前有挂起的信号，则需要清除挂起的信号
        if (signo == SIGCHLD && new_sa.sa_sigaction == SIG_DFL && sigismember(&p->signal.sigpending, signo)) {
            sigdelset(&p->signal.sigpending, signo);
        }
    }

    release(&p->lock);
    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigaction ======================

int sys_sigreturn() {
    return 0;
}

// ============= START OF CHECKPOINT1 sys_sigprocmask =====================
int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    sigset_t new_mask_user; // 用于存储从用户空间传入的信号集

    // 1. 检查信号掩码是否合法 
    if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
        return -EINVAL;
    }

    acquire(&p->lock);

    // 如果 oldset 不为空，先把当前的 sigmask 写回用户
    if (oldset) {
        if (copy_to_user(p->mm, (uint64)oldset, (char*)&(p->signal.sigmask), sizeof(sigset_t)) < 0) {
            release(&p->lock);
            return -EINVAL;
        }
    }

    // 如果 set 不为空，需要更新
    if (set) {
        if (copy_from_user(p->mm, (char*)&new_mask_user, (uint64)set, sizeof(sigset_t)) < 0) {
            release(&p->lock);
            return -EINVAL;
        }

        /*
         * SIGKILL 和 SIGSTOP 信号不能被阻塞。
         * 如果有任何信号集尝试阻塞它们，则将它们从信号集中移除。
         */
        sigdelset(&new_mask_user, SIGKILL);
        sigdelset(&new_mask_user, SIGSTOP);


        switch (how) {
        case SIG_BLOCK:
            p->signal.sigmask |= new_mask_user;
            break;
        case SIG_UNBLOCK:
            p->signal.sigmask &= ~new_mask_user;
            break;
        case SIG_SETMASK:
            p->signal.sigmask = new_mask_user;
            break;
        default:
            release(&p->lock);
            return -EINVAL;
        }
    }

    release(&p->lock);
    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigprocmask =====================

// ============= START OF CHECKPOINT1 sys_sigpending ===================
int sys_sigpending(sigset_t __user *set) {
    struct proc *p = curr_proc();

    if (!set) {
        return -EINVAL;
    }

    acquire(&p->lock);
    // Copies p->signal.sigpending to a local variable
    sigset_t pending = p->signal.sigpending;
    release(&p->lock);

    if (copy_to_user(p->mm, (uint64)set,
                     (char *)&pending, sizeof(sigset_t)) < 0) {
        return -EINVAL;
    }

    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigpending =====================

// ============= START OF CHECKPOINT1 sys_sigkill ======================
int sys_sigkill(int pid, int signo, int code) {
    struct proc *target_p = 0;
    struct proc *p;

    // 1. Check if the signal number is valid
    if (signo < SIGMIN || signo > SIGMAX) {
        return -EINVAL; // Invalid signal number
    }

    // 2. Find the target process by pid
    int found = 0;
    for (int i = 0; i < NPROC; i++) {
        p = pool[i]; // Assuming 'pool' is the global process array from proc.c
        acquire(&p->lock);
        if (p->pid == pid && p->state != UNUSED && p->state != ZOMBIE) {
            target_p = p;
            // Keep the lock on target_p if found, or release if not this one
            found = 1;
            break; // Found target
        }
        release(&p->lock);
    }
    if (!found) {
        return -EINVAL; // No such process
    }

    // 3. Add signal to target's pending set and fill siginfo
    sigaddset(&target_p->signal.sigpending, signo);

    struct proc *sender = curr_proc();
    target_p->signal.siginfos[signo].si_signo = signo;
    target_p->signal.siginfos[signo].si_code = code; // From syscall arg
    target_p->signal.siginfos[signo].si_pid = sender->pid; // Sender PID

    // 4. If the target process is sleeping and the signal is not blocked (or is SIGKILL/SIGSTOP),
    //    wake it up so it can handle the signal.
    //    SIGKILL and SIGSTOP should interrupt sleeps regardless of mask.
    int is_kill_or_stop = (signo == SIGKILL || signo == SIGSTOP);
    if (target_p->state == SLEEPING &&
        (!sigismember(&target_p->signal.sigmask, signo) || is_kill_or_stop)) {
        target_p->state = RUNNABLE;
        add_task(target_p); // Make it runnable so it can process the signal
    }

    release(&target_p->lock);
    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigkill ========================