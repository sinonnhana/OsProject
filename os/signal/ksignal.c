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
    // 1. 继承信号处理函数和信号 mask
    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        child->signal.sa[signo] = parent->signal.sa[signo];
    }
    child->signal.sigmask = parent->signal.sigmask;

    // 2. 清空 pending 和 siginfo
    sigemptyset(&child->signal.sigpending);
    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        memset(&child->signal.siginfos[signo], 0, sizeof(siginfo_t));
    }

    return 0;
}

int siginit_exec(struct proc *p) {
    // 1. 保留 signal mask
    // 不变：p->signal.sigmask;

    // 2. 保留 pending（不清）
    // 不变：p->signal.sigpending;
    // 不变：p->signal.siginfos;

    // 3. 重置 signal handler：所有非 SIG_IGN 的变为 SIG_DFL
    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        void *handler = p->signal.sa[signo].sa_sigaction;
        if (handler != SIG_IGN) {
            p->signal.sa[signo].sa_sigaction = SIG_DFL;
            sigemptyset(&p->signal.sa[signo].sa_mask);
            p->signal.sa[signo].sa_restorer = NULL;
        }
    }

    return 0;
}

int do_signal(void) {
    // 1. 按信号编号顺序处理，确保SIGKILL等高优先级信号优先处理
    // 2. 完整保存RISC-V的所有通用寄存器状态
    // 3. 在用户栈上构造siginfo和ucontext结构
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;    

    // 按优先级遍历所有信号
    for (int signo = SIGMIN; signo <= SIGMAX; signo++) {
        if (!sigismember(&p->signal.sigpending, signo)) continue;
        if (sigismember(&p->signal.sigmask, signo)) continue; // 被 mask 了，暂不处理

        void *handler = p->signal.sa[signo].sa_sigaction;

        // 1. 忽略型信号处理
        if (handler == SIG_IGN) {
            sigdelset(&p->signal.sigpending, signo);
            continue;
        }

        // 2. 默认处理
        if (handler == SIG_DFL) {
            if (signo == SIGCHLD) {
                sigdelset(&p->signal.sigpending, signo);// 忽略型默认行为可直接忽略
                continue;
            }
        
            // 其他信号默认终止进程
            // 使用 setkilled() 设置退出码
            setkilled(p, -10 - signo);
            return 0;
        }

        // 说明此时是一个捕捉型信号，要准备执行 handler
        // 准备执行用户态 handler：压栈 ucontext 和 siginfo，修改 trapframe

        /// 3. 用户定义处理函数
        // 构造ucontext保存当前状态
        struct ucontext uc;
        uc.uc_sigmask = p->signal.sigmask; // 保存当前 signal mask
        uc.uc_mcontext.epc = tf->epc;

        // 保存所有通用寄存器
        uc.uc_mcontext.regs[0]  = tf->ra;
        uc.uc_mcontext.regs[1]  = tf->sp;
        uc.uc_mcontext.regs[2]  = tf->gp;
        uc.uc_mcontext.regs[3]  = tf->tp;
        uc.uc_mcontext.regs[4]  = tf->t0;
        uc.uc_mcontext.regs[5]  = tf->t1;
        uc.uc_mcontext.regs[6]  = tf->t2;
        uc.uc_mcontext.regs[7]  = tf->s0;
        uc.uc_mcontext.regs[8]  = tf->s1;
        uc.uc_mcontext.regs[9]  = tf->a0;
        uc.uc_mcontext.regs[10] = tf->a1;
        uc.uc_mcontext.regs[11] = tf->a2;
        uc.uc_mcontext.regs[12] = tf->a3;
        uc.uc_mcontext.regs[13] = tf->a4;
        uc.uc_mcontext.regs[14] = tf->a5;
        uc.uc_mcontext.regs[15] = tf->a6;
        uc.uc_mcontext.regs[16] = tf->a7;
        uc.uc_mcontext.regs[17] = tf->s2;
        uc.uc_mcontext.regs[18] = tf->s3;
        uc.uc_mcontext.regs[19] = tf->s4;
        uc.uc_mcontext.regs[20] = tf->s5;
        uc.uc_mcontext.regs[21] = tf->s6;
        uc.uc_mcontext.regs[22] = tf->s7;
        uc.uc_mcontext.regs[23] = tf->s8;
        uc.uc_mcontext.regs[24] = tf->s9;
        uc.uc_mcontext.regs[25] = tf->s10;
        uc.uc_mcontext.regs[26] = tf->s11;
        uc.uc_mcontext.regs[27] = tf->t3;
        uc.uc_mcontext.regs[28] = tf->t4;
        uc.uc_mcontext.regs[29] = tf->t5;
        uc.uc_mcontext.regs[30] = tf->t6;

        // 构造siginfo并写入用户栈
        struct siginfo info = p->signal.siginfos[signo];
        tf->sp -= sizeof(struct siginfo);
        acquire(&p->mm->lock);
        if (copy_to_user(p->mm, tf->sp, (char *)&info, sizeof(struct siginfo)) < 0){
            release(&p->mm->lock);
            return -1;
        }
        
        uint64 siginfo_user_ptr = tf->sp;

        // 写入ucontext到用户栈
        tf->sp -= sizeof(struct ucontext);

        if (copy_to_user(p->mm, tf->sp, (char *)&uc, sizeof(struct ucontext)) < 0){
            release(&p->mm->lock);
            return -1;
        }
        release(&p->mm->lock);
        uint64 ucontext_user_ptr = tf->sp;

        // 设置trapframe，准备执行信号处理函数
        tf->epc = (uint64)handler;                          // 入口地址
        tf->ra = (uint64)p->signal.sa[signo].sa_restorer;   // 返回地址
        tf->a0 = signo;
        tf->a1 = siginfo_user_ptr;
        tf->a2 = ucontext_user_ptr;

        // 更新信号掩码（阻塞 handler 期间设定的信号）
        p->signal.sigmask |= p->signal.sa[signo].sa_mask;
        p->signal.sigmask |= sigmask(signo); // 也阻塞自身

        // 清除挂起信号
        sigdelset(&p->signal.sigpending, signo);
        

        return 0; // 成功处理一个信号，准备执行 handler
    }

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

    acquire(&p->mm->lock);

    // 2. 返回旧的sigaction配置
    // 如果 oldact 不为空，需要把旧的 sigaction 写回给用户
    if (oldact) {
        if (copy_to_user(p->mm, (uint64)oldact,
                         (char *)&p->signal.sa[signo],
                         sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);
            return -EINVAL;
        }
    }

    // 3. 设置新的sigaction配置
    // 如果 act 不为空，需要更新新的 sigaction
    if (act) {
        sigaction_t new_sa;
        if (copy_from_user(p->mm, (char *)&new_sa,
                           (uint64)act,
                           sizeof(sigaction_t)) < 0) {
            release(&p->mm->lock);
            return -EINVAL;
        }
        
        // 4. SIGKILL和SIGSTOP不能被捕获或忽略
        if (signo == SIGKILL || signo == SIGSTOP) {
            if (new_sa.sa_sigaction == SIG_IGN || 
                (new_sa.sa_sigaction != SIG_DFL && new_sa.sa_sigaction != SIG_IGN)) {
                release(&p->mm->lock);
                return -EINVAL; // Cannot ignore or catch SIGKILL/SIGSTOP
            }
        }

        // 更新内核记录的 sigaction
        p->signal.sa[signo] = new_sa;

        // 5. 特殊处理：如果设置为SIG_IGN，清除已挂起的信号
        if (new_sa.sa_sigaction == SIG_IGN && sigismember(&p->signal.sigpending, signo)) {
            sigdelset(&p->signal.sigpending, signo);
        }

        // 如果新的处理函数是 SIG_DFL，并且当前有挂起的信号，则需要清除挂起的信号
        if (signo == SIGCHLD && new_sa.sa_sigaction == SIG_DFL && sigismember(&p->signal.sigpending, signo)) {
            sigdelset(&p->signal.sigpending, signo);
        }
    }

    release(&p->mm->lock);
    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigaction ======================

int sys_sigreturn() {
    struct proc *p = curr_proc();
    struct trapframe *tf = p->trapframe;

    struct ucontext user_uc;

    // 从用户栈读取 ucontext
    acquire(&p->mm->lock);
    if (copy_from_user(p->mm, (char *)&user_uc, tf->sp, sizeof(struct ucontext)) < 0) {
        release(&p->mm->lock);
        return -EINVAL;
    }
    release(&p->mm->lock);
    

    // 恢复 signal mask
    p->signal.sigmask = user_uc.uc_sigmask;

    // 恢复通用寄存器（x1 ~ x31）
    tf->ra = user_uc.uc_mcontext.regs[0];   // x1
    tf->sp = user_uc.uc_mcontext.regs[1];   // x2
    tf->gp = user_uc.uc_mcontext.regs[2];   // x3
    tf->tp = user_uc.uc_mcontext.regs[3];   // x4

    tf->t0 = user_uc.uc_mcontext.regs[4];   // x5
    tf->t1 = user_uc.uc_mcontext.regs[5];   // x6
    tf->t2 = user_uc.uc_mcontext.regs[6];   // x7

    tf->s0 = user_uc.uc_mcontext.regs[7];   // x8
    tf->s1 = user_uc.uc_mcontext.regs[8];   // x9

    tf->a0 = user_uc.uc_mcontext.regs[9];   // x10
    tf->a1 = user_uc.uc_mcontext.regs[10];  // x11
    tf->a2 = user_uc.uc_mcontext.regs[11];  // x12
    tf->a3 = user_uc.uc_mcontext.regs[12];  // x13
    tf->a4 = user_uc.uc_mcontext.regs[13];  // x14
    tf->a5 = user_uc.uc_mcontext.regs[14];  // x15
    tf->a6 = user_uc.uc_mcontext.regs[15];  // x16
    tf->a7 = user_uc.uc_mcontext.regs[16];  // x17

    tf->s2 = user_uc.uc_mcontext.regs[17];  // x18
    tf->s3 = user_uc.uc_mcontext.regs[18];  // x19
    tf->s4 = user_uc.uc_mcontext.regs[19];  // x20
    tf->s5 = user_uc.uc_mcontext.regs[20];  // x21
    tf->s6 = user_uc.uc_mcontext.regs[21];  // x22
    tf->s7 = user_uc.uc_mcontext.regs[22];  // x23
    tf->s8 = user_uc.uc_mcontext.regs[23];  // x24
    tf->s9 = user_uc.uc_mcontext.regs[24];  // x25
    tf->s10 = user_uc.uc_mcontext.regs[25]; // x26
    tf->s11 = user_uc.uc_mcontext.regs[26]; // x27

    tf->t3 = user_uc.uc_mcontext.regs[27];  // x28
    tf->t4 = user_uc.uc_mcontext.regs[28];  // x29
    tf->t5 = user_uc.uc_mcontext.regs[29];  // x30
    tf->t6 = user_uc.uc_mcontext.regs[30];  // x31

    // 恢复程序计数器（epc）
    tf->epc = user_uc.uc_mcontext.epc;

    return 0;
}

// ============= START OF CHECKPOINT1 sys_sigprocmask =====================
// 用于读取和修改进程的信号掩码，控制哪些信号被阻塞
int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    struct proc *p = curr_proc();
    sigset_t new_mask_user; // 用于存储从用户空间传入的信号集

    // 1. 检查信号掩码是否合法 
    if (how != SIG_BLOCK && how != SIG_UNBLOCK && how != SIG_SETMASK) {
        return -EINVAL;
    }

    acquire(&p->mm->lock);

    // 第二步：返回当前信号掩码（如果oldset不为空）
    if (oldset) {
        if (copy_to_user(p->mm, (uint64)oldset, (char*)&(p->signal.sigmask), sizeof(sigset_t)) < 0) {
            release(&p->mm->lock);
            return -EINVAL;
        }
    }

    // 第三步：处理新的信号掩码设置
    if (set) {
        // 从用户空间读取新的信号集
        if (copy_from_user(p->mm, (char*)&new_mask_user, (uint64)set, sizeof(sigset_t)) < 0) {
            release(&p->mm->lock);
            return -EINVAL;
        }

        /*
         * SIGKILL 和 SIGSTOP 信号不能被阻塞。
         * 如果有任何信号集尝试阻塞它们，则将它们从信号集中移除。
         */
        // 第四步：强制移除不可阻塞的信号
        sigdelset(&new_mask_user, SIGKILL);
        sigdelset(&new_mask_user, SIGSTOP);

        // 第五步：根据how参数执行相应操作
        switch (how) {
        case SIG_BLOCK:
            p->signal.sigmask |= new_mask_user;     // 添加阻塞信号
            break;
        case SIG_UNBLOCK:
            p->signal.sigmask &= ~new_mask_user;    // 移除阻塞信号
            break;
        case SIG_SETMASK:
            p->signal.sigmask = new_mask_user;      // 直接设置
            break;
        default:
            release(&p->mm->lock);
            return -EINVAL;
        }
    }

    release(&p->mm->lock);
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

    acquire(&p->mm->lock);
    if (copy_to_user(p->mm, (uint64)set,
                     (char *)&pending, sizeof(sigset_t)) < 0) {
        release(&p->mm->lock);
        return -EINVAL;
    }
    release(&p->mm->lock);

    return 0;
}
// ============= END OF CHECKPOINT1 sys_sigpending =====================

// ============= START OF CHECKPOINT1 sys_sigkill ======================
// sigkill可以发送任何信号，包括SIGKILL
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

    siginfo_t *info = &target_p->signal.siginfos[signo];
    info->si_signo  = signo;
    info->si_code   = code;

    struct proc *sender = curr_proc();

    if (sender) {
        info->si_pid = sender->pid;  // 发送的这个信号的进程 pid
    } else {
        info->si_pid = -1;  // 内核发送的信号，填充 -1
    }

    // 其余字段目前默认填 0
    info->si_status = 0;
    info->addr = 0;
    
    // target_p->signal.siginfos[signo].si_signo = signo;
    // target_p->signal.siginfos[signo].si_code = code; // From syscall arg
    // target_p->signal.siginfos[signo].si_pid = sender->pid; // Sender PID

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


int sys_alarm(int seconds) {
    struct proc *p = curr_proc();

    if (seconds < 0)
        return -1;

    int ticks = seconds * 100; // 假设每秒 100 tick，与你的时钟频率对应

    int remaining_ticks = p->signal.alarm_ticks_left;

    if (seconds == 0) {
        p->signal.alarm_ticks_left = 0;
        p->signal.alarm_interval = 0;
    } else {
        p->signal.alarm_ticks_left = ticks;
        p->signal.alarm_interval = ticks;
    }

    return remaining_ticks / 100;  // 返回旧的剩余秒数
}
