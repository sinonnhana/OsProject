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

int sys_sigaction(int signo, const sigaction_t __user *act, sigaction_t __user *oldact) {
    return 0;
}

int sys_sigreturn() {
    return 0;
}

int sys_sigprocmask(int how, const sigset_t __user *set, sigset_t __user *oldset) {
    return 0;
}

int sys_sigpending(sigset_t __user *set) {
    return 0;
}

int sys_sigkill(int pid, int signo, int code) {
    return 0;
}