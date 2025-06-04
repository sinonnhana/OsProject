#include "../../os/ktest/ktest.h"
#include "../lib/user.h"

// Base Checkpoint 1: sigaction, sigkill, and sigreturn

// send SIGUSR0 to a child process, which default action is to terminate it.
void basic1(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sleep(10);
        exit(1);
    } else {
        // parent
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGUSR0);
    }
}

// send SIGUSR0 to a child process, but should be ignored.
void basic2(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = SIG_IGN,
            .sa_mask      = 0,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR0, &sa, 0);
        sleep(10);
        sleep(10);
        sleep(10);
        exit(1);
    } else {
        // parent
        sleep(5);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == 1);
    }
}

void handler3(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    getpid();
    sleep(1);
    exit(103);
}

// set handler for SIGUSR0, which call exits to terminate the process.
//  this handler will not return, so sigreturn should not be called.
void basic3(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler3,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (1);
        exit(1);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 103);
    }
}

volatile int handler4_flag = 0;
void handler4(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    sleep(1);
    sleep(1);
    fprintf(1, "handler4 triggered\n");
    handler4_flag = 1;
}

// set handler for SIGUSR0, and return from handler.
void basic4(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler4,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (handler4_flag == 0);
        exit(104);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 104);
    }
}

static volatile int handler5_cnt = 0;
void handler5(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    static volatile int nonreentrace = 0;
    assert(!nonreentrace);    // non-reentrance
    nonreentrace = 1;
    sleep(5);
    sleep(5);
    if (handler5_cnt < 5)
        sigkill(getpid(), SIGUSR0, 0);
    sleep(5);
    sleep(5);
    fprintf(1, "handler5 triggered\n");
    nonreentrace = 0;
    handler5_cnt++;
}

// signal handler itself should not be reentrant.
//  when the signal handler is called for SIGUSR0, it should block all SIGUSR0.
//  after the signal handler returns, the signal should be unblocked.
//   then, the signal handler should be called again. (5 times)
// set handler for SIGUSR0, kernel should block it from re-entrance.
void basic5(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler5,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        while (handler5_cnt < 5);
        exit(105);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 105);
    }
}

volatile int handler6_flag = 0;
void handler6(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    handler6_flag = 1;
    fprintf(1, "handler6 triggered due to %d\n", signo);
    sleep(30);
    assert(handler6_flag == 2);
    handler6_flag = 3;
}

void handler6_2(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR1);
    assert(handler6_flag == 1);
    handler6_flag = 2;
    fprintf(1, "handler6_2 triggered due to %d\n", signo);
}

// signal handler can be nested.
void basic6(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler6,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR0, &sa, 0);
        sigaction_t sa2 = {
            .sa_sigaction = handler6_2,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa2.sa_mask);
        sigaction(SIGUSR1, &sa2, 0);
        while (handler6_flag != 3);
        exit(106);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        sleep(5);
        sigkill(pid, SIGUSR1, 0);
        sleep(5);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 106);
    }
}

volatile int handler7_flag = 0;
void handler7(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR0);
    handler7_flag = 1;
    fprintf(1, "handler7 triggered due to %d\n", signo);
    sleep(30);
    sigset_t pending;
    sigpending(&pending);
    assert_eq(pending, sigmask(SIGUSR1));
    assert(handler7_flag == 1); // handler7 should not interrupted by SIGUSR1 (handler7_2)
    handler7_flag = 2;
}

void handler7_2(int signo, siginfo_t* info, void* ctx2) {
    assert(signo == SIGUSR1);
    assert(handler7_flag == 2);
    handler7_flag = 3;
    fprintf(1, "handler7_2 triggered due to %d\n", signo);
}

// signal handler can be nested.
void basic7(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler7,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaddset(&sa.sa_mask, SIGUSR1); // block SIGUSR1 when handling SIGUSR0
        sigaction(SIGUSR0, &sa, 0);

        sigaction_t sa2 = {
            .sa_sigaction = handler7_2,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa2.sa_mask);
        sigaction(SIGUSR1, &sa2, 0);

        while (handler7_flag != 3);
        exit(107);
    } else {
        // parent
        sleep(10);
        sigkill(pid, SIGUSR0, 0);
        sleep(5);
        sigkill(pid, SIGUSR1, 0);
        sleep(5);
        int ret;
        wait(0, &ret);
        assert_eq(ret, 107);
    }
}

// SIG_IGN and SIG_DFL
void basic8(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = SIG_IGN,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR0, &sa, 0);
        sigkill(getpid(), SIGUSR0, 0); // should have no effect

        sigaction_t sa2 = {
            .sa_sigaction = SIG_DFL,
            .sa_restorer  = NULL,
        };
        sigaction(SIGUSR1, &sa2, 0);
        sigkill(getpid(), SIGUSR1, 0); // should terminate the process

        exit(1);
    } else {
        // parent
        // Removed:
        // sigkill(pid, SIGUSR0, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGUSR1); // child terminated by SIGUSR1
    }
}


// Base Checkpoint 2: SIGKILL

void handler10(int signo, siginfo_t* info, void* ctx2) {
    exit(2);
}

// child process is killed by signal: SIGKILL, which cannot be handled, ignored and blocked.
void basic10(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigaction_t sa = {
            .sa_sigaction = handler10,
            .sa_restorer  = NULL,
        };
        sigaction(SIGKILL, &sa, 0); 
        // set handler for SIGKILL, which should not be called
        while (1);
        exit(1);
    } else {
        // parent
        sleep(20);
        sigkill(pid, SIGKILL, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGKILL);
    }
}

// child process is killed by signal: SIGKILL, which cannot be handled, ignored and blocked.
void basic11(char* s) {
    int pid = fork();
    if (pid == 0) {
        // child
        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGKILL);
        sigprocmask(SIG_BLOCK, &mask, NULL);
        // set handler for SIGKILL, which should not be called
        while (1);
        exit(1);
    } else {
        // parent
        sleep(20);
        sigkill(pid, SIGKILL, 0);
        int ret;
        wait(0, &ret);
        assert(ret == -10 - SIGKILL);
    }
}

// Base Checkpoint 3: signals under fork & exec

void basic20(char *s) {
    // our modification does not affect our parent process.
    // because `run` method in the testsuite will do fork for us.

    sigaction_t sa = {
        .sa_sigaction = SIG_IGN,
        .sa_restorer  = NULL,
    };
    sigaction(SIGUSR0, &sa, 0);
    // ignore SIGUSR0.

    int pid = fork();
    if (pid == 0) {
        // child
        sigkill(getpid(), SIGUSR0, 0); 
        // should have no effect, because parent ignores it.
        exit(1);
    } else {
        // parent
        int ret;
        wait(0, &ret);
        assert(ret == 1); // child should not be terminated by SIGUSR0
    }
}
//alarm(1) 是否能在 1 秒后向当前进程发送 SIGALRM 信号，并调用用户注册的 handler
void alarm_handler1(int signo, siginfo_t* info, void* ctx) {
    assert(signo == SIGALRM);
    printf("SIGALRM received\n");
    exit(88); // 用特定退出码判断 handler 是否成功调用
}

void alarm_basic1(char* s) {
    int pid = fork();
    if (pid == 0) {
        // 注册 SIGALRM 的 handler
        sigaction_t sa = {
            .sa_sigaction = alarm_handler1,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, 0);

        // 设置 1 秒后触发 SIGALRM
        int old = alarm(1);
        assert_eq(old, 0); // 应该无旧的 alarm

        // 阻塞一段时间等待 handler 执行
        sleep(100);
        // 如果 handler 没触发就会执行到这里，视为失败
        exit(-1);
    } else {
        int code;
        wait(0, &code);
        assert_eq(code, 88); // 验证子进程通过 handler 正常退出
    }
}

//如果调用 alarm(0)，应该取消之前设置的 alarm，SIGALRM 不应触发。
void alarm_basic2(char* s) {
    int pid = fork();
    if (pid == 0) {
        sigaction_t sa = {
            .sa_sigaction = alarm_handler1,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, 0);

        alarm(2); // 设置 2 秒
        alarm(0); // 马上取消

        // 如果 alarm 被取消，就不应该触发 handler
        sleep(300);
        exit(42);
    } else {
        int code;
        wait(0, &code);
        assert_eq(code, 42); // 应该按取消逻辑退出
    }
}

void alarm_handler3(int signo, siginfo_t* info, void* ctx) {
    printf("SIGALRM triggered unexpectedly!\n");
    exit(-1); // 不应该触发 handler
}

//第二次调用 alarm() 应该取消/替换之前设置的 alarm，仅保留最后一次的。
void alarm_basic3(char* s) {
    int pid = fork();
    if (pid == 0) {
        sigaction_t sa = {
            .sa_sigaction = alarm_handler3,
            .sa_restorer  = sigreturn,
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGALRM, &sa, 0);

        // 第一次设置 5 秒后触发
        alarm(5);

        // 2 秒后再设置成 1 秒，覆盖之前的
        sleep(200);
        unsigned int old = alarm(5);
        assert_eq(old, 3); // 原本还剩 3 秒

        sleep(400);
        exit(55); // 没有触发 handler，应正常退出
    } else {
        int code;
        wait(0, &code);
        assert_eq(code, 55);
    }
}




volatile int got_signal = 0;

void siginfo_handler(int signo, siginfo_t* info, void* ctx) {
    printf("signo: %d\n", info->si_signo);
    printf("si_code: %d\n", info->si_code);
    printf("si_pid: %d\n", info->si_pid);
    printf("si_status: %d\n", info->si_status);
    printf("addr: %p\n", info->addr);

    assert(signo == SIGUSR1);
    assert(info->si_signo == SIGUSR1);
    assert(info->si_pid > 0);  // 来自用户进程
    got_signal = 1;
}

void siginfo_test(char *s) {
    int pid = fork();
    if (pid == 0) {
        // 子
        sigaction_t sa = {
            .sa_sigaction = siginfo_handler,
            .sa_restorer  = sigreturn
        };
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, 0);

        while (!got_signal) {
            sleep(1); 
        }

        exit(123);
    } else {
        // 父
        sleep(3); // 等待子进程装载 handler
        sigkill(pid, SIGUSR1, 42); // code = 42

        int status;
        wait(0, &status);
        assert(status == 123);
    }
}



// === 新增：5.3.3 Checkpoint- SIGCHLD TEST START ===
volatile int sigchld_test_child_pid = 0;
volatile int sigchld_test_child_exit_code = 0;
volatile int sigchld_handler_called_count = 0;
const int EXPECTED_CHILD_EXIT_CODE = 42;

void sigchld_handler(int signo, siginfo_t *info, void *ucontext) {
    printf("SIGCHLD handler: signo=%d, child_pid=%d, child_exit_code=%d\n",
           signo, info->si_pid, info->si_code);
    // exit函数发送的SIGCHLD信号被do_signal处理后，调用sigchld_handler
    
    // 记录通知详情
    assert_eq(signo, SIGCHLD);
    sigchld_test_child_pid = info->si_pid; 
    sigchld_test_child_exit_code = info->si_code;
    sigchld_handler_called_count++;

    int status;
    int waited_pid = wait(info->si_pid, &status); // 回收子进程资源
    
    printf("SIGCHLD handler: wait() returned pid %d, status %d\n", waited_pid, status);

    assert_eq(waited_pid, info->si_pid);
    assert_eq(status, info->si_code);
}

void sigchld_test(char *s) {
    printf("Starting %s\n", s);

    sigchld_handler_called_count = 0; // Reset for the test
    sigaction_t sa;
    // 设置处理程序
    sa.sa_sigaction = sigchld_handler;
    sa.sa_restorer = sigreturn;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGCHLD, &sa, NULL) < 0) {
        printf("sigaction for SIGCHLD failed\n");
        exit(1); // Test failed
    }

    int child_pid = fork();

    if (child_pid < 0) {
        printf("fork failed\n");
        exit(1); // Test failed
    }

    if (child_pid == 0) {
        // 子进程执行
        printf("Child (PID %d): executing and will exit with code %d.\n", getpid(), EXPECTED_CHILD_EXIT_CODE);
        sleep(5); // 睡眠5个时间单位
        exit(EXPECTED_CHILD_EXIT_CODE); // 退出，退出码为42
    } else {
        // 父进程
        printf("Parent (PID %d): created child (PID %d). Waiting for SIGCHLD...\n", getpid(), child_pid);
        
        // 等待 handler 执行
        int timeout = 200;
        while(sigchld_handler_called_count == 0 && timeout > 0) {
            sleep(10); // Sleep for 100ms
            timeout--;
        }

        if (sigchld_handler_called_count == 0) {
            printf("TIMEOUT: SIGCHLD handler not called.\n");
            sigkill(child_pid, SIGKILL, 0); // Clean up child if it's stuck
            wait(child_pid, 0);
            exit(1); // Test failed
        }
        
        // 检查通知系统是否工作正常
        printf("Parent: SIGCHLD handler was called %d time(s).\n", sigchld_handler_called_count);
        assert_eq(sigchld_handler_called_count, 1); // For one child, handler should be called once.
        assert_eq(sigchld_test_child_pid, child_pid);
        assert_eq(sigchld_test_child_exit_code, EXPECTED_CHILD_EXIT_CODE);

        printf("Parent: Test assertions passed.\n");
        int status_ignored;
        // 防止重复处理
        int wait_again_pid = wait(child_pid, &status_ignored);
        if (wait_again_pid == child_pid) {
            printf("ERROR: Child %d was reaped again by parent's main flow. It should have been reaped in handler.\n", child_pid);
            exit(1); // Test failed
        } else {
            printf("Parent: Confirmed child %d was not reaped again (wait returned %d), as expected.\n", child_pid, wait_again_pid);
        }
        exit(0); // Test success
    }
}
// === 新增：5.3.3 Checkpoint- SIGCHLD TEST END ===