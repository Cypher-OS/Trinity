#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <sys/reboot.h>
#include <time.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <limits.h>

#define SHELL "/bin/bash"
#define LOG_PATH "/var/log/initrinity.log"

static volatile sig_atomic_t sigchldFlag = 0;
static volatile sig_atomic_t sigtermFlag = 0;
static volatile sig_atomic_t sighupFlag = 0;

static int logfd = -1;
static int use_syslog_fallback = 0;
static void tryOpenLog(void);

static void xlog(const char *fmt, ...) {
    char buf[512];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    int n = snprintf(buf, sizeof(buf), "[%ld.%03ld] ", (long)ts.tv_sec, ts.tv_nsec/1000000);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + n, sizeof(buf) - n, fmt, ap);
    va_end(ap);
    size_t l = strlen(buf);
    if (l == 0) return;
    if (buf[l-1] != '\n') {
        if (l < sizeof(buf) - 1) {
            buf[l] = '\n';
            buf[l+1] = '\0';
            l++;
        }
    }
    if (logfd >= 0) {
        ssize_t r = write(logfd, buf, strlen(buf));
        (void)r;
    } else {
        syslog(LOG_INFO, "%s", buf);
    }
}

static void klog(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    va_end(ap);
    size_t len = strlen(buf);
    if (len == 0) return;
    if (buf[len - 1] != '\n') {
        if (len < sizeof(buf) - 1) {
            buf[len++] = '\n';
            buf[len] = '\0';
        }
    }

    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        int r = write(fd, buf, len);
        (void)r;
        close(fd);
    }
}

static void sigchldHandler(int sig) {
    (void)sig;
    sigchldFlag = 1;
}

static void sigtermHandler(int sig) {
    (void)sig;
    sigtermFlag = 1;
}

static void sighupHandler(int sig) {
    (void)sig;
    sighupFlag = 1;
}

static void setupSignals() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchldHandler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGCHLD, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigtermHandler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sighupHandler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGHUP, &sa, NULL);
} 

static void reapChildren() {
    int status;
    pid_t pid;
    while (1) {
        pid = waitpid(-1, &status, WNOHANG);
        if (pid == 0) break;
        if (pid == -1) {
            if (errno == ECHILD) break;
            if (errno == EINTR) continue;
            xlog("waitpid error: %s", strerror(errno));
            break;
        }
    }
}

static void shutdown() {
    klog("shutting down Cypher!");

    reapChildren();
    sync();
    umount2("/sys", MNT_DETACH);
    umount2("/proc", MNT_DETACH);
    umount2("/dev", MNT_DETACH);
    umount2("/run", MNT_DETACH);
    umount2("/tmp", MNT_DETACH);

    if(reboot(RB_POWER_OFF) == -1) {
        klog("reboot failed!");
        mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
        int fd = open("/dev/console", O_RDWR);
        if (fd >= 0) {
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        }
        execl("/bin/sh", "sh", NULL);   
    }
}

static void tryOpenLog() {
    if (logfd >= 0) return;
    int fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        logfd = fd;
        use_syslog_fallback = 0;
        xlog("log opened: %s", LOG_PATH);
    } else {
        openlog("cypherd", LOG_PID | LOG_CONS, LOG_DAEMON);
        syslog(LOG_ERR, "cannot open log file %s: %s", LOG_PATH, strerror(errno));
        use_syslog_fallback = 1;
        logfd = -1;
    }
}

static void mountEssentials() {

    mkdir("/dev/pts", 0755);
    mkdir("/dev/shm", 0755);

    if (mount("proc", "/proc", "proc", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /proc failed!: %s", strerror(errno));
    } else klog("mounted /proc.");
    
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /sys failed!: %s", strerror(errno));
    } else klog("mounted /sys.");

    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /dev failed!: %s", strerror(errno));
    } else klog("mounted /dev.");

    if (mount("devpts", "/dev/pts", "devpts", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /dev/pts failed!: %s", strerror(errno));
    } else klog("mounted /dev/pts.");

    if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID|MS_NODEV, NULL) == -1 && errno != EBUSY) {
        klog("mounting /dev/shm failed!: %s", strerror(errno));
    } else klog("mounted /dev.shm.");

    if (mount("tmpfs", "/run", "tmpfs", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /run failed!: %s", strerror(errno));
    } else klog("mounted /run.");

    if (mount("cgroup2","/sys/fs/cgroup", "cgroup2", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /cgroup/cgroup2 failed!: %s", strerror(errno));
    } else klog("mounted /cgroup/cgroup2.");

    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) == -1 && errno != EBUSY) {
        klog("mounting /tmp failed!: %s", strerror(errno));
    } else klog("mounted /tmp.");
}

static void spawnGetty(void) {
    pid_t pid;
    while(1) {
        pid = fork();
        if (pid == 0) {
        int fd = open("/dev/ttyS0", O_RDWR);
        klog("STARTING BASHHHH");
            if (fd < 0) {
                _exit(1);
            }
            if (setsid() < 0) {
                _exit(1);
            }
            if (ioctl(fd, TIOCSCTTY, 1) < 0) {
                _exit(1);
            }
            dup2(fd, STDIN_FILENO);
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            if (fd > 2) close(fd);
        // klog("gettyyyy starting");
        // execlp("agetty", "agetty", "-L", "ttyS0", "115200", "vt100", (char*)NULL);
        // klog("gettyyyy failed");
        // _exit(127);
        } else if (pid > 0) {
            klog("getty spawned pid=%d", pid);
        } else {
            klog("getty fork failed: %s", strerror(errno));
        }
}
}

int main() {
    if (geteuid() != 0){
        fprintf(stderr, "INIT should be run by a superuser!\n");
        _exit(1);
    }

    if (getpid() != 1) {
        fprintf(stderr, "INIT should be PID 1!\n");
        return 1;
    }

    umask(0022);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 0);
    
    sigset_t block, old;
    sigemptyset(&block);
    sigaddset(&block, SIGCHLD);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    sigprocmask(SIG_BLOCK, &block, &old);

    mountEssentials();
    setupSignals();
    spawnGetty();
    pid_t pid = fork();
    if (pid == 0) {
        execl("/sbin/trinity", "trinity",  NULL);
        klog("exec trinity failed");
        _exit(127);
    }
    klog("Trinity started as pid=%d", pid);


    sigprocmask(SIG_SETMASK, &old, NULL);

    sigset_t emptymask;
    sigemptyset(&emptymask);

    while(1) {
        if (sigchldFlag) {
            sigchldFlag = 0;
            reapChildren();
        }
        if (sighupFlag) {
            sighupFlag = 0;
            tryOpenLog();
        }
        if (sigtermFlag) {
            sigtermFlag = 0;
            shutdown();
        }
        sigsuspend(&emptymask);
    }
    return 0;
}

