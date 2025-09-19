#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <wordexp.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sendfile.h>

#define UNIT_DIR "/etc/trinity"
#define LOG_DIR "/var/log/trinity"
#define RUN_DIR "/run/trinity"
#define CONTROL_SOCKET RUN_DIR "/trinity.sock"
#define CGROUP_ROOT "/sys/fs/cgroup"
#define CGROUP_PREFIX "trinity.slice"

#define MAX_UNITS 512
#define MAX_LINE 2048
#define LOG_BUF 2048

#define DEFAULT_RESTART_SECS 2
#define DEFAULT_STARTLIMIT_INTERVAL 10
#define DEFAULT_STARTLIMIT_BURST 5
#define STOP_GRACE_SEC 5

#define UNIT_IMMORTAL (1<<0)   
#define UNIT_CHILD    (1<<1)

typedef enum {
    US_INACTIVE = 0,
    US_ACTIVATING,
    US_ACTIVE,
    US_DEACTIVATING,
    US_FAILED,
    US_RESTART_SCHEDULED
} ustate_t;

typedef enum {
    RM_NO = 0, 
    RM_ONFAIL,
    RM_ALWAYS
} rmode_t;

typedef struct unit {
    char name[128];
    char desc[256];
    char exec[MAX_LINE];
    char after[512];
    char envlines[1024];
    char envfile[PATH_MAX];
    char workdir[PATH_MAX];
    char user[64];
    char group[64];
    char mem_max[64];
    char cpu_max[64];

    rmode_t restart;
    int restart_sec;
    int startlimit_burst;
    int startlimit_interval;

    pid_t pid;
    ustate_t state;
    int start_count;
    time_t last_start_time;
    unsigned long long start_time;
    int ndeps;
    struct unit *deps[16];

    char cgroup_path[PATH_MAX];
    int flags;
    int exitStatus;

    int restart_timerfd;
} unit_t;

unit_t units[MAX_UNITS];
int n_units = 0;
int epoll_fd = -1;
// int signal_fd = -1;
int signalfd_fd = -1;
int control_fd = -1;
volatile sig_atomic_t shutting_down = 0;

//utils

void logmsg(const char *fmt, ...) {
    char buf[LOG_BUF];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(stdout, "[%ld.%03ld] %s\n", (long)ts.tv_sec, ts.tv_nsec/1000000, buf);
    fflush(stdout);
}

void trim(char *s) {
    char *p = s;
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    for (int i = (int)strlen(s) - 1; i >=0; --i) {
        if (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n') s[i] = 0;
        else break;
    }
}

char *stripQuotes(char *s) {
    trim(s);
    int len = (int)strlen(s);
    if (len >= 2 && ((s[0]=='"' && s[len-1]=='"') || (s[0]=='\'' && s[len-1]=='\''))) {
        s[len-1] = 0;
        return s+1;
    }
    return s;
}

int isFileExist(const char *p) {
    struct stat st;
    return stat(p, &st) == 0;
}

int isPidAlive(pid_t pid) {
    if (pid <= 0) return 0;
    if (kill(pid, 0) == 0) return 1;
    if (errno == EPERM) return 1;
    return 0;
}

static unsigned long long getStartProcTime(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    char buf[8192];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);

    char *rp = strrchr(buf, ')');
    if (!rp) return 0;
    char *p = rp + 1;
    if (*p == '\0') return 0;

    char *saveptr = NULL;
    char *tok = strtok_r(p, " ", &saveptr);
    if (!tok) return 0;

    int field = 3;
    unsigned long long start_time = 0;
    while (tok) {
        if (field == 22) {
            start_time = strtoull(tok, NULL, 10);
            break;
        }
        tok = strtok_r(NULL, " ", &saveptr);
        field++;
    }
    return start_time;
}

static int reapChildBlocking(pid_t pid, int *outStatus) {
    int status = 0;
    pid_t r;
    do {
        r = waitpid(pid, &status, 0);
    } while (r == -1 && errno == EINTR);

    if (r == pid) {
        if (outStatus) *outStatus = status;
        return 1;
    }
    if (r == -1 && errno == ECHILD) {
        return 0;
    }
    return -1;
}

static int reapChildNonBlocking(pid_t pid, int *outStatus) {
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid) {
        if (outStatus) *outStatus = status;
        return 1;
    }
    if (r == 0) return 0;
    if (errno == ECHILD) return 0;
    return -1;
}

int readFileToBuf(const char *path, char *buf, size_t buflen) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t off = 0;
    while (fgets(buf + off, (int)(buflen - off), f)) {
        off = strlen(buf);
        if (off >= buflen - 1) break;
    }
    fclose(f);
    return 0;
}

//parsing units

int parseUnitFile(const char *path, unit_t *u) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char tmp[MAX_LINE];
        strncpy(tmp, line, sizeof(tmp)- 1);
        trim(tmp);
        if (!tmp[0]) continue;
        if (tmp[0] == '#' || tmp[0] == ';') continue;
        char *eq = strchr(tmp, '=');
        if (!eq) continue;
        *eq = 0;
        char key[256], val[MAX_LINE];
        snprintf(key, sizeof(key), "%s", tmp);
        snprintf(val, sizeof(val), "%s", eq+1);
        trim(key); trim(val);
         if (!strcasecmp(key, "ExecStart")) {
            strncpy(u->exec, stripQuotes(val), sizeof(u->exec)-1);
        } else if (!strcasecmp(key, "Restart")) {
            if (!strcasecmp(val, "always")) u->restart = RM_ALWAYS;
            else if (!strcasecmp(val, "on-failure")) u->restart = RM_ONFAIL;
            else u->restart = RM_NO;
        } else if (!strcasecmp(key, "RestartSec")) {
            u->restart_sec = atoi(val);
        } else if (!strcasecmp(key, "StartLimitBurst")) {
            u->startlimit_burst = atoi(val);
        } else if (!strcasecmp(key, "StartLimitInterval")) {
            u->startlimit_interval = atoi(val);
        } else if (!strcasecmp(key, "After")) {
            strncpy(u->after, val, sizeof(u->after)-1);
        } else if (!strcasecmp(key, "Description")) {
            strncpy(u->desc, stripQuotes(val), sizeof(u->desc)-1);
        } else if (!strcasecmp(key, "User")) {
            strncpy(u->user, val, sizeof(u->user)-1);
        } else if (!strcasecmp(key, "Group")) {
            strncpy(u->group, val, sizeof(u->group)-1);
        } else if (!strcasecmp(key, "Environment")) {
            if (u->envlines[0]) strncat(u->envlines, "\n", sizeof(u->envlines)-strlen(u->envlines)-1);
            strncat(u->envlines, val, sizeof(u->envlines)-strlen(u->envlines)-1);
        } else if (!strcasecmp(key, "EnvironmentFile")) {
            strncpy(u->envfile, stripQuotes(val), sizeof(u->envfile)-1);
        } else if (!strcasecmp(key, "WorkingDirectory")) {
            strncpy(u->workdir, stripQuotes(val), sizeof(u->workdir)-1);
        } else if (!strcasecmp(key, "MemoryMax")) {
            strncpy(u->mem_max, val, sizeof(u->mem_max)-1);
        } else if (!strcasecmp(key, "CPU.max") || !strcasecmp(key, "CPUQuota")) {
            strncpy(u->cpu_max, val, sizeof(u->cpu_max)-1);
        }
    }
    fclose(f);
    if (u->restart_sec <= 0) u->restart_sec = DEFAULT_RESTART_SECS;
    if (u->startlimit_burst <= 0) u->startlimit_burst = DEFAULT_STARTLIMIT_BURST;
    if (u->startlimit_interval <= 0) u->startlimit_interval = DEFAULT_STARTLIMIT_INTERVAL;
    return 0;
}

//loading unitss

int loadUnits(void) {
    DIR *d = opendir(UNIT_DIR);
    if (!d) return -1;
    struct dirent *ent;
    n_units = 0;
    while ((ent = readdir(d)) && n_units < MAX_UNITS) {
        if (ent->d_type != DT_REG && ent->d_type != DT_UNKNOWN) continue;
        const char *name = ent->d_name;
        size_t l = strlen(name);
        if (l > 8 && strcmp(name + l - 8, ".service") == 0) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", UNIT_DIR, name);
            unit_t *u = &units[n_units];
            memset(u, 0, sizeof(unit_t));
            strncpy(u->name, name, sizeof(u->name)-1);
            char *dot = strstr(u->name, ".service"); if (dot) *dot = 0;
            u->restart = RM_NO;
            u->state = US_INACTIVE;
            u->restart_timerfd = -1;
            if (parseUnitFile(path, u) == 0) {
                logmsg("loaded unit %s -> '%s'", u->name, u->exec);
                n_units++;
            } else {
                logmsg("failed to parse %s", path);
            }
        }
    }
    closedir(d);
    return n_units;
}

unit_t *findUnitByName(const char *name) {
    for (int i = 0; i < n_units; ++i) {
        if (strcmp(units[i].name, name) == 0) return &units[i];
    }
    return NULL;
}

//dependency building. and start order

void buildDeps(void) {
    for (int i = 0; i < n_units; ++i) {
        unit_t *u = &units[i];
        if (u->after[0] == 0) continue;
        char buf[512]; 
        strncpy(buf, u->after, sizeof(buf)-1);
        char *save = NULL;
        char *tok = strtok_r(buf, ",", &save);
        while(tok) {
            trim(tok);
            unit_t *d = findUnitByName(tok);
            if (d) {
                if (u->ndeps < (int)(sizeof(u->deps)/sizeof(u->deps[0]))) {
                    u->deps[u->ndeps++] = d;
                    logmsg("dep: %s after %s", u->name, d->name);
                }
            } else {
                logmsg("warning: %s references unknown After=%s", u->name, tok);
            }
            tok = strtok_r(NULL, ",", &save);
        }
    }
}

int start_order[MAX_UNITS];
int start_order_n = 0;
int visited[MAX_UNITS];

int index_of(unit_t *u) {
    for (int i = 0; i < n_units; ++i) if (&units[i] == u) return i;
    return -1;
}

int dfs(unit_t *u) {
    int idx = index_of(u);
    if (idx < 0) return 0;
    if (visited[idx] == 1) {
        logmsg("ERROR: Dependency cycle involving %s", u->name);
        return -1;
    }
    if (visited[idx] == 2) return 0;
    visited[idx] = 1;
    for (int i = 0; i < u->ndeps; ++i) {
        if (dfs(u->deps[i]) < 0) return -1;
    }
    visited[idx] = 2;
    start_order[start_order_n++] = idx;
    return 0;
}

int computeStartOrder(void) {
    memset(visited, 0, sizeof(visited));
    start_order_n = 0;
    for (int i = 0; i < n_units; ++i) {
        if (!visited[i]) {
            if (dfs(&units[i]) < 0) return -1;
        }
    }
    return 0;
}

//cgroups

//parsing envp and argv 

char **prepareEnv(unit_t *u) {
    extern char **environ;
    size_t base = 0;
    size_t new = 0;
    for (char **e = environ; e && *e; ++e) 
        base++;
    char *tmp = NULL;

    if (u->envlines[0]) {
        tmp = strdup(u->envlines);
        char *save = NULL;
        char *tok = strtok_r(tmp, "\n", &save);
        while (tok) {
            new++;
            tok = strtok_r(NULL, "\n", &save);
        }
        free(tmp);
    }

    if (u->envfile) {
        char buf[4096] = {0};
        if (readFileToBuf(u->envfile, buf, sizeof(buf)) == 0) {
            tmp = strdup(buf);
            char *save = NULL;
            char *tok = strtok_r(tmp, "\n", &save);
            while (tok) {
                trim(tok);
                if (tok[0]) new++;
                tok = strtok_r(NULL, "\n", &save);
            }
        } free(tmp);
    }

    size_t total = base + new + 2;
    char **envp = calloc(total, sizeof(char *));
    size_t i = 0;
    for (char **e = environ; e && *e; ++e) 
        envp[i++] = strdup(*e);

    if (u->envlines[0]) {
        tmp = strdup(u->envlines);
        char *save = NULL;
        char *tok = strtok_r(tmp, "\n", &save);
        while (tok) {
            trim(tok);
            if (tok[0])
                envp[i++] = strdup(tok);
            tok = strtok_r(NULL, "\n", &save);    
        }
        free(tmp);
    }

    if (u->envfile[0]) {
        char buf[4096] = {0};
        if (readFileToBuf(u->envfile, buf, sizeof(buf)) == 0) {
            tmp = strdup(buf);
            char *save = NULL;
            char *tok = strtok_r(tmp, "\n", &save);
            while (tok) {
                trim(tok);
                if(tok[0] && tok[0] != '#') 
                    envp[i++] = strdup(tok);
                tok = strtok_r(NULL, "\n", &save);
            }
        } free(tmp);
    }
    envp[i] = NULL;
    return envp;
}

static void freeEnvp(char **envp) {
    if (!envp) return;
    for (char **p = envp; *p; ++p) free(*p);
    free(envp);
}

static char **prepareArgv(const char *cmd) {
    if (!cmd || !*cmd) return NULL;
    wordexp_t p;
    if (wordexp(cmd, &p, 0) != 0) return NULL;
    char **argv = calloc(p.we_wordc + 1, sizeof(char *));
    for (size_t i = 0; i < p.we_wordc; ++i) argv[i] = strdup(p.we_wordv[i]);
    argv[p.we_wordc] = NULL;
    wordfree(&p);
    return argv;
}

static void freeArgv(char **argv) {
    if (!argv) return;
    for (char **p = argv; *p; ++p) free(*p);
    free(argv);
}

//dropping privileges

static int dropPrivileges(const char *user, const char *group) {
    if (!user || user[0] == 0) return 0;
    struct passwd *pw = getpwnam(user);
    if(!pw) {
        logmsg("unknown user %s", user);
        return -1;
    }
    gid_t gid = pw->pw_gid;
    uid_t uid = pw->pw_uid;

    if (group && group[0]) {
        struct group *gr = getgrnam(group);
        if (gr) gid = gr->gr_gid;
    }

    if (initgroups(pw->pw_name, gid) != 0) {
        logmsg("initgroups filed for %s : %s", user, strerror(errno));
    }

    if(setgid(gid) != 0) {
        logmsg("setgid(%d) failed: %s", (int)gid, strerror(errno));
        return -1;
    }

    if(setuid(uid) != 0) {
        logmsg("setuid(%d) failed: %s", (int)uid, strerror(errno));
        return -1;
    }

    return 0;
}

static int openUnitLog(unit_t *u) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, u->name);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if (fd < 0) {
        logmsg("cannot open log %s:%s", path, strerror(errno));
    }
    return fd;
}

//starting service

static int startUnit(unit_t *u) {
    if (u->state == US_ACTIVE || u->state == US_ACTIVATING || u->state == US_RESTART_SCHEDULED) return 0;

    time_t now = time(NULL);
    if (u->last_start_time && (now - u->last_start_time) <= u->startlimit_interval) {
        if (u->start_count >= u->startlimit_burst) {
            logmsg("unit %s entered start limit (burst=%d interval=%d)", u->name, u->startlimit_burst, u->startlimit_interval);
            u->state = US_FAILED;
            return -1;
        }
    } else {
        u->start_count = 0;
    }
    
    u->start_count++;
    u->last_start_time = now;
    u->state = US_ACTIVATING;

    pid_t pid = fork();
    if (pid < 0) {
        logmsg("fork failed for %s : %s", u->name, strerror(errno));
        u->state = US_FAILED;
        return -1;
    }
    if (pid == 0) {
        setsid();
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        int logfd = openUnitLog(u);
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
            if (logfd > 2) close(logfd);
        } else {
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                if (devnull > 2) close(devnull);
            }
        }

        if(u->workdir[0]) {
            if (chdir(u->workdir) != 0) {
                logmsg("could not cd to %s:%s", u->workdir, strerror(errno));
            }
        } else {
            chdir("/");
        }


        char **envp = prepareEnv(u);
        char **argv = prepareArgv(u->exec);
        if (!argv || !argv[0]) {
            logmsg("invalid ExecStart for %s", u->name);
            _exit(127);
        }

        if(u->user[0]) {
            if (dropPrivileges(u->user, u->group) != 0) {
                logmsg("failed dropping privileges for %s", u->name);
                _exit(127);
            }
        }
        
        execve(argv[0], argv, envp);

        logmsg("execve failed for %s: %s", u->name, strerror(errno));
        _exit(127);
    } else {
        u->pid = pid;
        u->flags |= UNIT_CHILD;
        u->state = US_ACTIVATING;
        usleep(100 * 1000);
        if (isPidAlive(pid)) {
            u->state = US_ACTIVE;
        } else {
            logmsg("unit %s (pid=%d) died right after spawn", u->name, pid);
            u->state = US_FAILED;
            return -1;
        }
        u->start_time = getStartProcTime(pid);
        if (!u->start_time) {
        logmsg("Warning: failed to record start_time for %s (pid=%d)", u->name, pid);
        }   
        logmsg("started %s pid=%d", u->name, pid);
        return 0;
    }
}

//stoppping service

static void stopUnit(unit_t *u) {
    if (!u) return;

    if (u->state != US_ACTIVE && u->state != US_ACTIVATING) return;

    if (u->flags & UNIT_IMMORTAL) {
        logmsg("FATAL: refusing to stop immortal unit: %s", u->name);
        return;
    }

    if (u->pid == 1) {
        logmsg("FATAL: attempting to kill init! aborting stop operation");
        return;
    }

    if (u->pid <= 1) {
        logmsg("FATAL: Attempted to stop a critical system process (PID %d) (Name %s). Aborting.", u->pid, u->name);
        return;
    }

    u->state = US_DEACTIVATING;
    logmsg("stopping unit %s, PID %d", u->name, u->pid);

    unsigned long long curStart = getStartProcTime(u->pid);
    if (curStart == 0) {
        logmsg("unit %s PID %d not present.", u->name, u->pid);
        u->pid = 0;
        u->state = US_INACTIVE;
        return;
    }

    if (u->start_time && curStart != u->start_time) {
        logmsg("unit %s PID %d, start time mismatch (expected %llu got %llu).", u->name, u->pid, u->start_time, curStart);
        u->pid = 0;
        u->state = US_INACTIVE;
        return;
    }

    int sigErr = 0;
    sigErr = kill(u->pid, SIGTERM);

    if (sigErr < 0 && errno == ESRCH) {
        logmsg("unit %s PID %d, is already gone after TERM.",  u->name, u->pid);
        u->pid = 0;
        u->state = US_INACTIVE;
        return;
    } else if (sigErr < 0) {
        logmsg("Error sending SIGTERM to %s (pid %d): %s", u->name, u->pid, strerror(errno));
    }

    struct timespec t0, tnow;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    const long grace = STOP_GRACE_SEC * 1000L;
    long elapsed = 0;

    while (elapsed < grace) {
        if (u->flags & UNIT_CHILD) {
            int r = reapChildNonBlocking(u->pid, &u->exitStatus);
            if (r == 1) {
                logmsg("unit %s PID %d exited cleanly. status 0x%x", u->name, u->pid, u->exitStatus);
                u->pid = 0;
                u->state = US_INACTIVE;
                return;
            } else if (r == -1) {
                logmsg("waitpid error while waiting for %s: %s", u->name, strerror(errno));
                u->state = US_FAILED;
                return;
            } 
        } else {
            if (!isPidAlive(u->pid)) {
                logmsg("unit %s PID %d disappeared during grace period", u->name, u->pid);
                u->pid = 0;
                u->state = US_INACTIVE;
                return;
            }
        }    
        
        unsigned long long nowStart = getStartProcTime(u->pid);
        if (nowStart == 0) {
            logmsg("Unit %s PID %d vanished (no proc entry).", u->name, u->pid);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        }
        if (u->start_time && nowStart != u->start_time) {
            logmsg("unit %s PID %d was recycled (start_time changed). skipping kills", u->name, u->pid);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        }

        struct timespec sleep_ts = {0, 100 * 1000 * 1000};
        nanosleep(&sleep_ts, NULL);

        clock_gettime(CLOCK_MONOTONIC, &tnow);
        elapsed = (tnow.tv_sec - t0.tv_sec) * 1000L + (tnow.tv_nsec - t0.tv_nsec) / 1000000L;
    }

    unsigned long long finalStart = getStartProcTime(u->pid);
    if (finalStart == 0) {
        logmsg("unit %s PID %d gone at grace-time.", u->name, u->pid);
        u->pid = 0;
        u->state = US_INACTIVE;
        return;
    }
    if (u->start_time && finalStart != u->start_time) {
        logmsg("Unit %s: pid %d recycled before kill. skipping SIGKILL.", u->name, u->pid);
        u->pid = 0;
        u->state = US_INACTIVE;
        return;
    }

    logmsg("Unit %s did not exit after %d sec; sending SIGKILL to pid %d.", u->name, STOP_GRACE_SEC, u->pid);
    if (kill(u->pid, SIGKILL) < 0) {
        if (errno == ESRCH) {
            logmsg("Unit %s: pid %d vanished before SIGKILL.", u->name, u->pid);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        }
        logmsg("Error sending SIGKILL to %s: %s", u->name, strerror(errno));
    }

    if (u->flags & UNIT_CHILD) {
        int reapRes = reapChildBlocking(u->pid, &u->exitStatus);
        if (reapRes == 1) {
            logmsg("Unit %s (pid %d) reaped after SIGKILL (status 0x%x).", u->name, u->pid, u->exitStatus);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        } else if (reapRes == 0) {
            logmsg("Unit %s: not our child when reaping; treating as gone.", u->name);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        } else {
            logmsg("Error reaping %s after SIGKILL: %s", u->name, strerror(errno));
            u->state = US_FAILED;
            return;
        }
    } else {
        const int pollCycles = 10;
        int alive = 1;
        for (int i = 0; i < pollCycles; ++i) {
            if (!isPidAlive(u->pid)) {
                alive = 0;
                break;
            }
            struct timespec st = {0, 100 * 1000 * 1000};
            nanosleep(&st, NULL);
        } 
        if (!alive) {
            logmsg("unit %s terminated after SIGKILL.", u->name);
            u->pid = 0;
            u->state = US_INACTIVE;
            return;
        } else {
            logmsg("Unit %s: pid %d still alive after SIGKILL; giving up (marking FAILED).", u->name, u->pid);
            u->state = US_FAILED;
            return;
        }
    }
}

//restaring service

static int startRestart(unit_t *u, int secs) {
    if (secs <= 0) secs = DEFAULT_RESTART_SECS;
    if (u->restart_timerfd < 0) {
        u->restart_timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (u->restart_timerfd < 0) {
            logmsg("timerfd create failed: %s", strerror(errno));
            return -1;
        }
        struct epoll_event ev = { .events = EPOLLIN, .data.ptr = u};
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, u->restart_timerfd, &ev) < 0) {
            logmsg("epoll_ctl add timerfd failed: %s", strerror(errno));
            close(u->restart_timerfd);
            u->restart_timerfd = -1;
            return -1;
        }
    }
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    its.it_value.tv_sec = secs;
    if (timerfd_settime(u->restart_timerfd, 0, &its, NULL ) < 0) {
        logmsg("timerfd_settime failed: %s", strerror(errno));
        return -1;
    }
    u->state = US_RESTART_SCHEDULED;
    return 0;
}

static void cancelRestart(unit_t *u) {
    if (u->restart_timerfd >= 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, u->restart_timerfd, NULL);
        close(u->restart_timerfd);
        u->restart_timerfd = -1;
    }
}

//child exit

static void handleChildExit(pid_t pid, int status) {
    for (int i = 0; i < n_units; ++i) {
        unit_t *u = &units[i];
        if (u->pid == pid) {
            int exitcode = -1;
            if (WIFEXITED(status)) exitcode = WEXITSTATUS(status);
            logmsg("unit %s pid=%d exited status=%d", u->name, pid, exitcode);
            u->pid = 0;
            if (WIFEXITED(status) && exitcode == 0) {
                u->state = US_INACTIVE;
            } else {
                u->state = US_FAILED;
            }
            if (!shutting_down) {
                if(u->restart == RM_ALWAYS || (u->restart == RM_ONFAIL && !(WIFEXITED(status) && exitcode == 0))) {
                    startRestart(u, u->restart_sec);
                }
            }
            break;
        }
    }
}

//signal handling
static int setupSignalfd(void) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
        logmsg("sigprocmask failed: %s", strerror(errno));
        return -1;
    }
    signalfd_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signalfd_fd < 0) {
        logmsg("signalfd failed: %s", strerror(errno));
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN, .data.fd = signalfd_fd};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, signalfd_fd, &ev) < 0) {
        logmsg("epoll_ctl add signalfd failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

//socket

//start stop all
static void startAll(void) {
    for (int i = 0; i < start_order_n; ++i) {
        unit_t *u = &units[start_order[i]];
        if (u->exec[0]) {
            startUnit(u);
            usleep(100*1000);
        }
    }
}

static void stopAll(void) {
    shutting_down = 1;
    for (int i = start_order_n - 1; i >= 0; --i) {
        unit_t *u = &units[start_order[i]];
        if(u->state == US_ACTIVE || u->state == US_ACTIVATING) {
            stopUnit(u);
        }
    }
}

//event loop main
static void runEventLoop(void) {
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if(epoll_fd < 0) {
        logmsg("epoll_create1 failed: %s", strerror(errno));
        return;
    }
    if (setupSignalfd() < 0) {
        logmsg("cannot setup signalfd");
        return;
    }
    struct epoll_event events[32];
    while(!shutting_down) {
        int n = epoll_wait(epoll_fd, events, 32, -1);
        if (n < 0) {
            if (errno == EINTR) continue;
            logmsg("epoll_wait failed: %s", strerror(errno));
            break;
        }
        for (int i = 0; i < n; ++i) {
            struct epoll_event *ev = &events[i];
            if (ev->data.fd == signalfd_fd) {
                struct signalfd_siginfo si;
                while (read(signalfd_fd, &si, sizeof(si)) == sizeof(si)) {
                    if(si.ssi_signo == SIGCHLD) {
                        int status;
                        pid_t pid;
                        while((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                            handleChildExit(pid, status);
                        }
                    } else if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
                        logmsg("termination request recieved");
                        shutting_down = 1;
                    }
                }
            } else {
                unit_t *u = (unit_t *)ev->data.ptr;
                if (!u) continue;
                if(u->restart_timerfd >= 0 && ev->events & EPOLLIN) {
                    uint64_t expirations;
                    read(u->restart_timerfd, &expirations, sizeof(expirations));
                    close(u->restart_timerfd);
                    u->restart_timerfd = -1;
                    logmsg("restart timer expired for %s, attempting start", u->name);
                    startUnit(u);
                }
            }

        }
    }
    logmsg("event loop exiting, shutting down untis");
    stopAll();
}

static void setupBasicDirs(void) {
    mkdir(LOG_DIR, 0755);
    mkdir(RUN_DIR, 0755);
}

int main(int argc, char **argv) {
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    // setupBasicDirs();

    if(loadUnits() <= 0) {
        logmsg("no units found under %s", UNIT_DIR);
    }

    buildDeps();
    if (computeStartOrder() < 0) {
        logmsg("dependency resolution failed; continuing but order may be incomplete");
    }

    for (int i = 0; i < n_units; ++i) {
        units[i].restart_timerfd = -1;
    }

    startAll();
    runEventLoop();
    logmsg("[ Trinity ]: exiting");
    return 0;
}
