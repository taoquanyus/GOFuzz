/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - map display utility
   ----------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   Exit code is 2 if the target program crashes; 1 if it times out or
   there is a problem executing it; or 0 if execution is successful.
*/

#define AFL_MAIN
#define _GNU_SOURCE

#include "android-ashmem.h"

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sched.h>

#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include "aflnet.h"

#define server_wait_usecs 10000

unsigned int *
(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;

/* Expected arguments:
1. Path to the test case (e.g., crash-triggering input)
2. Application protocol (e.g., RTSP, FTP)
3. Server's network port
Optional:
4. First response timeout (ms), default 1
5. Follow-up responses timeout (us), default 1000
*/
s32 opt;
u8 mem_limit_given = 0, timeout_given = 0, qemu_mode = 0;
u32 tcnt;
char **use_argv;
char *protocol;

static u8 *netns_name; /* network namespace name to run server in */

FILE *fp;
int portno, n;
struct sockaddr_in serv_addr;
char *buf = NULL, *response_buf = NULL;
int response_buf_size = 0;
unsigned int size, i, state_count, packet_count = 0;
unsigned int *state_sequence;
unsigned int socket_timeout = 1000;
unsigned int poll_timeout = 1;


static s32 child_pid;                 /* PID of the tested program         */

static u8 *trace_bits;                /* SHM with instrumentation bitmap   */

static u8 *out_file,                  /* Trace output file                 */
*doc_path,                  /* Path to docs                      */
*target_path,               /* Path to target binary             */
*at_file;                   /* Substitution string for @@        */

static u32 exec_tmout;                /* Exec timeout (ms)                 */

static u64 mem_limit = MEM_LIMIT;     /* Memory limit (MB)                 */

static s32 shm_id;                    /* ID of the SHM region              */

static u8 quiet_mode,                /* Hide non-essential messages?      */
edges_only,                /* Ignore hit counts?                */
cmin_mode,                 /* Generate output in afl-cmin mode? */
binary_mode,               /* Write output as a binary map      */
keep_cores;                /* Allow coredumps?                  */

static volatile u8
        stop_soon,                 /* Ctrl-C pressed?                   */
child_timed_out,           /* Child timed out?                  */
child_crashed;             /* Child crashed?                    */

/* Classify tuple counts. Instead of mapping to individual bits, as in
   afl-fuzz.c, we map to more user-friendly numbers between 1 and 8. */

static const u8 count_class_human[256] = {

        [0]           = 0,
        [1]           = 1,
        [2]           = 2,
        [3]           = 3,
        [4 ... 7]     = 4,
        [8 ... 15]    = 5,
        [16 ... 31]   = 6,
        [32 ... 127]  = 7,
        [128 ... 255] = 8

};

static const u8 count_class_binary[256] = {

        [0]           = 0,
        [1]           = 1,
        [2]           = 2,
        [3]           = 4,
        [4 ... 7]     = 8,
        [8 ... 15]    = 16,
        [16 ... 31]   = 32,
        [32 ... 127]  = 64,
        [128 ... 255] = 128

};

static void classify_counts(u8 *mem, const u8 *map) {

    u32 i = MAP_SIZE;

    if (edges_only) {

        while (i--) {
            if (*mem) *mem = 1;
            mem++;
        }

    } else {

        while (i--) {
            *mem = map[*mem];
            mem++;
        }

    }

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

    shmctl(shm_id, IPC_RMID, NULL);

}


/* Configure shared memory. */

static void setup_shm(void) {

    u8 *shm_str;

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (shm_id < 0) PFATAL("shmget() failed");

    atexit(remove_shm);

    shm_str = alloc_printf("%d", shm_id);

    setenv(SHM_ENV_VAR, shm_str, 1); //设置环境变量，之后fork得到的子进程可以通过此环境变量，得到这块共享内存的标志符

    ck_free(shm_str);

    trace_bits = shmat(shm_id, NULL, 0);// trace_bits 用来保存共享内存的地址

    if (!trace_bits) PFATAL("shmat() failed");

}

/* Write results. */

static u32 write_results(void) {

    s32 fd;
    u32 i, ret = 0;

    u8 cco = !!getenv("AFL_CMIN_CRASHES_ONLY"),
            caa = !!getenv("AFL_CMIN_ALLOW_ANY");

    if (!strncmp(out_file, "/dev/", 5)) {

        fd = open(out_file, O_WRONLY, 0600);
        if (fd < 0) PFATAL("Unable to open '%s'", out_file);

    } else if (!strcmp(out_file, "-")) {

        fd = dup(1);
        if (fd < 0) PFATAL("Unable to open stdout");

    } else {

        unlink(out_file); /* Ignore errors */
        fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) PFATAL("Unable to create '%s'", out_file);

    }


    if (binary_mode) {

        for (i = 0; i < MAP_SIZE; i++)
            if (trace_bits[i]) ret++;

        ck_write(fd, trace_bits, MAP_SIZE, out_file);
        close(fd);

    } else {

        FILE *f = fdopen(fd, "w");

        if (!f) PFATAL("fdopen() failed");

        for (i = 0; i < MAP_SIZE; i++) {

            if (!trace_bits[i]) continue;
            ret++;

            if (cmin_mode) {

                if (child_timed_out) break;
                if (!caa && child_crashed != cco) break;

                fprintf(f, "%u%u\n", trace_bits[i], i);

            } else fprintf(f, "%06u:%u\n", i, trace_bits[i]);

        }

        fclose(f);

    }

    return ret;

}

/* Move process to the network namespace "netns_name" */

static void move_process_to_netns() {
    const char *netns_path_fmt = "/var/run/netns/%s";
    char netns_path[272]; /* 15 for "/var/.." + 256 for netns name + 1 '\0' */
    int netns_fd;

    if (strlen(netns_name) > 256)
        FATAL("Network namespace name \"%s\" is too long", netns_name);

    sprintf(netns_path, netns_path_fmt, netns_name);

    netns_fd = open(netns_path, O_RDONLY);
    if (netns_fd == -1)
        PFATAL("Unable to open %s", netns_path);

    if (setns(netns_fd, CLONE_NEWNET) == -1)
        PFATAL("setns failed");
}
static u32 write_bits(){
    u32 i, ret = 0;
    for (i = 0; i < MAP_SIZE; i++) {

        if (!trace_bits[i]) continue;
        ret++;
    }
//    printf("%u\n", ret);
}
int send_to_server() {
    //Wait for the server to initialize
    usleep(server_wait_usecs);

    if (response_buf) {
        ck_free(response_buf);
        response_buf = NULL;
        response_buf_size = 0;
    }

    int sockfd;
    if ((!strcmp(protocol, "DTLS12")) || (!strcmp(protocol, "DNS")) || (!strcmp(protocol, "SIP"))) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    } else {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (sockfd < 0) {
        PFATAL("Cannot create a socket");
    }
    //Set timeout for socket data sending/receiving -- otherwise it causes a big delay
    //if the server is still alive after processing all the requests
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = socket_timeout;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

    memset(&serv_addr, '0', sizeof(serv_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");


    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        //If it cannot connect to the server under test
        //try it again as the server initial startup time is varied
        for (n = 0; n < 1000; n++) {
            if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) == 0) break;
            usleep(1000);
        }
        if (n == 1000) {
            close(sockfd);
            return 1;
        }
    }
    write_bits();

//Send requests one by one
    //And save all the server responses
    while (!feof(fp)) {
        //检测流上的文件结束符，如果文件结束，则返回非0值，否则返回0
        if (buf) {
            ck_free(buf);
            buf = NULL;
        }
//        unsigned int size2 = ftell(fp);

        if (fread(&size, sizeof(unsigned int), 1, fp) > 0) {//sizeof(unsigned int) = 4
            packet_count++;
            if(!quiet_mode)fprintf(stderr, "\nSize of the current packet %d is  %d\n", packet_count, size);

            buf = (char *) ck_alloc(size);
            fread(buf, size, 1, fp);
//            buf = (char *) ck_alloc(size2);
//            fread(buf, size2, 1, fp);

            if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
            n = net_send(sockfd, timeout, buf, size);
            if (n != size) break;

            if (net_recv(sockfd, timeout, poll_timeout, &response_buf, &response_buf_size)) break;
        }
    }

    fclose(fp);
    close(sockfd);

    //Extract response codes
    if(!quiet_mode){
        state_sequence = (*extract_response_codes)(response_buf, response_buf_size, &state_count);
        fprintf(stderr, "\n--------------------------------");
        fprintf(stderr, "\nResponses from server:");

        for (i = 0; i < state_count; i++) {
            fprintf(stderr, "%d-", state_sequence[i]);
        }

        fprintf(stderr, "\n++++++++++++++++++++++++++++++++\nResponses in details:\n");
        for (i = 0; i < response_buf_size; i++) {
            fprintf(stderr, "%c", response_buf[i]);
        }
        fprintf(stderr, "\n--------------------------------");

        //Free memory
        ck_free(state_sequence);
        if (buf) ck_free(buf);
        ck_free(response_buf);
    }
}


/* Handle timeout signal. */

static void handle_timeout(int sig) {

    child_timed_out = 1;
    if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Execute target application. */

static void run_target(char **argv) {

    static struct itimerval it;
    int status = 0;

    if (!quiet_mode)
        SAYF("-- Program output begins --\n" cRST);
//    memset(trace_bits, 0, MAP_SIZE);
    MEM_BARRIER();

    child_pid = fork();
//    sleep(10);

//    printf("pid: %d\n", child_pid);
    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {
        //子进程
        struct rlimit r;

//        if (!quiet_mode) {

            s32 fd = open("/dev/null", O_RDWR);

            if (fd < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) {
                *(u32 *) trace_bits = EXEC_FAIL_SIG;
                PFATAL("Descriptor initialization failed");
            }

            close(fd);

//        }
        if (mem_limit) {

            r.rlim_max = r.rlim_cur = ((rlim_t) mem_limit) << 20;

#ifdef RLIMIT_AS

            setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

            setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

        }

        if (!keep_cores) r.rlim_max = r.rlim_cur = 0;
        else r.rlim_max = r.rlim_cur = RLIM_INFINITY;

        setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

//        move_process_to_netns(); //aflnet
        if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

        setsid();
        char* argv_list[] = {"testOnDemandRTSPServer","8554",NULL};

        if(execv("/home/mi/Desktop/workspace/live555/testProgs/testOnDemandRTSPServer", argv_list)==-1){
            printf("execv:error!");
        }

        *(u32 *) trace_bits = EXEC_FAIL_SIG;
        exit(0);

    }
    /* Configure timeout, wait for child, cancel timeout. */
    sleep(10);
    if (exec_tmout) {

        child_timed_out = 0;
        it.it_value.tv_sec = (exec_tmout / 1000);
        it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

    }

    setitimer(ITIMER_REAL, &it, NULL);
    write_bits();
    send_to_server();///////////////////

    if (waitpid(child_pid, &status, 0) <= 0) FATAL("waitpid() failed");

    child_pid = 0;
    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);

    MEM_BARRIER();

    /* Clean up bitmap, analyze exit condition, etc. */

    if (*(u32 *) trace_bits == EXEC_FAIL_SIG)
        FATAL("Unable to execute '%s'", argv[0]);

    classify_counts(trace_bits, binary_mode ?
                                count_class_binary : count_class_human);

    if (!quiet_mode)
        SAYF(cRST "-- Program output ends --\n");

    if (!child_timed_out && !stop_soon && WIFSIGNALED(status))
        child_crashed = 1;

    if (!quiet_mode) {

        if (child_timed_out)
            SAYF(cLRD "\n+++ Program timed off +++\n" cRST);
        else if (stop_soon)
            SAYF(cLRD "\n+++ Program aborted by user +++\n" cRST);
        else if (child_crashed)
            SAYF(cLRD "\n+++ Program killed by signal %u +++\n" cRST, WTERMSIG(status));

    }


}


/* Handle Ctrl-C and the like. */

static void handle_stop_sig(int sig) {

    stop_soon = 1;

    if (child_pid > 0) kill(child_pid, SIGKILL);

}


/* Do basic preparations - persistent fds, filenames, etc. */

static void set_up_environment(void) {

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    if (getenv("AFL_PRELOAD")) {
        setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
        setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
    }

}


/* Setup signal handlers, duh. */

static void setup_signal_handlers(void) {

    struct sigaction sa;

    sa.sa_handler = NULL;
    sa.sa_flags = SA_RESTART;
    sa.sa_sigaction = NULL;

    sigemptyset(&sa.sa_mask);

    /* Various ways of saying "stop". */

    sa.sa_handler = handle_stop_sig;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Exec timeout notifications. */

    sa.sa_handler = handle_timeout;
    sigaction(SIGALRM, &sa, NULL);

}


/* Detect @@ in args. */

static void detect_file_args(char **argv) {

    u32 i = 0;
    u8 *cwd = getcwd(NULL, 0);

    if (!cwd) PFATAL("getcwd() failed");

    while (argv[i]) {

        u8 *aa_loc = strstr(argv[i], "@@");
        // strstr(str1,str2) 函数用于判断字符串str2是否是str1的子串。
        // 如果是，则该函数返回str1字符串从str2第一次出现的位置开始到str1结尾的字符串；否则，返回NULL。

        if (aa_loc) {

            u8 *aa_subst, *n_arg;

            if (!at_file) FATAL("@@ syntax is not supported by this tool.");

            /* Be sure that we're always using fully-qualified paths. */

            if (at_file[0] == '/') aa_subst = at_file;
            else aa_subst = alloc_printf("%s/%s", cwd, at_file);

            /* Construct a replacement argv value. */

            *aa_loc = 0;
            n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
            argv[i] = n_arg;
            *aa_loc = '@';

            if (at_file[0] != '/') ck_free(aa_subst);

        }

        i++;

    }

    free(cwd); /* not tracked */

}


/* Show banner. */

static void show_banner(void) {

    SAYF(cCYA "aflnet-showmap " cBRI VERSION cRST " by <quanyu1@kth.se>\n");

}

/* Display usage hints. */

static void usage(u8 *argv0) {

    show_banner();

    SAYF("\n%s [ options ] -- /path/to/target_app [ ... ]\n\n"

         "Required parameters:\n\n"

         "  -o file       - file to write the trace data to\n\n"

         "Execution control settings:\n\n"

         "  -t msec       - timeout for each run (none)\n"
         "  -m megs       - memory limit for child process (%u MB)\n"
         "  -Q            - use binary-only instrumentation (QEMU mode)\n\n"

         "Other settings:\n\n"

         "  -q            - sink program's output and don't show messages\n"
         "  -e            - show edge coverage only, ignore hit counts\n"
         "  -c            - allow core dumps\n\n"

         "This tool displays raw tuple data captured by AFL instrumentation.\n"
         "For additional help, consult %s/README.\n\n" cRST,

         argv0, MEM_LIMIT, doc_path);

    exit(1);

}


/* Find binary. */

static void find_binary(u8 *fname) {

    u8 *env_path = 0;
    struct stat st;

    if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

        target_path = ck_strdup(fname);

        if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
            !(st.st_mode & 0111) || st.st_size < 4)
            FATAL("Program '%s' not found or not executable", fname);

    } else {

        while (env_path) {

            u8 *cur_elem, *delim = strchr(env_path, ':');

            if (delim) {

                cur_elem = ck_alloc(delim - env_path + 1);
                memcpy(cur_elem, env_path, delim - env_path);
                delim++;

            } else cur_elem = ck_strdup(env_path);

            env_path = delim;

            if (cur_elem[0])
                target_path = alloc_printf("%s/%s", cur_elem, fname);
            else
                target_path = ck_strdup(fname);

            ck_free(cur_elem);

            if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
                (st.st_mode & 0111) && st.st_size >= 4)
                break;

            ck_free(target_path);
            target_path = 0;

        }

        if (!target_path) FATAL("Program '%s' not found or not executable", fname);

    }

}


/* Fix up argv for QEMU. */

static char **get_qemu_argv(u8 *own_loc, char **argv, int argc) {

    char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
    u8 *tmp, *cp, *rsl, *own_copy;

    /* Workaround for a QEMU stability glitch. */

    setenv("QEMU_LOG", "nochain", 1);

    memcpy(new_argv + 3, argv + 1, sizeof(char *) * argc);

    new_argv[2] = target_path;
    new_argv[1] = "--";

    /* Now we need to actually find qemu for argv[0]. */

    tmp = getenv("AFL_PATH");

    if (tmp) {

        cp = alloc_printf("%s/afl-qemu-trace", tmp);

        if (access(cp, X_OK))
            FATAL("Unable to find '%s'", tmp);

        target_path = new_argv[0] = cp;
        return new_argv;

    }

    own_copy = ck_strdup(own_loc);
    rsl = strrchr(own_copy, '/');

    if (rsl) {

        *rsl = 0;

        cp = alloc_printf("%s/afl-qemu-trace", own_copy);
        ck_free(own_copy);

        if (!access(cp, X_OK)) {

            target_path = new_argv[0] = cp;
            return new_argv;

        }

    } else
        ck_free(own_copy);

    if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

        target_path = new_argv[0] = BIN_PATH
        "/afl-qemu-trace";
        return new_argv;

    }

    FATAL("Unable to find 'afl-qemu-trace'.");

}


/* Main entry point */
// PFATAL("Usage: ./aflnet-replay packet_file protocol port [first_resp_timeout(us) [follow-up_resp_timeout(ms)]]");
//Usage : .aflnet-showmap
// ./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512', '-t', '500'] + argvv + [f]
int main(int argc, char **argv) {

    doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

    while ((opt = getopt(argc, argv, "+o:m:t:A:eqZQbcp:f:k:T:S:")) > 0)

        switch (opt) {

            case 'o':

                if (out_file) FATAL("Multiple -o options not supported");
                out_file = optarg;
                break;

            case 'm': {

                u8 suffix = 'M';

                if (mem_limit_given) FATAL("Multiple -m options not supported");
                mem_limit_given = 1;

                if (!strcmp(optarg, "none")) {

                    mem_limit = 0;
                    break;

                }

                if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
                    optarg[0] == '-')
                    FATAL("Bad syntax used for -m");

                switch (suffix) {

                    case 'T':
                        mem_limit *= 1024 * 1024;
                        break;
                    case 'G':
                        mem_limit *= 1024;
                        break;
                    case 'k':
                        mem_limit /= 1024;
                        break;
                    case 'M':
                        break;

                    default:
                        FATAL("Unsupported suffix or bad syntax for -m");

                }

                if (mem_limit < 5) FATAL("Dangerously low value of -m");

                if (sizeof(rlim_t) == 4 && mem_limit > 2000)
                    FATAL("Value of -m out of range on 32-bit systems");

            }

                break;

            case 't':

                if (timeout_given) FATAL("Multiple -t options not supported");
                timeout_given = 1;

                if (strcmp(optarg, "none")) {
                    exec_tmout = atoi(optarg);

                    if (exec_tmout < 20 || optarg[0] == '-')
                        FATAL("Dangerously low value of -t");

                }

                break;

            case 'e':

                if (edges_only) FATAL("Multiple -e options not supported");
                edges_only = 1;
                break;

            case 'q':

                if (quiet_mode) FATAL("Multiple -q options not supported");
                quiet_mode = 1;
                break;

            case 'Z':

                /* This is an undocumented option to write data in the syntax expected
                   by afl-cmin. Nobody else should have any use for this. */

                cmin_mode = 1;
                quiet_mode = 1;
                break;

            case 'A':

                /* Another afl-cmin specific feature. */
                at_file = optarg;
                break;

            case 'Q':

                if (qemu_mode) FATAL("Multiple -Q options not supported");
                if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

                qemu_mode = 1;
                break;

            case 'b':

                /* Secret undocumented mode. Writes output in raw binary format
                   similar to that dumped by afl-fuzz in <out_dir/queue/fuzz_bitmap. */

                binary_mode = 1;
                break;

            case 'c':

                if (keep_cores) FATAL("Multiple -c options not supported");
                keep_cores = 1;
                break;


            case 'p':
                protocol = optarg;
                break;

            case 'f':
                fp = fopen(optarg, "rb");
                break;

            case 'k':
                portno = atoi(optarg);
                break;

            case 'T':
                poll_timeout = atoi(optarg);
                break;

            case 'S':
                socket_timeout = atoi(optarg);
                break;

            default:

                usage(argv[0]);

        }

    setup_shm();
    setup_signal_handlers();

    set_up_environment();

    if (optind == argc || !out_file) usage(argv[0]);

    if (!strcmp(protocol, "RTSP")) extract_response_codes = &extract_response_codes_rtsp;
    else if (!strcmp(protocol, "FTP")) extract_response_codes = &extract_response_codes_ftp;
    else if (!strcmp(protocol, "DNS")) extract_response_codes = &extract_response_codes_dns;
    else if (!strcmp(protocol, "DTLS12")) extract_response_codes = &extract_response_codes_dtls12;
    else if (!strcmp(protocol, "DICOM")) extract_response_codes = &extract_response_codes_dicom;
    else if (!strcmp(protocol, "SMTP")) extract_response_codes = &extract_response_codes_smtp;
    else if (!strcmp(protocol, "SSH")) extract_response_codes = &extract_response_codes_ssh;
    else if (!strcmp(protocol, "TLS")) extract_response_codes = &extract_response_codes_tls;
    else if (!strcmp(protocol, "SIP")) extract_response_codes = &extract_response_codes_sip;
    else if (!strcmp(protocol, "HTTP")) extract_response_codes = &extract_response_codes_http;
    else if (!strcmp(protocol, "IPP")) extract_response_codes = &extract_response_codes_ipp;
    else {
        fprintf(stderr, "[AFLNet-replay] Protocol %s has not been supported yet!\n", protocol);
        exit(1);
    }


    detect_file_args(argv + optind+1);

    find_binary(argv[optind]);

    if (!quiet_mode) {
        show_banner();
        ACTF("Executing '%s'...\n", target_path);
    }

    if (qemu_mode)
        use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
    else
        use_argv = argv + optind;

    run_target(use_argv);

    tcnt = write_results();

    if (!quiet_mode) {

        if (!tcnt) FATAL("No instrumentation detected" cRST);
        OKF("Captured %u tuples in '%s'." cRST, tcnt, out_file);

    }

    exit(child_crashed);

}

