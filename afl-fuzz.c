#define _GNU_SOURCE
#define _GNU_SOURCE
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <graphviz/gvc.h>
#include <math.h>

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"
#include "aflnet.h"


//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
// add from aflnet
static u8 shuffle_queue;


static u32 queued_paths,              /* Total number of queued testcases */
queued_variable,           /* Testcases with variable behavior */
queued_at_start,           /* Total number of initial inputs   */
queued_discovered,         /* Items discovered during this run */
queued_imported,           /* Items imported via -S            */
queued_favored,            /* Paths deemed favorable           */
queued_with_cov,           /* Paths with new coverage bytes    */
pending_not_fuzzed,        /* Queued but not done yet          */
pending_favored,           /* Pending favored paths            */
cur_skipped_paths,         /* Abandoned inputs in cur cycle    */
cur_depth,                 /* Current path depth               */
max_depth,                 /* Max path depth                   */
useless_at_start,          /* Number of useless starting paths */
var_byte_count,            /* Bitmap bytes with var behavior   */
current_entry,             /* Current queue entry ID           */
havoc_div = 1;             /* Cycle count divisor for havoc    */

static u64 total_crashes,             /* Total number of crashes          */
unique_crashes,            /* Crashes with unique signatures   */
total_tmouts,              /* Total number of timeouts         */
unique_tmouts,             /* Timeouts with unique signatures  */
unique_hangs,              /* Hangs with unique signatures     */
//total_execs,               /* Total execve() calls             */
slowest_exec_ms,           /* Slowest testcase non hang in ms  */
start_time,                /* Unix start time (ms)             */
last_path_time,            /* Time for most recent path (ms)   */
last_crash_time,           /* Time for most recent crash (ms)  */
last_hang_time,            /* Time for most recent hang (ms)   */
last_crash_execs,          /* Exec counter at last crash       */
queue_cycle,               /* Queue round counter              */
cycles_wo_finds,           /* Cycles without any new paths     */
trim_execs,                /* Execs done to trim input files   */
bytes_trim_in,             /* Bytes coming into the trimmer    */
bytes_trim_out,            /* Bytes coming outa the trimmer    */
blocks_eff_total,          /* Blocks subject to effector maps  */
blocks_eff_select;         /* Blocks selected as fuzzable      */

static u32 rand_cnt;                  /* Random number counter            */


struct queue_entry {

    u8 *fname;                          /* File name for the test case      */
    u32 len;                            /* Input length                     */

    u8 cal_failed,                     /* Calibration failed?              */
    trim_done,                      /* Trimmed?                         */
    was_fuzzed,                     /* Had any fuzzing done yet?        */
    passed_det,                     /* Deterministic stages passed?     */
    has_new_cov,                    /* Triggers new coverage?           */
    var_behavior,                   /* Variable behavior?               */
    favored,                        /* Currently favored?               */
    fs_redundant;                   /* Marked as redundant in the fs?   */

    u32 bitmap_size,                    /* Number of bits set in bitmap     */
    exec_cksum;                     /* Checksum of the execution trace  */

    u64 exec_us,                        /* Execution time (us)              */
    handicap,                       /* Number of queue cycles behind    */
    depth;                          /* Path depth                       */

    u8 *trace_mini;                     /* Trace bytes, if kept             */
    u32 tc_ref;                         /* Trace bytes ref count            */

    struct queue_entry *next,           /* Next element, if any             */
    *next_100;       /* 100 elements ahead               */

    region_t *regions;                  /* Regions keeping information of message(s) sent to the server under test */
    u32 region_count;                   /* Total number of regions in this seed */
    u32 index;                          /* Index of this queue entry in the whole queue */
    u32 generating_state_id;            /* ID of the start at which the new seed was generated */
    u8 is_initial_seed;                 /* Is this an initial seed */
    u32 unique_state_count;             /* Unique number of states traversed by this queue entry */

};

static struct queue_entry *queue,     /* Fuzzing queue (linked list)      */
*queue_cur, /* Current offset within the queue  */
*queue_top, /* Top of the list                  */
*q_prev100; /* Previous 100 marker              */

static struct queue_entry *
        top_rated[MAP_SIZE];                /* Top entries for bitmap bytes     */




/* AFLNet-specific variables & functions */

u32 server_wait_usecs = 10000;
u32 poll_wait_msecs = 1;
u32 socket_timeout_usecs = 1000;
u8 net_protocol;
u8 *net_ip;
u32 net_port;
char *response_buf = NULL;
int response_buf_size = 0; //the size of the whole response buffer
u32 *response_bytes = NULL; //an array keeping accumulated response buffer size
//e.g., response_bytes[i] keeps the response buffer size
//once messages 0->i have been received and processed by the SUT
u32 max_annotated_regions = 0;
u32 target_state_id = 0;
u32 *state_ids = NULL;
u32 state_ids_count = 0;
u32 selected_state_index = 0;
u32 state_cycles = 0;
u32 messages_sent = 0;
static u8 session_virgin_bits[MAP_SIZE];     /* Regions yet untouched while the SUT is still running */
static u8 *cleanup_script; /* script to clean up the environment of the SUT -- make fuzzing more deterministic */
static u8 *netns_name; /* network namespace name to run server in */
char **was_fuzzed_map = NULL; /* A 2D array keeping state-specific was_fuzzed information */
u32 fuzzed_map_states = 0;
u32 fuzzed_map_qentries = 0;
u32 max_seed_region_count = 0;
u32 local_port;        /* TCP/UDP port number to use as source */

/* flags */
u8 use_net = 0;
u8 poll_wait = 0;
u8 server_wait = 0;
u8 socket_timeout = 0;
u8 protocol_selected = 0;
u8 terminate_child = 0;
u8 corpus_read_or_sync = 0;
u8 state_aware_mode = 1; //直接把它设置为1
u8 region_level_mutation = 0;
u8 state_selection_algo = ROUND_ROBIN, seed_selection_algo = RANDOM_SELECTION;
u8 false_negative_reduction = 0;

/* Implemented state machine */
Agraph_t *ipsm;
static FILE *ipsm_dot_file;

/* Hash table/map and list */
klist_t(lms) *kl_messages;
khash_t(hs32) *khs_ipsm_paths;
khash_t(hms) *khms_states;

//M2_prev points to the last message of M1 (i.e., prefix)
//If M1 is empty, M2_prev == NULL
//M2_next points to the first message of M3 (i.e., suffix)
//If M3 is empty, M2_next point to the end of the kl_messages linked list
kliter_t(lms) *M2_prev, *M2_next;

//Function pointers pointing to Protocol-specific functions
unsigned int *
(*extract_response_codes)(unsigned char *buf, unsigned int buf_size, unsigned int *state_count_ref) = NULL;

region_t *(*extract_requests)(unsigned char *buf, unsigned int buf_size, unsigned int *region_count_ref) = NULL;


//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||




/* Most of code is borrowed directly from AFL fuzzer (https://github.com/mirrorer/afl), credits to Michal Zalewski */

/* Fork server init timeout multiplier: we'll wait the user-selected timeout plus this much for the fork server to spin up. */
#define FORK_WAIT_MULT      10
/* Environment variable used to pass SHM ID to the called program. */
#define SHM_ENV_VAR "__AFL_SHM_ID"
/* Local port to communicate with python module. */
#define PORT                12012
/* Maximum line length passed from GCC to 'as' and used for parsing configuration files. */
#define MAX_LINE            8192
/* Designated file descriptors for forkserver commands (the application will use FORKSRV_FD and FORKSRV_FD + 1). */
#define FORKSRV_FD          198
/* Distinctive bitmap signature used to indicate failed execution. */
#define EXEC_FAIL_SIG       0xfee1dead
/* Smoothing divisor for CPU load and exec speed stats (1 - no smoothing). */
#define AVG_SMOOTHING       16
/* Caps on block sizes for inserion and deletion operations. The set of numbers are adaptive to file length and the defalut max file length is 10000. */
/* default setting, will be changed later accroding to file len */
int havoc_blk_small = 2048;
int havoc_blk_medium = 4096;
int havoc_blk_large = 8192;
#define HAVOC_BLK_SMALL     2048
#define HAVOC_BLK_MEDIUM    4096
#define HAVOC_BLK_LARGE     7402

#define MEM_BARRIER() \
    asm volatile("" ::: "memory")
/* Map size for the traced binary. */
#define MAP_SIZE            2<<18

#define R(x) (random() % (x))
#define likely(_x)   __builtin_expect(!!(_x), 1)
#define unlikely(_x)  __builtin_expect(!!(_x), 0)
#define MIN(_a,_b) ((_a) > (_b) ? (_b) : (_a))
#define MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))

/* Error-checking versions of read() and write() that call RPFATAL() as appropriate. */
#define ck_write(fd, buf, len, fn) do { \
    u32 _len = (len); \
    int _res = write(fd, buf, _len); \
    if (_res != _len) fprintf(stderr, "Short write to %d %s\n",_res, fn); \
} while (0)

#define ck_read(fd, buf, len, fn) do { \
    u32 _len = (len); \
    int _res = read(fd, buf, _len); \
    if (_res != _len) fprintf(stderr, "Short read from %d %s\n",_res, fn); \
} while (0)

/* User-facing macro to sprintf() to a dynamically allocated buffer. */
#define alloc_printf(_str...) ({ \
    char* _tmp; \
    int _len = snprintf(NULL, 0, _str); \
    if (_len < 0) perror("Whoa, snprintf() fails?!"); \
    _tmp = malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
})


typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
#ifdef __x86_64__
typedef unsigned long long u64;
#else
typedef uint64_t u64;
#endif /* ^__x86_64__ */

unsigned long total_execs;              /* Total number of execs */
static int shm_id;                      /* ID of the SHM region */
static int mem_limit  = 1024;           /* Maximum memory limit for target program */
static int cpu_aff = -1;                /* Selected CPU core */
int round_cnt = 0;                      /* Round number counter */
int edge_gain=0;                        /* If there is new edge gain */
int exec_tmout = 1000;                  /* Exec timeout (ms)                 */

int stage_num = 1;
int old=0;
int now=0;
int fast=1;
char * target_path;                     /* Path to target binary            */
char * trace_bits;                      /* SHM with instrumentation bitmap  */
static volatile int stop_soon;          /* Ctrl-C pressed?                  */
static int cpu_core_count;              /* CPU core count                   */
static u64 total_cal_us=0;              /* Total calibration time (us)      */
static volatile int child_timed_out;    /* Traced process timed out?        */
int kill_signal;                        /* Signal that killed the child     */
static int out_fd,                      /* Persistent fd for out_file       */
dev_urandom_fd = -1,         /* Persistent fd for /dev/urandom   */
dev_null_fd = -1,            /* Persistent fd for /dev/null      */
fsrv_ctl_fd,                 /* Fork server control pipe (write) */
fsrv_st_fd;                  /* Fork server status pipe (read)   */
static int forksrv_pid,                 /* PID of the fork server           */
child_pid = -1,              /* PID of the fuzzed program        */
out_dir_fd = -1;             /* FD of the lock file              */

char *in_dir,                           /* Input directory with test cases  */
*out_file,                         /* File to fuzz, if any             */
*out_dir;                          /* Working & output directory       */
char virgin_bits[MAP_SIZE];             /* Regions yet untouched by fuzzing */
static int mut_cnt = 0;                 /* Total mutation counter           */
char *out_buf, *out_buf1, *out_buf2, *out_buf3;
size_t len;                             /* Maximum file length for every mutation */
int loc[10000];                         /* Array to store critical bytes locations*/
int sign[10000];                        /* Array to store sign of critical bytes  */

/* more fined grined mutation can have better results but slower*/
//int num_index[23] = {0,2,4,8,16,32,64,128,256,512,1024,1536,2048,2560,3072, 3584,4096,4608,5120, 5632,6144,6656,7103};
/* default setting, will be change according to different file length */
int num_index[14] = {0,2,4,8,16,32,64,128,256,512,1024,2048,4096,8192};



enum {
    /* 00 */ FAULT_NONE,
    /* 01 */ FAULT_TMOUT,
    /* 02 */ FAULT_CRASH,
    /* 03 */ FAULT_ERROR,
    /* 04 */ FAULT_NOINST,
    /* 05 */ FAULT_NOBITS
};


//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//add function from here


/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);

    return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}


/* Describe integer as memory size. */

static u8 *DMS(u64 val) {

    static u8 tmp[12][16];
    static u8 cur;

    cur = (cur + 1) % 12;

    /* 0-9999 */
    CHK_FORMAT(1, 10000, "%llu B", u64);

    /* 10.0k - 99.9k */
    CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

    /* 100k - 999k */
    CHK_FORMAT(1024, 1000, "%llu kB", u64);

    /* 1.00M - 9.99M */
    CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

    /* 10.0M - 99.9M */
    CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

    /* 100M - 999M */
    CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

    /* 1.00G - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

    /* 10.0G - 99.9G */
    CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

    /* 100G - 999G */
    CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

    /* 1.00T - 9.99G */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

    /* 10.0T - 99.9T */
    CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

    /* 100T+ */
    strcpy(tmp[cur], "infty");
    return tmp[cur];

}

/* Generate a random number (from 0 to limit - 1). This may
   have slight bias. */

static inline u32 UR(u32 limit) {

    if (unlikely(!rand_cnt--)) {

        u32 seed[2];

        ck_read(dev_urandom_fd, &seed, sizeof(seed), "/dev/urandom");

        srandom(seed[0]);
        rand_cnt = (RESEED_RNG / 2) + (seed[1] % RESEED_RNG);

    }

    return random() % limit;

}

/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void **ptrs, u32 cnt) {

    u32 i;

    for (i = 0; i < cnt - 2; i++) {

        u32 j = i + UR(cnt - i);
        void *s = ptrs[i];
        ptrs[i] = ptrs[j];
        ptrs[j] = s;

    }

}

/* Initialize the implemented state machine as a graphviz graph */
void setup_ipsm()
{
    ipsm = agopen("g", Agdirected, 0);

    agattr(ipsm, AGNODE, "color", "black"); //Default node colr is black
    agattr(ipsm, AGEDGE, "color", "black"); //Default edge color is black

    khs_ipsm_paths = kh_init(hs32);

    khms_states = kh_init(hms);
}

/* Free memory allocated to state-machine variables */
void destroy_ipsm()
{
    agclose(ipsm);

    kh_destroy(hs32, khs_ipsm_paths);

    state_info_t *state;
    kh_foreach_value(khms_states, state, {ck_free(state->seeds); ck_free(state);});
    kh_destroy(hms, khms_states);

    ck_free(state_ids);
}

/* Expand the size of the map when a new seed or a new state has been discovered */
void expand_was_fuzzed_map(u32 new_states, u32 new_qentries) {
    int i, j;
    //Realloc the memory
    was_fuzzed_map = (char **) ck_realloc(was_fuzzed_map, (fuzzed_map_states + new_states) * sizeof(char *));
    for (i = 0; i < fuzzed_map_states + new_states; i++)
        was_fuzzed_map[i] = (char *) ck_realloc(was_fuzzed_map[i], (fuzzed_map_qentries + new_qentries) * sizeof(char));

    //All new cells are marked as -1 -- meaning UNREACHABLE
    //Keep other cells untouched
    for (i = 0; i < fuzzed_map_states + new_states; i++)
        for (j = 0; j < fuzzed_map_qentries + new_qentries; j++)
            if ((i >= fuzzed_map_states) || (j >= fuzzed_map_qentries)) was_fuzzed_map[i][j] = -1;

    //Update total number of states (rows) and total number of queue entries (columns) in the was_fuzzed_map
    fuzzed_map_states += new_states;
    fuzzed_map_qentries += new_qentries;
}

/* Append new test case to the queue. */

static void add_to_queue(u8 *fname, u32 len, u8 passed_det) {

    struct queue_entry *q = ck_alloc(sizeof(struct queue_entry));

    q->fname = fname;
    q->len = len;
    q->depth = cur_depth + 1;
    q->passed_det = passed_det;
    q->regions = NULL;
    q->region_count = 0;
    q->index = queued_paths;
    q->generating_state_id = target_state_id;
    q->is_initial_seed = 0;
    q->unique_state_count = 0;

    if (q->depth > max_depth) max_depth = q->depth;

    if (queue_top) {

        queue_top->next = q;
        queue_top = q;

    } else q_prev100 = queue = queue_top = q;

    queued_paths++;
    pending_not_fuzzed++;

    cycles_wo_finds = 0;

    if (!(queued_paths % 100)) {

        q_prev100->next_100 = q;
        q_prev100 = q;

    }

    /* AFLNet: extract regions keeping client requests if needed */
    if (corpus_read_or_sync) {
        FILE *fp;
        unsigned char *buf;

        /* opening file for reading */
        fp = fopen(fname, "rb");

        buf = (unsigned char *) ck_alloc(len);
        u32 byte_count = fread(buf, 1, len, fp);
        fclose(fp);

        if (byte_count != len) PFATAL("AFLNet - Inconsistent file length '%s'", fname);
        q->regions = (*extract_requests)(buf, len, &q->region_count);
        ck_free(buf);

        //Keep track the maximal number of seed regions
        //We use this for some optimization to reduce the overhead while following the server's sequence diagram
        if ((corpus_read_or_sync == 1) && (q->region_count > max_seed_region_count))
            max_seed_region_count = q->region_count;

    } else {
        //Convert the linked list kl_messages to regions
        q->regions = convert_kl_messages_to_regions(kl_messages, &q->region_count, messages_sent);
    }

    /* save the regions' information to file for debugging purpose */
    u8 *fn = alloc_printf("%s/regions/%s", out_dir, basename(fname));
    save_regions_to_file(q->regions, q->region_count, fn);
    ck_free(fn);

    last_path_time = get_cur_time();

    //Add a new column to the was_fuzzed map
    if (fuzzed_map_states) {
        expand_was_fuzzed_map(0, 1);
    } else {
        //Also add a new row (for state 0) if needed
        expand_was_fuzzed_map(1, 1);
    }
}


/* Destroy the entire queue. */

static void destroy_queue(void) {

    struct queue_entry *q = queue, *n;

    while (q) {

        n = q->next;
        ck_free(q->fname);
        ck_free(q->trace_mini);
        u32 i;
        //Free AFLNet-specific data structure
        for (i = 0; i < q->region_count; i++) {
            if (q->regions[i].state_sequence) ck_free(q->regions[i].state_sequence);
        }
        if (q->regions) ck_free(q->regions);
        ck_free(q);
        q = n;

    }

}



/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void) {

    struct dirent **nl;
    s32 nl_cnt;
    u32 i;
    u8 *fn;

    /* AFLNet: set this flag to enable request extractions while adding new seed to the queue */
    corpus_read_or_sync = 1;

    /* Auto-detect non-in-place resumption attempts. */

    fn = alloc_printf("%s/queue", in_dir);
    if (!access(fn, F_OK)) in_dir = fn; else ck_free(fn);

    ACTF("Scanning '%s'...", in_dir);

    /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

    nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

    if (nl_cnt < 0) {

        if (errno == ENOENT || errno == ENOTDIR)

            SAYF("\n" cLRD "[-] " cRST
                         "The input directory does not seem to be valid - try again. The fuzzer needs\n"
                         "    one or more test case to start with - ideally, a small file under 1 kB\n"
                         "    or so. The cases must be stored as regular files directly in the input\n"
                         "    directory.\n");

        PFATAL("Unable to open '%s'", in_dir);

    }

    if (shuffle_queue && nl_cnt > 1) {

        ACTF("Shuffling queue...");
        shuffle_ptrs((void **) nl, nl_cnt);

    }

    for (i = 0; i < nl_cnt; i++) {

        struct stat st;

        u8 *fn = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
        u8 *dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

        u8 passed_det = 0;

        free(nl[i]); /* not tracked */

        if (lstat(fn, &st) || access(fn, R_OK))
            PFATAL("Unable to access '%s'", fn);

        /* This also takes care of . and .. */

        if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {

            ck_free(fn);
            ck_free(dfn);
            continue;

        }

        if (st.st_size > MAX_FILE)
            FATAL("Test case '%s' is too big (%s, limit is %s)", fn,
                  DMS(st.st_size), DMS(MAX_FILE));

        /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

        if (!access(dfn, F_OK)) passed_det = 1;
        ck_free(dfn);

        add_to_queue(fn, st.st_size, passed_det);

    }

    /* AFLNet: unset this flag to disable request extractions while adding new seed to the queue */
    corpus_read_or_sync = 0;

    free(nl); /* not tracked */

    if (!queued_paths) {

        SAYF("\n" cLRD "[-] " cRST
                     "Looks like there are no valid test cases in the input directory! The fuzzer\n"
                     "    needs one or more test case to start with - ideally, a small file under\n"
                     "    1 kB or so. The cases must be stored as regular files directly in the\n"
                     "    input directory.\n");

        FATAL("No usable test cases in '%s'", in_dir);

    }

    last_path_time = 0;
    queued_at_start = queued_paths;

}
static u64 get_cur_time_us(void);
/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char **argv, struct queue_entry *q, u8 *use_mem,
                         u32 handicap, u8 from_queue) {

    static u8 first_trace[MAP_SIZE];

    u8 fault = 0, new_bits = 0, var_detected = 0,
            first_run = (q->exec_cksum == 0);

    u64 start_us, stop_us;

    s32 old_sc = stage_cur, old_sm = stage_max;
    u32 use_tmout = exec_tmout;
    u8 *old_sn = stage_name;

    /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

    if (!from_queue || resuming_fuzz)
        use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                        exec_tmout * CAL_TMOUT_PERC / 100);

    q->cal_failed++;

    stage_name = "calibration";
    stage_max = fast_cal ? 3 : CAL_CYCLES;

    /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

    if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
        init_forkserver(argv);

    if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);

    start_us = get_cur_time_us();

    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {

        u32 cksum;

        if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

        write_to_testcase(use_mem, q->len);

        fault = run_target(argv, use_tmout);

        /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

        if (stop_soon || fault != crash_mode) goto abort_calibration;

        if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
            fault = FAULT_NOINST;
            goto abort_calibration;
        }

        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

        if (q->exec_cksum != cksum) {

            u8 hnb = has_new_bits(virgin_bits);
            if (hnb > new_bits) new_bits = hnb;

            if (q->exec_cksum) {

                u32 i;

                for (i = 0; i < MAP_SIZE; i++) {

                    if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

                        var_bytes[i] = 1;
                        stage_max = CAL_CYCLES_LONG;

                    }

                }

                var_detected = 1;

            } else {

                q->exec_cksum = cksum;
                memcpy(first_trace, trace_bits, MAP_SIZE);

            }

        }

    }

    stop_us = get_cur_time_us();

    total_cal_us += stop_us - start_us;
    total_cal_cycles += stage_max;

    /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

    q->exec_us = (stop_us - start_us) / stage_max;
    q->bitmap_size = count_bytes(trace_bits);
    q->handicap = handicap;
    q->cal_failed = 0;

    total_bitmap_size += q->bitmap_size;
    total_bitmap_entries++;

    update_bitmap_score(q);

    /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

    if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

    abort_calibration:

    if (new_bits == 2 && !q->has_new_cov) {
        q->has_new_cov = 1;
        queued_with_cov++;
    }

    /* Mark variable paths. */

    if (var_detected) {

        var_byte_count = count_bytes(var_bytes);

        if (!q->var_behavior) {
            mark_as_variable(q);
            queued_variable++;
        }

    }

    stage_name = old_sn;
    stage_cur = old_sc;
    stage_max = old_sm;

    if (!first_run) show_stats();

    return fault;

}



/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char **argv) {

    struct queue_entry *q = queue;
    u32 cal_failures = 0;
    u8 *skip_crashes = getenv("AFL_SKIP_CRASHES");

    while (q) {

        u8 *use_mem;
        u8 res;
        s32 fd;

        q->is_initial_seed = 1;

        u8 *fn = strrchr(q->fname, '/') + 1;

        ACTF("Attempting dry run with '%s'...", fn);

        fd = open(q->fname, O_RDONLY);
        if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

        use_mem = ck_alloc_nozero(q->len);

        if (read(fd, use_mem, q->len) != q->len)
            FATAL("Short read from '%s'", q->fname);

        close(fd);

        /* AFLNet construct the kl_messages linked list for this queue entry*/
        kl_messages = construct_kl_messages(q->fname, q->regions, q->region_count);

        res = calibrate_case(argv, q, use_mem, 0, 1);
        ck_free(use_mem);

        /* Update state-aware variables (e.g., state machine, regions and their annotations */
        if (state_aware_mode) update_state_aware_variables(q, 1);

        /* save the seed to file for replaying */
        u8 *fn_replay = alloc_printf("%s/replayable-queue/%s", out_dir, basename(q->fname));
        save_kl_messages_to_file(kl_messages, fn_replay, 1, messages_sent);
        ck_free(fn_replay);

        /* AFLNet delete the kl_messages */
        delete_kl_messages(kl_messages);

        if (stop_soon) return;

        if (res == crash_mode || res == FAULT_NOBITS)
            SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST,
                 q->len, q->bitmap_size, q->exec_us);

        switch (res) {

            case FAULT_NONE:

                if (q == queue) check_map_coverage();

                if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

                break;

            case FAULT_TMOUT:

                if (timeout_given) {

                    /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

                    if (timeout_given > 1) {
                        WARNF("Test case results in a timeout (skipping)");
                        q->cal_failed = CAL_CHANCES;
                        cal_failures++;
                        break;
                    }

                    SAYF("\n" cLRD "[-] " cRST
                                 "The program took more than %u ms to process one of the initial test cases.\n"
                                 "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
                                 "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
                                 "    what you are doing and want to simply skip the unruly test cases, append\n"
                                 "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
                         exec_tmout);

                    FATAL("Test case '%s' results in a timeout", fn);

                } else {

                    SAYF("\n" cLRD "[-] " cRST
                                 "The program took more than %u ms to process one of the initial test cases.\n"
                                 "    This is bad news; raising the limit with the -t option is possible, but\n"
                                 "    will probably make the fuzzing process extremely slow.\n\n"

                                 "    If this test case is just a fluke, the other option is to just avoid it\n"
                                 "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

                    FATAL("Test case '%s' results in a timeout", fn);

                }

            case FAULT_CRASH:

                if (crash_mode) break;

                if (skip_crashes) {
                    WARNF("Test case results in a crash (skipping)");
                    q->cal_failed = CAL_CHANCES;
                    cal_failures++;
                    break;
                }

                if (mem_limit) {

                    SAYF("\n" cLRD "[-] " cRST
                                 "Oops, the program crashed with one of the test cases provided. There are\n"
                                 "    several possible explanations:\n\n"

                                 "    - The test case causes known crashes under normal working conditions. If\n"
                                 "      so, please remove it. The fuzzer should be seeded with interesting\n"
                                 "      inputs - but not ones that cause an outright crash.\n\n"

                                 "    - The current memory limit (%s) is too low for this program, causing\n"
                                 "      it to die due to OOM when parsing valid files. To fix this, try\n"
                                 "      bumping it up with the -m setting in the command line. If in doubt,\n"
                                 "      try something along the lines of:\n\n"

#ifdef RLIMIT_AS
                                 "      ( ulimit -Sv $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#else
                                 "      ( ulimit -Sd $[%llu << 10]; /path/to/binary [...] <testcase )\n\n"
#endif /* ^RLIMIT_AS */

                                 "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
                                 "      estimate the required amount of virtual memory for the binary. Also,\n"
                                 "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

#ifdef __APPLE__

                                 "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                                 "      break afl-fuzz performance optimizations when running platform-specific\n"
                                 "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                                 "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
                                 "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
                         DMS(mem_limit << 20), mem_limit - 1, doc_path);

                } else {

                    SAYF("\n" cLRD "[-] " cRST
                                 "Oops, the program crashed with one of the test cases provided. There are\n"
                                 "    several possible explanations:\n\n"

                                 "    - The test case causes known crashes under normal working conditions. If\n"
                                 "      so, please remove it. The fuzzer should be seeded with interesting\n"
                                 "      inputs - but not ones that cause an outright crash.\n\n"

#ifdef __APPLE__

                                 "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
                                 "      break afl-fuzz performance optimizations when running platform-specific\n"
                                 "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

                                 "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
                                 "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n");

                }

                FATAL("Test case '%s' results in a crash", fn);

            case FAULT_ERROR:

                FATAL("Unable to execute target application ('%s')", argv[0]);

            case FAULT_NOINST:

                FATAL("No instrumentation detected");

            case FAULT_NOBITS:

                useless_at_start++;

                if (!in_bitmap && !shuffle_queue)
                    WARNF("No new instrumentation output, test case may be useless.");

                break;

        }

        if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

        q = q->next;

    }

    if (cal_failures) {

        if (cal_failures == queued_paths)
            FATAL("All test cases time out%s, giving up!",
                  skip_crashes ? " or crash" : "");

        WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
              ((double) cal_failures) * 100 / queued_paths,
              skip_crashes ? " or crashes" : "");

        if (cal_failures * 5 > queued_paths)
            WARNF(cLRD "High percentage of rejected test cases, check settings!");

    }

    OKF("All test cases processed.");

}

//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
//||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||

/* Spin up fork server (instrumented mode only). The idea is explained here:
   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html
   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */
void setup_stdio_file(void) {

    char* fn = alloc_printf("%s/.cur_input", out_dir);

    unlink(fn); /* Ignore errors */

    out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

    if (out_fd < 0) perror("Unable to create .cur_input");

    free(fn);

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */
#define FF(_b)  (0xff << ((_b) << 3))
static u32 count_non_255_bytes(u8* mem) {

    u32* ptr = (u32*)mem;
    u32  i   = (MAP_SIZE >> 2);
    u32  ret = 0;

    while (i--) {

        u32 v = *(ptr++);

        /* This is called on the virgin bitmap, so optimize for the most likely
           case. */

        if (v == 0xffffffff) continue;
        if ((v & FF(0)) != FF(0)) ret++;
        if ((v & FF(1)) != FF(1)) ret++;
        if ((v & FF(2)) != FF(2)) ret++;
        if ((v & FF(3)) != FF(3)) ret++;

    }

    return ret;

}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

    stop_soon = 1;

    if (child_pid > 0) kill(child_pid, SIGKILL);
    if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);
    printf("total execs %ld edge coverage %d.\n", total_execs,(int)(count_non_255_bytes(virgin_bits)));

    //free buffer
    free(out_buf);
    free(out_buf1);
    free(out_buf2);
    free(out_buf3);
    exit(0);
}

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.
   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */
//检查当前执行路径是否为表带来了新内容。更新原始位以反映发现。如果唯一更改的是特定元组的命中计数，则返回1;如果有新的元组出现，则返回2。更新映射，因此后续调用将始终返回0。static

static inline char has_new_bits(char* virgin_map) {

#ifdef __x86_64__

    u64* current = (u64*)trace_bits;
    u64* virgin  = (u64*)virgin_map;

    u32  i = (MAP_SIZE >> 3);

#else

    u32* current = (u32*)trace_bits;
  u32* virgin  = (u32*)virgin_map;

  u32  i = (MAP_SIZE >> 2);

#endif /* ^__x86_64__ */

    u8   ret = 0;

    while (i--) {

        /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
           that have not been already cleared from the virgin map - since this will
           almost always be the case. */

        if (unlikely(*current) && unlikely(*current & *virgin)) {

            if (likely(ret < 2)) {

                u8* cur = (u8*)current;
                u8* vir = (u8*)virgin;

                /* Looks like we have not found any new bytes yet; see if any non-zero
                   bytes in current[] are pristine in virgin[]. */

#ifdef __x86_64__

                if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                    (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
                    (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                    (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) ret = 2;
                else ret = 1;

#else

                if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
            (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff)) ret = 2;
        else ret = 1;

#endif /* ^__x86_64__ */

            }

            *virgin &= ~*current;

        }

        current++;
        virgin++;

    }

    return ret;

}


/* Handle timeout (SIGALRM). */

static void handle_timeout(int sig) {

    if (child_pid > 0) {

        child_timed_out = 1;
        kill(child_pid, SIGKILL);

    } else if (child_pid == -1 && forksrv_pid > 0) {

        child_timed_out = 1;
        kill(forksrv_pid, SIGKILL);

    }

}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

    struct sigaction sa;

    sa.sa_handler   = NULL;
    sa.sa_flags     = SA_RESTART;
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

    /* Things we don't care about. */

    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);

}

void init_forkserver(char** argv) {

    static struct itimerval it;
    int st_pipe[2], ctl_pipe[2];
    int status;
    int rlen;
    char* cwd = getcwd(NULL, 0);
    out_file = alloc_printf("%s/%s/.cur_input",cwd, out_dir);
    printf("Spinning up the fork server...\n");

    if (pipe(st_pipe) || pipe(ctl_pipe)) perror("pipe() failed");

    forksrv_pid = fork();

    if (forksrv_pid < 0) perror("fork() failed");

    if (!forksrv_pid) {

        struct rlimit r;

        /* Umpf. On OpenBSD, the default fd limit for root users is set to
           soft 128. Let's try to fix that... */

        if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

            r.rlim_cur = FORKSRV_FD + 2;
            setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

        }

        if (mem_limit) {

            r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

            setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

            /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


        }

        /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
           before the dump is complete. */

        r.rlim_max = r.rlim_cur = 0;

        setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

        /* Isolate the process and configure standard descriptors. If out_file is
           specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

        setsid();

        dup2(dev_null_fd, 1);
        dup2(dev_null_fd, 2);

        if (out_file) {

            dup2(dev_null_fd, 0);

        } else {

            dup2(out_fd, 0);
            close(out_fd);

        }

        /* Set up control and status pipes, close the unneeded original fds. */

        if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) perror("dup2() failed");
        if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) perror("dup2() failed");

        close(ctl_pipe[0]);
        close(ctl_pipe[1]);
        close(st_pipe[0]);
        close(st_pipe[1]);

        close(out_dir_fd);
        close(dev_null_fd);
        close(dev_urandom_fd);

        /* This should improve performance a bit, since it stops the linker from
           doing extra work post-fork(). */

        if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);


        execv(target_path, argv);

        /* Use a distinctive bitmap signature to tell the parent about execv()
           falling through. */
        *(int *)trace_bits = EXEC_FAIL_SIG;
        exit(0);

    }

    /* Close the unneeded endpoints. */

    close(ctl_pipe[0]);
    close(st_pipe[1]);

    fsrv_ctl_fd = ctl_pipe[1];
    fsrv_st_fd  = st_pipe[0];

    /* Wait for the fork server to come up, but don't wait too long. */

    it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    rlen = read(fsrv_st_fd, &status, 4);

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;

    setitimer(ITIMER_REAL, &it, NULL);

    /* If we have a four-byte "hello" message from the server, we're all set.
       Otherwise, try to figure out what went wrong. */

    if (rlen == 4) {
        printf("All right - fork server is up.");
        return;
    }

    if (child_timed_out)
        perror("Timeout while initializing fork server (adjusting -t may help)");

    if (waitpid(forksrv_pid, &status, 0) <= 0)
        perror("waitpid() failed");

    if (WIFSIGNALED(status)) {

        fprintf(stderr, "Fork server crashed with signal %d", WTERMSIG(status));

    }

    if (*(int*)trace_bits == EXEC_FAIL_SIG)
        fprintf(stderr, "Unable to execute target application ('%s')", argv[0]);

    perror("Fork server handshake failed");

}


/* Get rid of shared memory (atexit handler). */

static void remove_shm(void) {

    shmctl(shm_id, IPC_RMID, NULL);

}

/* Configure shared memory and virgin_bits. This is called at startup. */

void setup_shm(void) {

    char* shm_str;

    memset(virgin_bits, 255, MAP_SIZE);

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (shm_id < 0) perror("shmget() failed");

    atexit(remove_shm);

    shm_str = alloc_printf("%d", shm_id);

    /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
       we don't want them to detect instrumentation, since we won't be sending
       fork server commands. This should be replaced with better auto-detection
       later on, perhaps? */

    setenv(SHM_ENV_VAR, shm_str, 1);

    free(shm_str);

    trace_bits = shmat(shm_id, NULL, 0);

    if (!trace_bits) perror("shmat() failed");

}

void setup_dirs_fds(void) {

    char* tmp;
    int fd;

    printf("Setting up output directories...");


    if (mkdir(out_dir, 0700)) {

        if (errno != EEXIST) fprintf(stderr,"Unable to create %s\n", out_dir);

    }

    /* Generally useful file descriptors. */

    dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd < 0) perror("Unable to open /dev/null");

    dev_urandom_fd = open("/dev/urandom", O_RDONLY);
    if (dev_urandom_fd < 0) perror("Unable to open /dev/urandom");

}


/* Detect @@ in args. */

void detect_file_args(char** argv) {

    int i = 0;
    char* cwd = getcwd(NULL, 0);

    if (!cwd) perror("getcwd() failed");

    while (argv[i]) {

        char* aa_loc = strstr(argv[i], "@@");

        if (aa_loc) {

            char *aa_subst, *n_arg;

            /* If we don't have a file name chosen yet, use a safe default. */

            if (!out_file)
                out_file = alloc_printf("%s/.cur_input", out_dir);

            /* Be sure that we're always using fully-qualified paths. */

            if (out_file[0] == '/') aa_subst = out_file;
            else aa_subst = alloc_printf("%s/%s", cwd, out_file);

            /* Construct a replacement argv value. */

            *aa_loc = 0;
            n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
            argv[i] = n_arg;
            *aa_loc = '@';

            if (out_file[0] != '/') free(aa_subst);

        }

        i++;

    }

    free(cwd); /* not tracked */

}

/* set up target path */
void setup_targetpath(char * argvs){
    char* cwd = getcwd(NULL, 0);
    target_path = alloc_printf("%s/%s", cwd, argvs);
    argvs = target_path;
}

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */
static const u8 count_class_lookup8[256] = {

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

static u16 count_class_lookup16[65536];


void init_count_class16(void) {

    u32 b1, b2;

    for (b1 = 0; b1 < 256; b1++)
        for (b2 = 0; b2 < 256; b2++)
            count_class_lookup16[(b1 << 8) + b2] =
                    (count_class_lookup8[b1] << 8) |
                    count_class_lookup8[b2];

}


#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

    u32 i = MAP_SIZE >> 3;

    while (i--) {

        /* Optimize for sparse bitmaps. */

        if (unlikely(*mem)) {

            u16* mem16 = (u16*)mem;

            mem16[0] = count_class_lookup16[mem16[0]];
            mem16[1] = count_class_lookup16[mem16[1]];
            mem16[2] = count_class_lookup16[mem16[2]];
            mem16[3] = count_class_lookup16[mem16[3]];

        }

        mem++;

    }

}

#else

static inline void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

    static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

    /* On Linux, /proc/stat is probably the best way; load averages are
       computed in funny ways and sometimes don't reflect extremely short-lived
       processes well. */

    FILE* f = fopen("/proc/stat", "r");
    u8 tmp[1024];
    u32 val = 0;

    if (!f) return 0;

    while (fgets(tmp, sizeof(tmp), f)) {

        if (!strncmp(tmp, "procs_running ", 14) ||
            !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

    }

    fclose(f);

    if (!res) {

        res = val;

    } else {

        res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
              ((double)val) * (1.0 / AVG_SMOOTHING);

    }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

    return res;

}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

    u32 cur_runnable = 0;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

    cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

    FILE* f = fopen("/proc/stat", "r");
    u8 tmp[1024];

    if (!f) return;

    while (fgets(tmp, sizeof(tmp), f))
        if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) cpu_core_count++;

    fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

    if (cpu_core_count > 0) {

        cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

        /* Add ourselves, since the 1-minute average doesn't include that yet. */

    cur_runnable++;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

        printf("You have %u CPU core%s and %u runnable tasks (utilization: %0.0f%%).\n",
               cpu_core_count, cpu_core_count > 1 ? "s" : "",
               cur_runnable, cur_runnable * 100.0 / cpu_core_count);

        if (cpu_core_count > 1) {

            if (cur_runnable > cpu_core_count * 1.5) {

                printf("System under apparent load, performance may be spotty.\n");

            }

        }

    } else {

        cpu_core_count = 0;
        printf("Unable to figure out the number of CPU cores.\n");

    }

}

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */
static void bind_to_free_cpu(void) {

    DIR* d;
    struct dirent* de;
    cpu_set_t c;

    u8 cpu_used[4096] = { 0 };
    u32 i;

    if (cpu_core_count < 2) return;

    if (getenv("AFL_NO_AFFINITY")) {

        perror("Not binding to a CPU core (AFL_NO_AFFINITY set).");
        return;

    }

    d = opendir("/proc");

    if (!d) {

        perror("Unable to access /proc - can't scan for free CPU cores.");
        return;

    }

    printf("Checking CPU core loadout...\n");

    /* Introduce some jitter, in case multiple AFL tasks are doing the same
       thing at the same time... */

    usleep(R(1000) * 250);

    /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
       Flag all processes bound to a specific CPU using cpu_used[]. This will
       fail for some exotic binding setups, but is likely good enough in almost
       all real-world use cases. */

    while ((de = readdir(d))) {

        u8* fn;
        FILE* f;
        u8 tmp[MAX_LINE];
        u8 has_vmsize = 0;

        if (!isdigit(de->d_name[0])) continue;

        fn = alloc_printf("/proc/%s/status", de->d_name);

        if (!(f = fopen(fn, "r"))) {
            free(fn);
            continue;
        }

        while (fgets(tmp, MAX_LINE, f)) {

            u32 hval;

            /* Processes without VmSize are probably kernel tasks. */

            if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

            if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
                !strchr(tmp, '-') && !strchr(tmp, ',') &&
                sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
                has_vmsize) {

                cpu_used[hval] = 1;
                break;

            }

        }

        free(fn);
        fclose(f);

    }

    closedir(d);

    for (i = 0; i < cpu_core_count; i++) if (!cpu_used[i]) break;

    if (i == cpu_core_count) {
        printf("No more free CPU cores\n");

    }

    printf("Found a free CPU core, binding to #%u.\n", i);

    cpu_aff = i;

    CPU_ZERO(&c);
    CPU_SET(i, &c);

    if (sched_setaffinity(0, sizeof(c), &c))
        perror("sched_setaffinity failed\n");

}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

    struct timeval tv;
    struct timezone tz;

    gettimeofday(&tv, &tz);

    return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */
//todo 这里是重点
static u8 run_target(int timeout) {

    static struct itimerval it;
    static u32 prev_timed_out = 0;

    int status = 0;

    child_timed_out = 0;

    /* After this memset, trace_bits[] are effectively volatile, so we
       must prevent any earlier operations from venturing into that
       territory. */

    memset(trace_bits, 0, MAP_SIZE);
    MEM_BARRIER();

    int res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

        if (stop_soon) return 0;
        fprintf(stderr,"err%d: Unable to request new process from fork server (OOM?)", res);

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

        if (stop_soon) return 0;
        fprintf(stderr, "err%d: Unable to request new process from fork server (OOM?)",res);

    }
    if (child_pid <= 0) perror("Fork server is misbehaving (OOM?)");


    /* Configure timeout, as requested by user, then wait for child to terminate. */

    it.it_value.tv_sec = (timeout / 1000);
    it.it_value.tv_usec = (timeout % 1000) * 1000;

    setitimer(ITIMER_REAL, &it, NULL);

    /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */



    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

        if (stop_soon) return 0;
        fprintf(stderr, "err%d: Unable to communicate with fork server (OOM?)",res);

    }


    if (!WIFSTOPPED(status)) child_pid = 0;

    it.it_value.tv_sec = 0;
    it.it_value.tv_usec = 0;

    setitimer(ITIMER_REAL, &it, NULL);

    total_execs++;

    /* Any subsequent operations on trace_bits must not be moved by the
       compiler below this point. Past this location, trace_bits[] behave
       very normally and do not have to be treated as volatile. */

    MEM_BARRIER();


#ifdef __x86_64__
    classify_counts((u64*)trace_bits);
#else
    classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

    prev_timed_out = child_timed_out;

    /* Report outcome to caller. */

    if (WIFSIGNALED(status) && !stop_soon) {

        kill_signal = WTERMSIG(status);

        if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

        return FAULT_CRASH;

    }
    return FAULT_NONE;

}

/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {
    // 理论上来说这个可以舍弃了

    int fd = out_fd;

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) perror("Unable to create file");


    ck_write(fd, mem, len, out_file);

    close(fd);

}

/* Check CPU governor. */

static void check_cpu_governor(void) {

    FILE* f;
    u8 tmp[128];
    u64 min = 0, max = 0;

    if (getenv("AFL_SKIP_CPUFREQ")) return;

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
    if (!f) return;

    printf("Checking CPU scaling governor...\n");

    if (!fgets(tmp, 128, f)) perror("fgets() failed");

    fclose(f);

    if (!strncmp(tmp, "perf", 4)) return;

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

    if (f) {
        if (fscanf(f, "%llu", &min) != 1) min = 0;
        fclose(f);
    }

    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

    if (f) {
        if (fscanf(f, "%llu", &max) != 1) max = 0;
        fclose(f);
    }

    if (min == max) return;

    printf("Err: Suboptimal CPU scaling governor\n");

}

/* parse one line of gradient string into array */
void parse_array(char * str, int * array){

    int i=0;

    char* token = strtok(str,",");

    while(token != NULL){
        array[i]=atoi(token);
        i++;
        token = strtok(NULL, ",");
    }

    return;
}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

    u32 min_value, max_value;

    switch ((random()%3)) {

        case 0:  min_value = 1;
            max_value = havoc_blk_small;
            break;

        case 1:  min_value = havoc_blk_small;
            max_value = havoc_blk_medium;
            break;

        case 2:  min_value = havoc_blk_medium;
            max_value = havoc_blk_large;
    }

    if (min_value >= limit) min_value = 1;

    return min_value + (random()%(MIN(max_value, limit) - min_value + 1));

}

/* gradient guided mutation */
void gen_mutate(){
    int tmout_cnt = 0;

    /* flip interesting locations within 14 iterations */
    for(int iter=0 ;iter<13; iter=iter+1){
        memcpy(out_buf1, out_buf, len);
        memcpy(out_buf2, out_buf, len);

        /* find mutation range for every iteration */
        int low_index = num_index[iter];
        int up_index = num_index[iter+1];
        u8 up_step = 0;
        u8 low_step = 0;
        for(int index=low_index; index<up_index; index=index+1){
            int cur_up_step = 0;
            int cur_low_step = 0;
            if(sign[index] == 1){
                cur_up_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (u8)(out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
            else{
                cur_up_step = (u8)out_buf[loc[index]];
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
        }

        /* up direction mutation(up to 255) */
        for(int step=0;step<up_step;step=step+1){
            int mut_val;
            for(int index=low_index; index<up_index; index=index+1){
                mut_val = ((u8)out_buf1[loc[index]] + sign[index]);
                if(mut_val < 0)
                    out_buf1[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf1[loc[index]] = 255;
                else
                    out_buf1[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf1, len);
            int fault = run_target(exec_tmout);
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000);
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }
            }
            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }

        }

        /* low direction mutation(up to 255) */
        for(int step=0;step<low_step;step=step+1){
            for(int index=low_index; index<up_index;index=index+1){
                int mut_val = ((u8)out_buf2[loc[index]] - sign[index]);
                if(mut_val < 0)
                    out_buf2[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf2[loc[index]] = 255;
                else
                    out_buf2[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf2, len);
            int fault = run_target(exec_tmout);
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf2, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000);
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf2, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }
            }

            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }

        }
    }

    /* random insertion/deletion */
    int cut_len = 0;
    int del_loc = 0;
    int rand_loc = 0;
    for(int del_count=0; del_count < 1024;del_count= del_count+1){
        del_loc = loc[del_count];
        if ((len- del_loc) <= 2)
            continue;
        cut_len = choose_block_len(len-1-del_loc);

        /* random deletion at a critical offset */
        memcpy(out_buf1, out_buf,del_loc);
        memcpy(out_buf1+del_loc, out_buf+del_loc+cut_len, len-del_loc-cut_len);

        write_to_testcase(out_buf1, len-cut_len);

        int fault = run_target(exec_tmout);
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000);
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len - cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
            }
        }

        /* save mutations that find new edges. */
        int ret = has_new_bits(virgin_bits);
        if(ret==2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret==1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }

        cut_len = choose_block_len(len-1);
        rand_loc = (random()%cut_len);

        /* random insertion at a critical offset */
        memcpy(out_buf3, out_buf, del_loc);
        memcpy(out_buf3+del_loc, out_buf+rand_loc, cut_len);
        memcpy(out_buf3+del_loc+cut_len, out_buf+del_loc, len-del_loc);

        write_to_testcase(out_buf3, len+cut_len);

        fault = run_target(exec_tmout);
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000);
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf3, len + cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
            }
        }

        /* save mutations that find new edges. */
        ret = has_new_bits(virgin_bits);
        if(ret == 2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret == 1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
    }
}

/* only pop up the slow mutation when NEUZZ starts to stall */
void gen_mutate_slow(){
    int tmout_cnt = 0;

    /* flip interesting locations within 14 iterations */
    for(int iter=0 ;iter<13; iter=iter+1){
        memcpy(out_buf1, out_buf, len);
        memcpy(out_buf2, out_buf, len);

        /* find mutation range for every iteration */
        int low_index = num_index[iter];
        int up_index = num_index[iter+1];
        u8 up_step = 0;
        u8 low_step = 0;
        for(int index=low_index; index<up_index; index=index+1){
            int cur_up_step = 0;
            int cur_low_step = 0;
            if(sign[index] == 1){
                cur_up_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (u8)(out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
            else{
                cur_up_step = (u8)out_buf[loc[index]];
                if(cur_up_step > up_step)
                    up_step = cur_up_step;
                cur_low_step = (255 - (u8)out_buf[loc[index]]);
                if(cur_low_step > low_step)
                    low_step = cur_low_step;
            }
        }

        /* up direction mutation(up to 255) */
        for(int step=0;step<up_step;step=step+1){
            int mut_val;
            for(int index=low_index; index<up_index; index=index+1){
                mut_val = ((u8)out_buf1[loc[index]] + sign[index]);
                if(mut_val < 0)
                    out_buf1[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf1[loc[index]] = 255;
                else
                    out_buf1[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf1, len);
            int fault = run_target(exec_tmout);
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000);
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }
            }

            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }

        }

        /* low direction mutation(up to 255) */
        for(int step=0;step<low_step;step=step+1){
            for(int index=low_index; index<up_index;index=index+1){
                int mut_val = ((u8)out_buf2[loc[index]] - sign[index]);
                if(mut_val < 0)
                    out_buf2[loc[index]] = 0;
                else if (mut_val > 255)
                    out_buf2[loc[index]] = 255;
                else
                    out_buf2[loc[index]] = mut_val;
            }

            write_to_testcase(out_buf2, len);
            int fault = run_target(exec_tmout);
            if (fault != 0){
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf2, len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
                else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                    tmout_cnt = tmout_cnt + 1;
                    fault = run_target(1000);
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf2, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }
            }

            /* save mutations that find new edges. */
            int ret = has_new_bits(virgin_bits);
            if(ret == 2){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d_cov", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }
            if(ret == 1){
                char* mut_fn = alloc_printf("%s/id_%d_%d_%06d", out_dir, round_cnt, iter, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf2, len, mut_fn);
                close(mut_fd);
                free(mut_fn);
                mut_cnt = mut_cnt + 1;
            }

        }
    }

    /* more random insertion/deletion than normal round */
    int cut_len = 0;
    int del_loc = 0;
    int rand_loc = 0;
    for(int del_count=0; del_count < 4096;del_count= del_count+1){
        del_loc = loc[del_count];
        if ((len- del_loc) <= 2)
            continue;
        cut_len = choose_block_len(len-1-del_loc);

        /* random deletion at a critical offset */
        memcpy(out_buf1, out_buf,del_loc);
        memcpy(out_buf1+del_loc, out_buf+del_loc+cut_len, len-del_loc-cut_len);

        write_to_testcase(out_buf1, len-cut_len);

        int fault = run_target(exec_tmout);
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000);
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf1, len - cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
            }
        }

        /* save mutations that find new edges. */
        int ret = has_new_bits(virgin_bits);
        if(ret==2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret==1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf1, len-cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }

        cut_len = choose_block_len(len-1);
        rand_loc = (random()%cut_len);

        /* random insertion at a critical offset */
        memcpy(out_buf3, out_buf, del_loc);
        memcpy(out_buf3+del_loc, out_buf+rand_loc, cut_len);
        memcpy(out_buf3+del_loc+cut_len, out_buf+del_loc, len-del_loc);

        write_to_testcase(out_buf3, len+cut_len);

        fault = run_target(exec_tmout);
        if (fault != 0){
            if(fault == FAULT_CRASH){
                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
                free(mut_fn);
                close(mut_fd);
                mut_cnt = mut_cnt + 1;
            }
            else if((fault = FAULT_TMOUT) && (tmout_cnt < 20)){
                tmout_cnt = tmout_cnt + 1;
                fault = run_target(1000);
                if(fault == FAULT_CRASH){
                    char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                    int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    ck_write(mut_fd, out_buf3, len + cut_len, mut_fn);
                    free(mut_fn);
                    close(mut_fd);
                    mut_cnt = mut_cnt + 1;
                }
            }
        }

        /* save mutations that find new edges. */
        ret = has_new_bits(virgin_bits);
        if(ret == 2){
            char* mut_fn = alloc_printf("%s/id_%d_%06d_cov", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }
        else if(ret == 1){
            char* mut_fn = alloc_printf("%s/id_%d_%06d", "vari_seeds",round_cnt, mut_cnt);
            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
            ck_write(mut_fd, out_buf3, len+cut_len, mut_fn);
            free(mut_fn);
            close(mut_fd);
            mut_cnt = mut_cnt + 1;
        }    DIR *dp;
        struct dirent *entry;
        struct stat statbuf;
        if((dp = opendir(dir)) == NULL) {
            fprintf(stderr,"cannot open directory: %s\n", dir);
            return;
        }
        if(chdir(dir)== -1)
            perror("chdir failed\n");
        int cnt = 0;
        u64 start_us, stop_us;
        while((entry = readdir(dp)) != NULL) {
            if(stat(entry->d_name,&statbuf) == -1)
                continue;
            if(S_ISREG(statbuf.st_mode)) {
                char * tmp = NULL;
                tmp = strstr(entry->d_name,".");
                if(tmp != entry->d_name){
                    int fd_tmp = open(entry->d_name, O_RDONLY);
                    if(fd_tmp == -1)
                        perror("open failed");
                    int file_len = statbuf.st_size;
                    memset(out_buf1, 0, len);
                    ck_read(fd_tmp, out_buf1,file_len, entry->d_name);

                    start_us = get_cur_time_us();
                    write_to_testcase(out_buf1, file_len);
                    int fault = run_target(exec_tmout);
                    if (fault != 0){
                        if(fault == FAULT_CRASH){
                            char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                            ck_write(mut_fd, out_buf1, file_len, mut_fn);
                            free(mut_fn);
                            close(mut_fd);
                            mut_cnt = mut_cnt + 1;
                        }
                        else if(fault = FAULT_TMOUT){
                            fault = run_target(1000);
                            if(fault == FAULT_CRASH){
                                char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                                int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                                ck_write(mut_fd, out_buf1, file_len, mut_fn);
                                free(mut_fn);
                                close(mut_fd);
                                mut_cnt = mut_cnt + 1;
                            }
                        }
                    }

                    int ret = has_new_bits(virgin_bits);
                    if (ret!=0){
                        if(stage == 1){
                            char* mut_fn = alloc_printf("../%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
                            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                            ck_write(mut_fd, out_buf1, len, mut_fn);
                            free(mut_fn);
                            close(mut_fd);
                            mut_cnt = mut_cnt + 1;
                        }
                    }

                    stop_us = get_cur_time_us();
                    total_cal_us = total_cal_us - start_us + stop_us;
                    cnt = cnt + 1;
                    close(fd_tmp);
                }
            }
        }
        if(chdir("..") == -1)
            perror("chdir failed\n");
        closedir(dp);

        /* estimate the average exec time at the beginning*/
        if(stage ==2 ){
            u64 avg_us = (u64)(total_cal_us / cnt);
            if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
            else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
            else exec_tmout = avg_us * 5 / 1000;

            exec_tmout = (exec_tmout + 20) / 20 * 20;
            exec_tmout =  exec_tmout;
            printf("avg %d time out %d cnt %d sum %lld \n.",(int)avg_us, exec_tmout, cnt,total_cal_us);
        }

        printf("dry run %ld edge coverage %d.\n", total_execs,count_non_255_bytes(virgin_bits));
        return;
    }
}

/* dry run the seeds at dir, when stage == 1, save interesting seeds to out_dir; when stage == 2, compute the average exec time */
//todo 把aflnet的queue添加到此处
void dry_run(char* dir, int stage){
    DIR *dp;
    struct dirent *entry;
    struct stat statbuf;
    if((dp = opendir(dir)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", dir);
        return;
    }
    if(chdir(dir)== -1)
        perror("chdir failed\n");
    int cnt = 0;
    u64 start_us, stop_us;

    while((entry = readdir(dp)) != NULL) {
        if(stat(entry->d_name,&statbuf) == -1)
            continue;
        if(S_ISREG(statbuf.st_mode)) {
            char * tmp = NULL;
            tmp = strstr(entry->d_name,".");
            if(tmp != entry->d_name){
                int fd_tmp = open(entry->d_name, O_RDONLY);
                if(fd_tmp == -1)
                    perror("open failed");
                int file_len = statbuf.st_size;
                memset(out_buf1, 0, len);
                ck_read(fd_tmp, out_buf1,file_len, entry->d_name);

                start_us = get_cur_time_us();
                write_to_testcase(out_buf1, file_len);
                int fault = run_target(exec_tmout);

                if (fault != 0){
                    if(fault == FAULT_CRASH){
                        char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, file_len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                    else if(fault = FAULT_TMOUT){
                        fault = run_target(1000);
                        if(fault == FAULT_CRASH){
                            char* mut_fn = alloc_printf("%s/crash_%d_%06d", "./crashes",round_cnt, mut_cnt);
                            int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                            ck_write(mut_fd, out_buf1, file_len, mut_fn);
                            free(mut_fn);
                            close(mut_fd);
                            mut_cnt = mut_cnt + 1;
                        }
                    }
                }

                int ret = has_new_bits(virgin_bits);
                if (ret!=0){
                    if(stage == 1){
                        char* mut_fn = alloc_printf("../%s/id_%d_%06d", out_dir,round_cnt, mut_cnt);
                        int mut_fd = open(mut_fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                        ck_write(mut_fd, out_buf1, len, mut_fn);
                        free(mut_fn);
                        close(mut_fd);
                        mut_cnt = mut_cnt + 1;
                    }
                }

                stop_us = get_cur_time_us();
                total_cal_us = total_cal_us - start_us + stop_us;
                cnt = cnt + 1;
                close(fd_tmp);
            }
        }
    }
    if(chdir("..") == -1)
        perror("chdir failed\n");
    closedir(dp);

    /* estimate the average exec time at the beginning*/
    if(stage ==2 ){
        u64 avg_us = (u64)(total_cal_us / cnt);
        if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
        else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
        else exec_tmout = avg_us * 5 / 1000;

        exec_tmout = (exec_tmout + 20) / 20 * 20;
        exec_tmout =  exec_tmout;
        printf("avg %d time out %d cnt %d sum %lld \n.",(int)avg_us, exec_tmout, cnt,total_cal_us);
    }

    printf("dry run %ld edge coverage %d.\n", total_execs,count_non_255_bytes(virgin_bits));
    return;
}


void copy_file(char* src, char* dst){
    FILE *fptr1, *fptr2;
    int c;
    fptr1 = fopen(src, "r");
    if (fptr1 == NULL)
    {
        printf("Cannot open file %s \n", src);
        exit(0);
    }

    fptr2 = fopen(dst, "w");
    if (fptr2 == NULL)
    {
        printf("Cannot open file %s \n", dst);
        exit(0);
    }

    c = fgetc(fptr1);
    while (c != EOF)
    {
        fputc(c, fptr2);
        c = fgetc(fptr1);
    }

    fclose(fptr1);
    fclose(fptr2);
    return;
}

/* copy seeds from in_idr to out_dir */
void copy_seeds(char * in_dir, char * out_dir){
    struct dirent *de;
    DIR *dp;
    if((dp = opendir(in_dir)) == NULL) {
        fprintf(stderr,"cannot open directory: %s\n", in_dir);
        return;
    }
    char src[128], dst[128];
    while((de = readdir(dp)) != NULL){
        if(strcmp(".",de->d_name) == 0 || strcmp("..",de->d_name) == 0)
            continue;
        sprintf(src, "%s/%s", in_dir, de->d_name);
        sprintf(dst, "%s/%s", out_dir, de->d_name);
        copy_file(src, dst);
    }
    closedir(dp);
    return ;
}

/* parse the gradient to guide fuzzing */
void fuzz_lop(char * grad_file, int sock){
    dry_run("./splice_seeds/", 1);
    copy_file("gradient_info_p", grad_file);
    FILE *stream = fopen(grad_file, "r");
    char *line = NULL;
    size_t llen = 0;
    ssize_t nread;
    if (stream == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    int line_cnt=0;

    int retrain_interval = 1000;
    if(round_cnt == 0)
        retrain_interval = 750;

    while ((nread = getline(&line, &llen, stream)) != -1) {
        line_cnt = line_cnt+1;

        /* send message to python module */
        if(line_cnt == retrain_interval){
            round_cnt++;
            now = count_non_255_bytes(virgin_bits);
            edge_gain = now - old;
            old = now;
            if((edge_gain > 30) || (fast == 0)){
                send(sock,"train", 5,0);
                fast = 1;
                printf("fast stage\n");
            }
            else{
                send(sock,"sloww",5,0);
                fast = 0;
                printf("slow stage\n");
            }
        }

        /* parse gradient info */
        char* loc_str = strtok(line,"|");
        char* sign_str = strtok(NULL,"|");
        char* fn = strtok(strtok(NULL,"|"),"\n");
        parse_array(loc_str,loc);
        parse_array(sign_str,sign);

        /* print edge coverage per 10 files*/
        if((line_cnt % 10) == 0){
            printf("$$$$&&&& fuzz %s line_cnt %d\n",fn, line_cnt);
            printf("edge num %d\n",count_non_255_bytes(virgin_bits));
            fflush(stdout);
        }

        /* read seed into mem */
        int fn_fd = open(fn,O_RDONLY);
        if(fn_fd == -1){
            perror("open failed");
            exit(0);
        }
        struct stat st;
        int ret = fstat(fn_fd,&st);
        int file_len = st.st_size;
        memset(out_buf1,0,len);
        memset(out_buf2,0,len);
        memset(out_buf,0, len);
        memset(out_buf3,0, 20000);
        ck_read(fn_fd, out_buf, file_len, fn);

        /* generate mutation */
        if(stage_num == 1)
            gen_mutate();
        else
            gen_mutate_slow();
        close(fn_fd);
    }
    stage_num = fast;
    free(line);
    fclose(stream);
}

/* connect to python NN module, then read the gradient file to guide fuzzing */
void start_fuzz(int f_len){

    /* connect to python module */
    struct sockaddr_in address;
    int sock = 0;
    struct sockaddr_in serv_addr;
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        perror("Socket creation error");
        exit(0);
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){
        perror("Invalid address/ Address not supported");
        exit(0);
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        perror("Connection Failed");
        exit(0);
    }

    /* set up buffer */
    out_buf = malloc(10000);
    if(!out_buf)
        perror("malloc failed");
    out_buf1 = malloc(10000);
    if(!out_buf1)
        perror("malloc failed");
    out_buf2 = malloc(10000);
    if(!out_buf2)
        perror("malloc failed");
    out_buf3 = malloc(20000);
    if(!out_buf3)
        perror("malloc failed");

    len = f_len;
    /* dry run seeds*/
    dry_run(out_dir, 2);

    /* start fuzz */
    char buf[16];
    while(1){
        if(read(sock , buf, 5)== -1)
            perror("received failed\n");
        fuzz_lop("gradient_info", sock);
        printf("receive\n");
    }
    return;
}

/* function for local debugging, replace it with start_fuzz */
void start_fuzz_test(int f_len){
    int sock = 0;

    /* set up buffer */
    out_buf = malloc(10000);
    if(!out_buf)
        perror("malloc failed");
    out_buf1 = malloc(10000);
    if(!out_buf1)
        perror("malloc failed");
    out_buf2 = malloc(10000);
    if(!out_buf2)
        perror("malloc failed");
    out_buf3 = malloc(20000);
    if(!out_buf3)
        perror("malloc failed");

    len = f_len;
    /* dry run */
    //todo 4
    dry_run(out_dir, 0);
    /* fuzz */
    fuzz_lop("gradient_info", sock);
    return;
}

void main(int argc, char*argv[]){
    int opt;
    while ((opt = getopt(argc, argv, "+i:o:l:")) > 0)

        switch (opt) {

            case 'i': /* input dir */

                if (in_dir) perror("Multiple -i options not supported");
                in_dir = optarg;

                break;

            case 'o': /* output dir */

                if (out_dir) perror("Multiple -o options not supported");
                out_dir = optarg;
                break;

            case 'l': /* file len */
                sscanf (optarg,"%ld",&len);
                /* change num_index and havoc_blk_* according to file len */
                if(len > 7000)
                {
                    num_index[13] = (len - 1);
                    havoc_blk_large = (len - 1);
                }
                else if (len > 4000)
                {
                    num_index[13] = (len - 1);
                    num_index[12] = 3072;
                    havoc_blk_large = (len - 1);
                    havoc_blk_medium = 2048;
                    havoc_blk_small = 1024;
                }
                printf("num_index %d %d small %d medium %d large %d\n", num_index[12], num_index[13], havoc_blk_small, havoc_blk_medium, havoc_blk_large);
                printf("mutation len: %ld\n", len);
                break;

            default:
                printf("no manual...");
        }

    setup_signal_handlers();
    check_cpu_governor();
    get_core_count();
    bind_to_free_cpu();
    setup_shm();
    init_count_class16();
    //todo 1
    setup_ipsm();
    setup_dirs_fds();
    //todo
    read_testcases();
    if (!out_file) setup_stdio_file();
    detect_file_args(argv + optind + 1);
    setup_targetpath(argv[optind]);

    copy_seeds(in_dir, out_dir);
    init_forkserver(argv+optind);
//    perform_dry_run(use_argv);


    start_fuzz(len);
    //todo 2
    destroy_ipsm();
    printf("total execs %ld edge coverage %d.\n", total_execs, count_non_255_bytes(virgin_bits));
    return;

}