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

        /* Move the process to the different namespace. */

        if (netns_name)
            move_process_to_netns();

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
        close(fileno(plot_file));

        /* This should improve performance a bit, since it stops the linker from
           doing extra work post-fork(). */

        if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

        /* Set sane defaults for ASAN if nothing else specified. */

        setenv("ASAN_OPTIONS", "abort_on_error=1:"
                               "detect_leaks=0:"
                               "symbolize=0:"
                               "allocator_may_return_null=1", 0);

        /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
           point. So, we do this in a very hacky way. */

        setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                                                                  "symbolize=0:"
                                                                  "abort_on_error=1:"
                                                                  "allocator_may_return_null=1:"
                                                                  "msan_track_origins=0", 0);

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

//todo: 当前还未完成dry_run的重构
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

int main(int argc, char** argv) {
    //todo：输入变量变量变形



    //todo: 把流程走一遍
    setup_signal_handlers();
    check_asan_opts();
    check_cpu_governor();
    get_core_count();
    bind_to_free_cpu();
    setup_shm();
    init_count_class16();
    setup_ipsm(); //核心添加的部分
    setup_dirs_fds();
    if (!out_file) setup_stdio_file();
    detect_file_args(argv + optind + 1);
    setup_targetpath(argv[optind]);
    copy_seeds(in_dir, out_dir);
    init_forkserver(argv+optind);
    start_fuzz(len);
}