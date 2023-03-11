#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "writesnoop.h"
#include "util.h"
#include "syscall.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
    __type(value, struct copy_str);
    __uint(max_entries, 10240);
} pid_exec_mapper SEC(".maps");

int mypid = 0;

/* Compare two strings (whose sizes are known) passed for equality */
static __always_inline int string_cmp(
    const unsigned char *string1,
    const unsigned char *string2,
    unsigned int size1,
    unsigned int size2)
{
    if(size1 != size2) {
        return -1;
    }
    for(int i = 0; i < size1; ++i) {
        if(string1[i] != string2[i]) {
            return -1;
        }
    }
    return 0;
}

static inline void string_cpy(char* string_to, const char* string_from, int len_from)
{
    for(int i = 0;i < len_from; i++)
    {
        string_to[i] = string_from[i];
    }
}

/* Check if the filepath to which the write call is equal to - "/var/log/app/.*" */
static __always_inline int check_log_filepath(unsigned int fd) {
    // struct files_struct *files = NULL;
    // struct fdtable *fdt = NULL;
    struct file **_fdt = NULL;
    struct file *f = NULL;
    struct dentry *de = NULL;
    struct dentry *de_parent = NULL;
    struct task_struct *curr = NULL;
    int nread = 0;
    int buf_cnt = 0;
    int i = 1;
    const unsigned char dirname_var[] = {'v','a','r','\0'};
    const unsigned char dirname_log[] = {'l','o','g','\0'};
    const unsigned char dirname_app[] = {'a','p','p','\0'};
    int var_dirlevel = -1; /* Root directory is the lowest level */
    int log_dirlevel = -1;
    int app_dirlevel = -1;

    curr = (struct task_struct *)bpf_get_current_task();
    // bpf_probe_read_kernel(&files, sizeof(files), &curr->files);
    // bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    // bpf_probe_read_kernel(&_fdt, sizeof(_fdt), &fdt->fd);
    // bpf_probe_read_kernel(&f, sizeof(f), &_fdt[fd]);
    // bpf_probe_read_kernel(&de, sizeof(de), &f->f_path.dentry);
    _fdt = BPF_CORE_READ(curr, files, fdt, fd);
    bpf_core_read(&f, sizeof(f), &_fdt[fd]);;
    de = BPF_CORE_READ(f, f_path.dentry);

    /* Iterate up the dentry hierarchy and store the lowest levels at which
    "var/", "log/" and "app/" occur. If the filepath is "/var/log/app/.*" then
    these levels occur as consecutive integers and thus return 1, else return 0 */
    for (i = MAX_DIR_LEVELS_ALLOWED; i >= 1; --i) {
        // bpf_probe_read_kernel(&de_parent, sizeof(de_parent), &de->d_parent);
        de_parent = BPF_CORE_READ(de, d_parent);
        if(de_parent == NULL) {
            break;
        }
        
	    struct qstr d_name = {};
        unsigned char name[MAX_FILEPATH_SIZE];
        unsigned int len = 0;
        
	    // bpf_probe_read_kernel(&len, sizeof(len), &d_name.len);
        len = BPF_CORE_READ(de_parent, d_name.len);

        // bpf_probe_read(&d_name, sizeof(d_name), &de_parent->d_name);
        // bpf_probe_read_str(name, MAX_FILEPATH_SIZE, d_name.name);
        bpf_core_read(&d_name, sizeof(d_name), &de_parent->d_name);
        bpf_core_read_str(name, MAX_FILEPATH_SIZE, d_name.name);
	
	    if(string_cmp(name, dirname_var, len+1, 4) == 0) {
            var_dirlevel = i;
        }
        if(string_cmp(name, dirname_log, len+1, 4) == 0) {
            log_dirlevel = i;
        }
        if(string_cmp(name, dirname_app, len+1, 4) == 0) {
            app_dirlevel = i;
        }
        de = de_parent;
    }
    return (app_dirlevel == log_dirlevel + 1 && log_dirlevel == var_dirlevel + 1);
}

SEC("tp/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    ctx->args[1] : char *buf
    ctx->args[2] : unsigned int count
    */
    void *event_data;
    struct read_data_t *read_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct read_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    read_data = (struct read_data_t *)init_event(event_data, SYSCALL_READ);
    
    /* Task and event context */
    read_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    read_data->syscall_id = SYSCALL_READ; // syscall id
    read_data->pid = (tgid_pid >> 32); // process id
    read_data->tgid = tgid_pid;
    read_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&read_data->comm, sizeof(read_data->comm)); // command of the task that made the syscall

    /* Arguments */
    read_data->fd = (unsigned int)ctx->args[0];
    read_data->buf = (char *)ctx->args[1];
    read_data->count = (unsigned int)ctx->args[2];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    ctx->args[1] : const char *buf
    ctx->args[2] : unsigned int count
    */
	u64 tgid_pid = bpf_get_current_pid_tgid();
    /* If the write call was made by the frontend program it's useless */
    if(mypid == (tgid_pid >> 32)) {
        return 0;
    }

    /* Generate write system log */
    void *event_data;
    struct write_data_t *write_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();

    event_data = reserve_in_event_queue(&rb, sizeof(struct write_data_t), 0);
    if(!event_data)
        return 0;
    write_data = (struct write_data_t *)init_event(event_data, SYSCALL_WRITE);
    
    /* Task and event context */
    write_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    write_data->syscall_id = SYSCALL_WRITE; // syscall id
    write_data->pid = (tgid_pid >> 32); // process id
    write_data->tgid = tgid_pid;
    write_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&write_data->comm, sizeof(write_data->comm)); // command of the task that made teh syscall

    /* Arguments */
    write_data->fd = (unsigned int)ctx->args[0];
    write_data->buf = (char *)ctx->args[1];
    write_data->count = (unsigned int)ctx->args[2];

    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);

    unsigned int fd = (unsigned int)ctx->args[0];
    /* Write to a log file */
    if(check_log_filepath(fd)) {
        int i = 0;
        int c = 5;
        int cnt = (int)ctx->args[2];
        char *buf = (char *)ctx->args[1];
        while(c--) {
            /* Reserve sizeof(struct applog_data_t) storage in the ringbuffer */
            void *event_data;
            struct applog_data_t *applog_data;

            event_data = reserve_in_event_queue(&rb, sizeof(struct applog_data_t), 0);
            if(!event_data)
                return 0;
            applog_data = (struct applog_data_t *)init_event(event_data, APP);
            
            /* Populate all fields in struct */
            applog_data->ts = bpf_ktime_get_boot_ns();
            applog_data->pid = tgid_pid;
            applog_data->tgid = (tgid_pid >> 32);
            applog_data->ppid = BPF_CORE_READ(curr, real_parent, tgid);
            bpf_get_current_comm(&applog_data->comm, sizeof(applog_data->comm));
            applog_data->fd = fd;
            bpf_core_read_user_str(applog_data->msg, MAX_MSG_LEN, (void *)buf);

            /* Successfully submit it to user-space for post-processing */
            bpf_ringbuf_submit(event_data, 0);

            cnt -= MAX_MSG_LEN;
            if(cnt < 0){
                break;
            }
            buf = buf + MAX_MSG_LEN - 1;
        }
    }
	return 0;
}

SEC("tp/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    ctx->args[0] : const char *filename
    ctx->args[1] : int flags
    ctx->args[2] : umode_t mode
    */
    void *event_data;
    struct open_data_t *open_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct open_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    open_data = (struct open_data_t *)init_event(event_data, SYSCALL_OPEN);
    
    /* Task and event context */
    open_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    open_data->syscall_id = SYSCALL_OPEN; // syscall id
    open_data->pid = (tgid_pid >> 32); // process id
    open_data->tgid = tgid_pid;
    open_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&open_data->comm, sizeof(open_data->comm)); // command of the task that made the syscall

    /* Arguments */
    bpf_core_read_user_str(open_data->filename, sizeof(open_data->filename), (char *)ctx->args[0]);
    open_data->flags = (int)ctx->args[1];
    open_data->mode = (unsigned short)ctx->args[2];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    ctx->args[0] : unsigned int fd
    */
    void *event_data;
    struct close_data_t *close_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct close_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    close_data = (struct close_data_t *)init_event(event_data, SYSCALL_CLOSE);
    
    /* Task and event context */
    close_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    close_data->syscall_id = SYSCALL_CLOSE; // syscall id
    close_data->pid = (tgid_pid >> 32); // process id
    close_data->tgid = tgid_pid;
    close_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&close_data->comm, sizeof(close_data->comm)); // command of the task that made the syscall

    /* Arguments */
    close_data->fd = (unsigned int)ctx->args[0];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    ctx->args[0] : const char *filename
    ctx->args[1] : const char *__argv
    ctx->args[2] : const char *__envp
    */
    void *event_data;
    struct execve_data_t *execve_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct execve_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    execve_data = (struct execve_data_t *)init_event(event_data, SYSCALL_EXECVE);
    
    /* Task and event context */
    execve_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    execve_data->syscall_id = SYSCALL_EXECVE; // syscall id
    execve_data->pid = (tgid_pid >> 32); // process id
    execve_data->tgid = tgid_pid;
    execve_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&execve_data->comm, sizeof(execve_data->comm)); // command of the task that made the syscall

    /* Arguments */
    bpf_core_read_user_str(execve_data->filename, sizeof(execve_data->filename), (char *)ctx->args[0]);
    
    /* Update (pid, name of executable) map */
    struct copy_str ename = {};
    bpf_core_read_user_str(ename.exe_name, sizeof(ename.exe_name), (char *)ctx->args[0]);
    bpf_map_update_elem(&pid_exec_mapper, &tgid, &ename, 0);
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;

}

SEC("tp/syscalls/sys_enter_exit")
int handle_exit(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    cts->args[0] : int error_code
    */
    void *event_data;
    struct exit_data_t *exit_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct exit_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    exit_data = (struct exit_data_t *)init_event(event_data, SYSCALL_EXIT);
    
    /* Task and event context */
    exit_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    exit_data->syscall_id = SYSCALL_EXIT; // syscall id
    exit_data->pid = (tgid_pid >> 32); // process id
    exit_data->tgid = tgid_pid;
    exit_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&exit_data->comm, sizeof(exit_data->comm)); // command of the task that made the syscall

    /* Arguments */
    exit_data->error_code = (int)ctx->args[0];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_exit_group")
int handle_exit_group(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    cts->args[0] : int error_code
    */
    void *event_data;
    struct exit_group_data_t *exit_group_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct exit_group_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    exit_group_data = (struct exit_group_data_t *)init_event(event_data, SYSCALL_EXIT_GROUP);
    
    /* Task and event context */
    exit_group_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    exit_group_data->syscall_id = SYSCALL_EXIT_GROUP; // syscall id
    exit_group_data->pid = (tgid_pid >> 32); // process id
    exit_group_data->tgid = tgid_pid;
    exit_group_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&exit_group_data->comm, sizeof(exit_group_data->comm)); // command of the task that made the syscall

    /* Arguments */
    exit_group_data->error_code = (int)ctx->args[0];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    /* 
    cts->args[0] : int dfd
    ctx->args[1] : const char *filename
    ctx->args[2] : int flags
    ctx->args[3] : umode_t mode
    */
    void *event_data;
    struct openat_data_t *openat_data;
    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 tgid = tgid_pid >> 32;

    /* Reserve space in event queue */
    event_data = reserve_in_event_queue(&rb, sizeof(struct openat_data_t), 0);
    if(!event_data)
        return 0;
    /* Tag the entry with the syscall_id */
    openat_data = (struct openat_data_t *)init_event(event_data, SYSCALL_OPENAT);
    
    /* Task and event context */
    openat_data->ts =  bpf_ktime_get_boot_ns(); // time in nanoseconds when syscall was called
    openat_data->syscall_id = SYSCALL_OPENAT; // syscall id
    openat_data->pid = (tgid_pid >> 32); // process id
    openat_data->tgid = tgid_pid;
    openat_data->ppid = BPF_CORE_READ(curr, real_parent, tgid); // parent process id
    bpf_get_current_comm(&openat_data->comm, sizeof(openat_data->comm)); // command of the task that made the syscall

    /* Arguments */
    openat_data->dfd = (int)ctx->args[0];
    bpf_core_read_user_str(openat_data->filename, sizeof(openat_data->filename), (char *)ctx->args[1]);
    openat_data->flags = (int)ctx->args[2];
    openat_data->mode = (unsigned short)ctx->args[3];
    
    /* Submit to event queue */
    bpf_ringbuf_submit(event_data, 0);
    return 0;
}

