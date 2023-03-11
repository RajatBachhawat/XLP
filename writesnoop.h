/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __WRITESNOOP_H
#define __WRITESNOOP_H

#define TASK_COMM_LEN 16
#define MAX_MSG_LEN 200
#define MAX_FILEPATH_SIZE 100
#define MAX_FILE_AND_DIR_NAME_SIZE 10
#define MAX_DIR_LEVELS_ALLOWED 6
#define SYSCALL_NAME_MAXLEN 20

typedef signed char __s8;
typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __s8 s8;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

// typedef struct task_context {
//     u32 pid;                    /* PID as in the userspace term */
//     u32 tid;                    /* TID as in the userspace term */
//     u32 ppid;                   /* Parent PID as in the userspace term */
//     u32 host_pid;               /* PID in host pid namespace */
//     u32 host_tid;               /* TID in host pid namespace */
//     u32 host_ppid;              /* Parent PID in host pid namespace */
//     char comm[TASK_COMM_LEN];   /* Command for the task */
// } task_context_t;

// typedef struct event_context {
//     u64 ts;                     /* Timestamp at which event occurs */
//     u32 syscall_id;             /* Syscall that triggered event */
//     task_context_t task;        /* Task related context */
// } event_context_t;

struct applog_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id : -1 for application event */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */
    // Data
    unsigned int fd;                            /* File descriptor */
    char msg[MAX_MSG_LEN];                      /* Application log message string (lms) */
};

struct read_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    unsigned int fd;                            /* File descriptor of file to be read */
    char *buf;                                  /* Starting address of buffer */
    size_t count;                               /* Number of bytes ro be read */
    
    int exit_code;                              /* Exit code */
};

struct write_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    unsigned int fd;                            /* File descriptor of file to be written */
    char *buf;                                  /* Starting address of buffer */
    unsigned int count;                         /* Number of bytes being written */
    
    int exit_code;                              /* Exit code */
};

struct open_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    char filename[MAX_FILEPATH_SIZE];           /* File path of the file to be opened */
    int flags;                                  /* Flags */
    unsigned short mode;                        /* Mode */
    
    int exit_code;                              /* Exit code */
};

struct close_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    unsigned int fd;                            /* File descriptor to be closed */

    int exit_code;                              /* Exit code */
};

struct execve_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */
    // Args
    char filename[MAX_FILEPATH_SIZE];           /* File path of the binary that is executed */
    
    int exit_code;                              /* Exit code */
};

struct exit_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    int error_code;                             /* Error code with which exited */
    
    int exit_code;                              /* Exit code */
};

struct exit_group_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    int error_code;                             /* Error code with which exited */
    
    int exit_code;                              /* Exit code */
};

struct openat_data_t {
    // Metadata
    u64 ts;                                     /* time in nanosecs since boot */
    u32 syscall_id;                             /* syscall id */
    u32 pid;                                    /* kernel's view of the pid */
    u32 tgid;                                   /* process's view of the pid */
    u32 ppid;                                   /* kernel's view of the parent's pid */
    char comm[TASK_COMM_LEN];                   /* command for the task */    
    // Args
    int dfd;                                    /* Directory file descriptor */
    char filename[MAX_FILEPATH_SIZE];           /* File path of the file to be opened */
    int flags;                                  /* Flags */
    unsigned short mode;                        /* Mode */
    
    int exit_code;                              /* Exit code */
};

struct copy_str
{
    char exe_name[MAX_FILEPATH_SIZE];
};


#endif /* __WRITESNOOP_H */
