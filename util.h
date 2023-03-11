#ifndef __UTIL_H
#define __UTIL_H

#include "vmlinux.h"
#include "writesnoop.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

static void *reserve_in_event_queue(void *ringbuf, u64 payload_size, u64 flags)
{
    void *data = bpf_ringbuf_reserve(ringbuf, payload_size + sizeof(u32), flags);
    if (!data) /* Null-check the pointer to the address in the ringbuf, must-do */
        return NULL;
    return data;
}

// static void init_context(event_context_t *context, struct task_struct *task, u32 syscall_id)
// {
//     u64 id = bpf_get_current_pid_tgid();
//     context->ts = bpf_ktime_get_boot_ns();
//     context->syscall_id = syscall_id;
//     context->task.host_tid = id;
//     context->task.host_pid = id >> 32;
//     context->task.host_ppid = get_task_ppid(task);
//     context->task.tid = get_task_ns_pid(task);
//     context->task.pid = get_task_ns_tgid(task);
//     context->task.ppid = get_task_ns_ppid(task);
// }

static void *init_event(void *data, u32 syscall_id)
{
    *((u32 *)data) = syscall_id;
    data = data + sizeof(u32);
    return data;
}

// static __always_inline u32 get_task_ppid(struct task_struct *task)
// {
//     return BPF_CORE_READ(task, real_parent, tgid);
// }

// static __always_inline u64 get_task_start_time(struct task_struct *task)
// {
//     return READ_KERN(task->start_time);
// }

// static __always_inline u32 get_task_host_pid(struct task_struct *task)
// {
//     return READ_KERN(task->pid);
// }

// static __always_inline u32 get_task_host_tgid(struct task_struct *task)
// {
//     return READ_KERN(task->tgid);
// }

#endif /* __UTIL_H */