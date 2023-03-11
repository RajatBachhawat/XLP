// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "writesnoop.h"
#include "syscall.h"
#include "writesnoop.skel.h"

#define QUOTE(...) #__VA_ARGS__

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	u32 event_id = *((u32 *)data);
	// TODO: ADD SANITY CHECK OF EVENT ID
	data = data + sizeof(u32);
	switch(event_id)
	{
		case APP:
		{
			const struct applog_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);

			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"data":{
						"fd":%d,
						"lms":"%s"
					},
					"artifacts":{
						"exe":"%s"
						// "file_read"
					}
				}
				),
				d->ts, ts, d->pid, d->tgid, d->ppid, d->comm, d->fd, d->msg, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_READ:
		{
			const struct read_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);

			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"read",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"fd":%d,
						"buf":"0x%x",
						"count":%u
					},
					"artifacts":{
						"exe":"%s"
						// "file_read"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->fd, (unsigned int)d->buf, d->count, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_WRITE:
		{
			const struct write_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);
			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"write",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"fd":%d,
						"buf":"0x%x",
						"count":%u
					},
					"artifacts":{
						"exe":"%s"
						// "file_written"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->fd, (unsigned int)d->buf, d->count, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_OPEN:
		{
			const struct open_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);
			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"open",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"filename":"%s",
						"flags":%d,
						"mode":%d
					},
					"artifacts":{
						"exe":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->filename, d->flags, d->mode, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_CLOSE:
		{
			const struct close_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);
			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"close",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"fd":%d
					},
					"artifacts":{
						"exe":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->fd, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_DUP:
		case SYSCALL_DUP2:
		// case SYSCALL_SOCKET:
		case SYSCALL_CONNECT:
		case SYSCALL_ACCEPT:
		case SYSCALL_BIND:
		// case SYSCALL_LISTEN:
			break; 
		case SYSCALL_EXECVE:
		{
			const struct execve_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"execve",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"filename":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->filename
			);
			break;
		}
		case SYSCALL_EXIT:
		{
			const struct exit_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);

			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"exit",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"error_code":"%d"
					},
					"artifacts":{
						"exe":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->error_code, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_EXIT_GROUP:
		{
			const struct exit_group_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);

			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"exit_group",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"error_code":"%d"
					},
					"artifacts":{
						"exe":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->error_code, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_OPENAT:
		{
			const struct openat_data_t *d = data;
			char ts[32]; time_t t;

			time(&t); struct tm *tmd = localtime(&t);
			strftime(ts, sizeof(ts), "%H:%M:%S", tmd);

			struct writesnoop_bpf *skel = (struct writesnoop_bpf *)ctx;
			struct copy_str exe_name = {};
			bpf_map__lookup_elem(skel->maps.pid_exec_mapper, &(d->pid), sizeof(d->pid),
				&exe_name, sizeof(exe_name), 0
			);
			printf(
				QUOTE(
				{
					"event_context":{
						"ts":%llu,
						"datetime":"%s",
						"syscall_id":%d,
						"syscall_name":"openat",
						"task_context":{
							"host_pid":%d,
							"host_tid":%d,
							"host_ppid":%d,
							"task_command":"%s"
						}
					},
					"arguments":{
						"dfd":%d,
						"filename":"%s",
						"flags":%d,
						"mode":%d
					},
					"artifacts":{
						"exe":"%s"
					}
				}
				),
				d->ts, ts, d->syscall_id, d->pid, d->tgid,
				d->ppid, d->comm, d->dfd, d->filename, d->flags, d->mode, exe_name.exe_name
			);
			break;
		}
		case SYSCALL_UNLINKAT:
		case SYSCALL_ACCEPT4:
		case SYSCALL_DUP3:
		default:
		{
			break;
		}
	}
	printf(",\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct writesnoop_bpf *skel;

	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = writesnoop_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ensure that BPF program only handles write() syscalls from other processes */
	skel->bss->mypid = getpid();

	/* Load & verify BPF programs */
	err = writesnoop_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = writesnoop_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, skel, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	printf("{\n\"logs\":[\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* 1out, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}
	printf("]\n}");

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	writesnoop_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
