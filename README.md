# Universal Log File Generator

A collection of eBPF programs for tracing system calls, enriching them with extra information and logging them along with logging application based events (by keeping track of `write` calls made to a log file) into a single universal log file.

## Requirements
### User-space libraries
- libelf
- libbpf-bootstrap
### Kernel-level
- `CONFIG_DEBUG_INFO_BTF=y`
- Linux Kernel Version 5.8+
### Architecture
- x86-64

## How to Run
1. Install all the required libraries and ensure the kernel config is correct.
2. Make the necessary changes to the `Makefile` depending on where your libbpf-bootstrap directory with the required library source files is installed.
3. Add a target by the name of your eBPF program. E.g.: For `writesnoop.bpf.c`, the target is writesnoop.
4. Run `make writesnoop`.
5. Run the `writesnoop` binary generated, with super user privileges.

## Files and Directories
- `.output/`: Contains all the necessary library binaries compiled by the Makefile from libbpf-bootstrap.
- `.output/writesnoop.skel.h`: Skeleton eBPF header file generated from `writesnoop.skel.h`. Describes the structure of the ELF binary of the eBPF program. Declares wrapper functions for the `writesnoop` app over the libbpf functions for loading, attaching, etc. of the eBPF program
- `writesnoop.bpf.c`: The eBPF program logic, written in C using libbpf C CO-RE
- `writesnoop.c`: The frontend of the eBPF program. Contains the code for opening, loading, attaching of the eBPF program to the right hooks. Also contains the logic for handling of the various syscall log + application log events. Writes to the log file.
- `writesnoop.h` and `util.h`: Useful user-defined structs and helper functions.

## Challenges and Design Choices

### General

- Use of the bpf ring buffer instead of the per CPU ring buffer as the event queue so that the events are read in an ordered fashion from a single event queue.
- Also, `bpf_ringbuf_reserve()` is used to allocate space on the ring buffer itself directly, so the need to temporarily create the event data structures on the program stack (or a scratch space) is eliminated, thus saving memory and time (as events are created inplace in the queue).
- The function `bpf_ringbuf_reserve()` must always have a corresponding `bpf_ringbuf_submit()` call in all possible computation paths that the program takes, otherwise the eBPF verifier throws an error.
- For submitting of events to the event queue, we do the following. We reserve space as follows in the queue:
```
                        -----------------------------------------------
                        | event_id (4) | struct <event_name>_data (?) |
                        -----------------------------------------------
```
During the reading of these events at the frontend, we find out the event_name using the event_id, and thus, parse the next `sizeof(struct <event_name>_data)` number of bytes using the corresponding struct definition.

### Application events

### System Call events

1. `write`
- Additional information added: Path of executable that made the call, Name of the file written to (TODO)
- 
2. `read`
- Additional information added: Path of executable that made the call, Name of the file written to (TODO)
3. `exec`