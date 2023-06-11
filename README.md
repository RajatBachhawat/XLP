# Universal Log File Generator

A collection of eBPF programs for tracing system calls, enriching them with container distinguishing information and logging them along with logging similarly enriched application logs (by keeping track of `write` calls made to write logs) into a single universal log file.

## Build Requirements
If you wish to build the binaries from scratch, your system must satisfy the following requirements:
### Libraries/Applications
- `libbelf`
- `zlib`
- `clang`
- `docker`

> The `.output` directory contains a pre-built BPF binary. The build configuration used was:
>- `libelf 0.176-1.1`
>- `zlib 1.2.11`
>- `clang 10.0.0`
>
>If you wish to use this pre-built binary, the first 3 libraries need not be installed in your system.

The `Dockerfile` builds the userspace frontend object file and uses the BPF binary and library files in the `.output` directory to build the final binary that is run.

### Kernel
- `CONFIG_DEBUG_INFO_BTF=y`
- Linux Kernel Version 5.8+

### Architecture
- x86-64

## How to Build from Scratch
### Cloning the repo
1. Run the following command on your shell to clone this repository:
```
git clone <insert URL>
```
2. Run the following command to clone the submodules of the  `libbpf-bootstrap` repo.
```
git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```
### Building the BPF Binary
1. Run the following command to build the `libbpf` library, `bpftool` and the BPF binary.
```
make
```
### Building the Docker Image
1. Make sure all the `.c` files, the `.h` files, `writesnoop.mk` and the `.output/` directory with the BPF binary, `libbpf` and `bpftool` libraries are present in the directory containing the Dockerfile.
2. Run the following command (as root user) on your shell to build the Docker image
```
docker build -t univlogger .
```
### Running the Univlogger container
1. Run the following command (as root user) on your shell to run the Univlogger tool as a Docker container.
```
docker run --rm -it --name univlogger \
--privileged --pid=host --cgroupns=host \
-v $PWD/logs/:/disprotrack/logs \
-v /boot/config-$(uname -r):/boot/config-$(uname -r):ro \
-v /sys/kernel/debug/:/sys/kernel/debug/ \
univlogger
```
2. Run the microservices/serverless architecture to be logged.

## Limitations
1. Make sure that the application logs printed by your microservice/functions are written to `stdout` and `stderr`.

## Files and Directories
- `.output/`: Contains all the necessary library binaries, BPF object file and the userspace frontend object file compiled by the Makefile from libbpf-bootstrap.
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