# XLP : eXpress Logging for Multi-level Provenance of Distributed Applications

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
git clone https://anonymous.4open.science/r/XLP-11AE
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
docker build -t xlp .
```
### Running the XLP container
1. Run the following command (as root user) on your shell to run the XLP tool as a Docker container.
```
docker run --rm -it --name xlp \
--privileged --pid=host --cgroupns=host \
-v $PWD/logs/:/disprotrack/logs \
-v /boot/config-$(uname -r):/boot/config-$(uname -r):ro \
-v /sys/kernel/debug/:/sys/kernel/debug/ \
xlp
```
2. Run the microservices/serverless architecture to be logged.

## Limitations
1. Make sure that the application logs printed by your microservice/functions are written to `stdout` or `stderr` or a file in `/var/log/app/`.

## Files and Directories
- `.output/`: Contains all the necessary library binaries, BPF object file and the userspace frontend object file compiled by the Makefile from libbpf-bootstrap.
- `.output/writesnoop.skel.h`: Skeleton eBPF header file generated from `writesnoop.skel.h`. Describes the structure of the ELF binary of the eBPF program. Declares wrapper functions for the `writesnoop` app over the libbpf functions for loading, attaching, etc. of the eBPF program
- `writesnoop.bpf.c`: The eBPF program logic, written in C using libbpf C CO-RE
- `writesnoop.c`: The frontend of the eBPF program. Contains the code for opening, loading, attaching of the eBPF program to the right hooks. Also contains the logic for handling of the various syscall log + application log events. Writes to the log file.
- `writesnoop.h`, `util.h`, `syscall.h`, `filesystem.h` and `buffer.h`: Useful user-defined structs and helper functions.