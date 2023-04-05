FROM ubuntu:jammy

RUN apt-get update && \
    apt-get install -y build-essential git \
                        zlib1g-dev libevent-dev \
                        libelf-dev llvm \
                        clang libc6-dev-i386

RUN mkdir /disprotrack
WORKDIR /disprotrack
RUN git clone https://github.com/libbpf/libbpf-bootstrap.git && \
    cd libbpf-bootstrap && \
    git submodule update --init --recursive
COPY ./writesnoop.bpf.c ./writesnoop.bpf.c
COPY ./writesnoop.c ./writesnoop.c
COPY ./writesnoop.h ./writesnoop.h
COPY ./syscall.h ./syscall.h
COPY ./util.h ./util.h
COPY ./Makefile ./Makefile

RUN make
CMD ./writesnoop > ./logs/univlog.json
