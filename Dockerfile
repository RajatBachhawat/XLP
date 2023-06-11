FROM ubuntu:jammy

RUN apt-get update && \
    apt-get install -y build-essential \
                        zlib1g-dev libevent-dev \
                        libelf-dev libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /disprotrack
WORKDIR /disprotrack

ADD .output/ .output/
COPY ./writesnoop.bpf.c ./writesnoop.bpf.c
COPY ./writesnoop.c ./writesnoop.c
COPY ./writesnoop.h ./writesnoop.h
COPY ./syscall.h ./syscall.h
COPY ./util.h ./util.h
COPY ./buffer.h ./buffer.h
COPY ./filesystem.h ./filesystem.h
COPY ./writesnoop.mk ./Makefile

RUN make
CMD ./writesnoop -c > ./logs/univlog.json
