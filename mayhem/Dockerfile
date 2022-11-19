FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential clang libc++-dev libc++abi-dev

COPY . /repo
WORKDIR /repo
RUN g++ ISOBMFF-Dump/main.cpp /repo/ISOBMFF/source/* -I /repo/ISOBMFF/include/ -o dump

FROM ubuntu:22.04 as package
COPY --from=builder /repo/dump /
