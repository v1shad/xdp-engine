CLANG ?= clang
CXX   ?= g++

# Ubuntu keeps architecture-specific headers (asm/types.h) in a multiarch directory.
ARCH_INC := $(firstword $(wildcard /usr/include/$(shell uname -m)-linux-gnu))

# Stage 1 flags: -O2 is REQUIRED (the verifier rejects unoptimized code with function calls),
# -g emits debug info from which BTF is generated, -target bpf selects the BPF backend.
BPF_CFLAGS := -g -O2 -Wall -target bpf
ifneq ($(ARCH_INC),)
BPF_CFLAGS += -I$(ARCH_INC)
endif

all: xdp_prog.bpf.o engine

# Stage 1: C -> BPF bytecode inside an ELF object
xdp_prog.bpf.o: xdp_prog.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Stage 2: C++20 -> native executable, linked against libbpf and yaml-cpp
engine: engine.cpp rule_engine.cpp rule_engine.h storage.cpp storage.h playbook_runner.cpp playbook_runner.h
	$(CXX) -std=c++20 -O2 -Wall -Wextra -pthread engine.cpp rule_engine.cpp storage.cpp playbook_runner.cpp -o $@ -lbpf -lelf -lz -lyaml-cpp -lsqlite3

clean:
	rm -f xdp_prog.bpf.o engine
