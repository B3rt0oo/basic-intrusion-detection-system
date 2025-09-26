CLANG ?= clang
LLC ?= llc
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86

all: ids_bpf.o

ids_bpf.o: ids_kern.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -f ids_bpf.o

