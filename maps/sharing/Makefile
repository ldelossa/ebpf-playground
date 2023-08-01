all: tracepoint_openat.o tracepoint_read.o

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

tracepoint_openat.o: tracepoint_openat.c vmlinux.h
	clang -Wall -g3 -O3 -target bpf -c $< -o $@

tracepoint_read.o: tracepoint_read.c vmlinux.h
	clang -Wall -g3 -O3 -target bpf -c $< -o $@

.PHONY:
load: tracepoint_openat.o tracepoint_read.o
	sudo bpftool prog load tracepoint_openat.o /sys/fs/bpf/tracepoint_open autoattach
	sudo bpftool prog load tracepoint_read.o /sys/fs/bpf/tracepoint_open_read autoattach

unload:
	sudo rm -rf /sys/fs/bpf/tracepoint_open
	sudo rm -rf /sys/fs/bpf/tracepoint_open_read
	sudo rm -rf /sys/fs/bpf/shared_map