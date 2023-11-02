static_nested_map: static_nested_map.bpf.c vmlinux.h
	clang -Wall -g3 -O3 -target bpf -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

