#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1024);
    	__uint(pinning, LIBBPF_PIN_BY_NAME);
} shared_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int open_tracepoint_reader(struct pt_regs *ctx) {
	int key = 1;
	int *value = NULL;
	value = bpf_map_lookup_elem(&shared_map, &key);
	if (value) {
		bpf_printk("read value: %d\n", *value);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";