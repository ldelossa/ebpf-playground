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
int open_tracepoint(struct pt_regs *ctx) {
	__u32 key = 1;
	__u32 init = 1;
	__u32 *value = NULL;
	value = bpf_map_lookup_elem(&shared_map, &key);
	if (value) {
		bpf_printk("got value: %d\n", *value);
		(*value)++;
		bpf_printk("added to value: %d\n", *value);
		bpf_map_update_elem(&shared_map, &key, value, BPF_ANY);
	} else {
		bpf_printk("initialized value to 1\n");
		bpf_map_update_elem(&shared_map, &key, &init, BPF_NOEXIST);
	}
	return 1;
}

char _license[] SEC("license") = "GPL";