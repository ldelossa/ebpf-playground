#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1);
	__uint(map_flags, 0);
} inner_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
	__uint(map_flags, 0);
	/* Multicast group subscribers inner map definition */
	__array(values, typeof(inner_map));
} test_map SEC(".maps") = {
	.values = {
		[0xDEADBEEF] = &inner_map,
	},
};

int prog(void *ctx) {
	return 0;
}
