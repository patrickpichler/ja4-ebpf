#ifndef __BPF_KFUNCS_H__
#define __BPF_KFUNCS_H__

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>

extern int bpf_dynptr_from_skb(struct __sk_buff *s, u64 flags,
                               struct bpf_dynptr *ptr__uninit) __ksym;

extern void *bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
                              void *buffer__opt, u32 buffer__szk) __ksym;

extern int bpf_dynptr_adjust(const struct bpf_dynptr *p, u32 start,
                             u32 end) __ksym;

extern int bpf_dynptr_clone(const struct bpf_dynptr *p,
                            struct bpf_dynptr *clone__uninit) __ksym;

extern __u32 bpf_dynptr_size(const struct bpf_dynptr *p) __ksym;

#endif // __BPF_KFUNCS_H__
