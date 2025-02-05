#include <vmlinux.h>
#include <vmlinux_missing.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpf_kfuncs.h"
#include "types.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024 /* 1 MB */);
} events SEC(".maps");

struct event {
  u32 payload_size;
};

// Force BTF for event struct to be exported.
const struct event *unused_event __attribute__((unused));

int __always_inline is_tls_hello(struct bpf_dynptr *payload);

#define BUFFER_SIZE 256
#define min(x, y) ((x) < (y) ? (x) : (y))

int __always_inline submit(struct bpf_dynptr *payload) {
  struct bpf_dynptr ringbuf_ptr;

  u32 payload_size = bpf_dynptr_size(payload);

  if (bpf_ringbuf_reserve_dynptr(&events, sizeof(struct event) + payload_size,
                                 0, &ringbuf_ptr) < 0) {
    goto error;
  }

  struct event *evt = bpf_dynptr_data(&ringbuf_ptr, 0, sizeof(struct event));
  if (!evt) {
    goto error;
  }

  evt->payload_size = payload_size;

  u8 buf[BUFFER_SIZE];
  void *chunk;
  int chunk_size, off;
  u32 i, chunk_cnt, err;

  chunk_cnt = (payload_size + BUFFER_SIZE - 1) / BUFFER_SIZE;

  bpf_for(i, 0, chunk_cnt) {
    off = BUFFER_SIZE * i;
    chunk_size = min(payload_size - off, BUFFER_SIZE);

    asm volatile("%[size] &= 0xFFFF;\n" ::[size] "r"(chunk_size));
    asm volatile("if %[size] <= %[max_size] goto +1;\n"
                 "%[size] = %[max_size];\n" ::[size] "r"(chunk_size),
                 [max_size] "i"(BUFFER_SIZE));

    if (chunk_size == BUFFER_SIZE) {
      chunk = bpf_dynptr_slice(payload, off, buf, BUFFER_SIZE);
      if (!chunk) {
        bpf_printk("BUG! NULL pkt slice pointer");
        goto error;
      }
    } else {
      err = bpf_dynptr_read(buf, chunk_size, payload, off, 0);
      if (err) {
        bpf_printk("BUG! Failed to read packet data err = %d", err);
        goto error;
      }
      chunk = buf;
    }

    err = bpf_dynptr_write(&ringbuf_ptr, sizeof(struct event) + off, chunk,
                           chunk_size, 0);
    if (err) {
      bpf_printk("BUG! Failed to write ringbuf data err = %d", err);
      goto error;
    }
  }

  bpf_ringbuf_submit_dynptr(&ringbuf_ptr, 0);
  return 0;

error:
  bpf_ringbuf_discard_dynptr(&ringbuf_ptr, 0);
  return 1;
}

SEC("cgroup_skb/egress")
int handle_egress(struct __sk_buff *ctx) {

  struct bpf_dynptr data;
  if (bpf_dynptr_from_skb(ctx, 0, &data)) {
    goto error;
  }

  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    bpf_printk("no sock");
    goto out;
  }

  __be16 dst_port = bpf_ntohs(sk->dst_port);

  if (dst_port != 443) {
    goto out;
  }

  u32 offset = 0;
  u8 proto = 0;

  switch (ctx->family) {
  case AF_INET: {
    struct iphdr *iphdrs =
        bpf_dynptr_slice(&data, 0, NULL, bpf_core_type_size(struct iphdr));
    if (!iphdrs) {
      goto error;
    }

    proto = BPF_CORE_READ(iphdrs, protocol);
    offset += iphdrs->ihl * 4;
  } break;
  case AF_INET6: {
    struct ipv6hdr *iphdrs =
        bpf_dynptr_slice(&data, 0, NULL, bpf_core_type_size(struct ipv6hdr));
    if (!iphdrs) {
      goto error;
    }

    proto = BPF_CORE_READ(iphdrs, nexthdr);
    offset += bpf_core_type_size(struct ipv6hdr);
  } break;
  default:
    goto out;
  }

  // We are only interested in TCP for now.
  if (proto != IPPROTO_TCP) {
    goto out;
  }

  struct tcphdr *tcphdr =
      bpf_dynptr_slice(&data, offset, NULL, bpf_core_type_size(struct tcphdr));
  if (!tcphdr) {
    goto error;
  }

  u16 doff = BPF_CORE_READ_BITFIELD(tcphdr, doff);
  offset += doff * 4;

  struct bpf_dynptr payload;
  if (bpf_dynptr_clone(&data, &payload)) {
    goto error;
  }

  if (bpf_dynptr_adjust(&payload, offset, bpf_dynptr_size(&data))) {
    goto error;
  }

  if (!is_tls_hello(&payload)) {
    goto out;
  }

  bpf_printk("tls hello detected");
  submit(&payload);

error:
out:
  return 1;
}

struct tls_record_header {
  u8 content_type;
  union {
    u16 full;
    struct {
      u8 lower;
      u8 higher;
    } split;
  } version;
  u16 length;
} __attribute__((packed));

#define TLS_HEADER_LEN 5

#define HANDSHAKE_TYPE_CLIENT_HELLO 1
#define TLS_CONTENT_TYPE_HANDSHAKE 22

int __always_inline is_tls_hello(struct bpf_dynptr *payload) {
  u8 buf[sizeof(struct tls_record_header)];
  struct tls_record_header *hdr =
      bpf_dynptr_slice(payload, 0, &buf, sizeof(struct tls_record_header));
  if (!hdr) {
    return 0;
  }

  if (hdr->content_type != TLS_CONTENT_TYPE_HANDSHAKE) {
    return 0;
  }

  u8 handshake_type;

  if (bpf_dynptr_read(&handshake_type, 1, payload,
                      sizeof(struct tls_record_header), 0)) {
    return 0;
  }

  if (handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO) {
    return 0;
  }

  // swap bytes of version
  buf[1] ^= buf[2];
  buf[2] ^= buf[1];
  buf[1] ^= buf[2];

  // swap bytes of length
  buf[3] ^= buf[4];
  buf[4] ^= buf[3];
  buf[3] ^= buf[4];

  // We do not have the full package content, meaning we can not fully parse the
  // TLS packet to get the JA4 fingerprint.
  if (hdr->length + TLS_HEADER_LEN > bpf_dynptr_size(payload)) {
    return 0;
  }

  // TLS version 1.0 has the legacy version set to 0x0301
  // TLS version 1.1 has the legacy version set to 0x0302
  // TLS version 1.2 has the legacy version set to 0x0303
  // TLS version 1.3 has the legacy version set to 0x0303. To detect 1.3, the
  // version from the extensions must also be parsed.
  if (hdr->version.split.higher != 0x03 &&
      (hdr->version.split.lower < 0x01 || hdr->version.split.lower > 0x03)) {
    return 0;
  }

  return 1;
}
