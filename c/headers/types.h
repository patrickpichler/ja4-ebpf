#ifndef __TYPES_H__
#define __TYPES_H__

#include <vmlinux.h>

union protohdrs {
  struct tcphdr tcphdr;
  struct udphdr udphdr;
  struct icmphdr icmphdr;
  struct icmp6hdr icmp6hdr;
  union {
    u8 tcp_extra[40]; // data offset might set it up to 60 bytes
  };
};

union iphdrs {
  struct iphdr iphdr;
  struct ipv6hdr ipv6hdr;
};

struct nethdrs {
  union iphdrs iphdrs;
  union protohdrs protohdrs;
};

#endif // __TYPES_H__
