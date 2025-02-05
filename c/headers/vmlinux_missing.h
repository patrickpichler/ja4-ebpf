#ifndef __VMLINUX_MISSING_H__
#define __VMLINUX_MISSING_H__

/* Taken from kernel include/linux/socket.h. */
/* Supported address families. */
#define AF_UNSPEC 0
#define AF_UNIX 1      /* Unix domain sockets 		*/
#define AF_LOCAL 1     /* POSIX name for AF_UNIX	*/
#define AF_INET 2      /* Internet IP Protocol 	*/
#define AF_AX25 3      /* Amateur Radio AX.25 		*/
#define AF_IPX 4       /* Novell IPX 			*/
#define AF_APPLETALK 5 /* AppleTalk DDP 		*/
#define AF_NETROM 6    /* Amateur Radio NET/ROM 	*/
#define AF_BRIDGE 7    /* Multiprotocol bridge 	*/
#define AF_ATMPVC 8    /* ATM PVCs			*/
#define AF_X25 9       /* Reserved for X.25 project 	*/
#define AF_INET6 10    /* IP version 6			*/
#define AF_ROSE 11     /* Amateur Radio X.25 PLP	*/
#define AF_DECnet 12   /* Reserved for DECnet project	*/
#define AF_NETBEUI 13  /* Reserved for 802.2LLC project*/
#define AF_SECURITY 14 /* Security callback pseudo AF */
#define AF_KEY 15      /* PF_KEY key management API */
#define AF_NETLINK 16
#define AF_ROUTE AF_NETLINK /* Alias to emulate 4.4BSD */
#define AF_PACKET 17        /* Packet family		*/
#define AF_ASH 18           /* Ash				*/
#define AF_ECONET 19        /* Acorn Econet			*/
#define AF_ATMSVC 20        /* ATM SVCs			*/
#define AF_RDS 21           /* RDS sockets 			*/
#define AF_SNA 22           /* Linux SNA Project (nutters!) */
#define AF_IRDA 23          /* IRDA sockets			*/
#define AF_PPPOX 24         /* PPPoX sockets		*/
#define AF_WANPIPE 25       /* Wanpipe API Sockets */
#define AF_LLC 26           /* Linux LLC			*/
#define AF_IB 27            /* Native InfiniBand address	*/
#define AF_MPLS 28          /* MPLS */
#define AF_CAN 29           /* Controller Area Network      */
#define AF_TIPC 30          /* TIPC sockets			*/
#define AF_BLUETOOTH 31     /* Bluetooth sockets 		*/

#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 4
#endif

#ifndef IPPROTO_DCCP
#define IPPROTO_DCCP 33
#endif

#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE 136
#endif

#endif // __VMLINUX_MISSING_H__
