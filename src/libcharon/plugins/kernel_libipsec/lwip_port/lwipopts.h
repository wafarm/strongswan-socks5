/*
 * Minimal NO_SYS lwIP configuration for the kernel-libipsec SOCKS5 backend.
 */

#ifndef KERNEL_LIBIPSEC_LWIPOPTS_H_
#define KERNEL_LIBIPSEC_LWIPOPTS_H_

#define NO_SYS                          1
#define SYS_LIGHTWEIGHT_PROT            0
#define LWIP_TIMERS                     1
#define LWIP_TIMERS_CUSTOM              0

#define LWIP_IPV4                       1
#define LWIP_IPV6                       1
#define IP_FORWARD                      0
#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define LWIP_IPV6_FORWARD               0
#define LWIP_IPV6_REASS                 1
#define LWIP_IPV6_FRAG                  1
#ifdef USE_KERNEL_LIBIPSEC_SOCKS_PORTABLE
/* Required on 64-bit targets where the reassembly helper exceeds the header. */
#define IPV6_FRAG_COPYHEADER            1
#endif
#define IP_REASS_MAX_PBUFS              64
#define MEMP_NUM_REASSDATA              16

#define LWIP_RAW                        1
#define LWIP_ICMP                       1
#define LWIP_ICMP6                      1
#define LWIP_IGMP                       0
#define LWIP_IPV6_MLD                   0

#define LWIP_TCP                        1
#define LWIP_CALLBACK_API               1
#define TCP_MSS                         1460
#define TCP_WND                         32768
#define TCP_SND_BUF                     32768
#define TCP_SND_QUEUELEN                512
#define TCP_QUEUE_OOSEQ                 1
#define TCP_LISTEN_BACKLOG              0
#define MEMP_NUM_TCP_PCB                128
#define MEMP_NUM_TCP_PCB_LISTEN         0
#define MEMP_NUM_TCP_SEG                1024
#define LWIP_TCP_PCB_NUM_EXT_ARGS       1
#define LWIP_IPV6_NUM_ADDRESSES         1

#define LWIP_UDP                        1
#define MEMP_NUM_UDP_PCB                16
#define LWIP_DNS                        1
#define DNS_TABLE_SIZE                  128
#define DNS_MAX_SERVERS                 4
#define DNS_MAX_RETRIES                 4
#define DNS_MAX_NAME_LENGTH             256
#define DNS_RAND_TXID                   LWIP_RAND

#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define LWIP_NETIF_API                  0
#define LWIP_TCPIP_CORE_LOCKING         0

#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_IPV6_DHCP6                 0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS   0
#define LWIP_ND6_ALLOW_RA_UPDATES       0
#define LWIP_ND6_QUEUEING               0
#define LWIP_ND6_TCP_REACHABILITY_HINTS 0

#define PPP_SUPPORT                     0
#define LWIP_PPP_API                    0
#define PPPOS_SUPPORT                   0
#define PPPOE_SUPPORT                   0
#define PPPOL2TP_SUPPORT                0
#define PPP_IPV4_SUPPORT                0
#define PPP_IPV6_SUPPORT                0
#define CCP_SUPPORT                     0
#define MPPE_SUPPORT                    0

#define LWIP_SINGLE_NETIF               1
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_HAVE_LOOPIF                0
#define LWIP_NETIF_HOSTNAME             0

/* Allocate variable-sized protocol objects from the process heap. */
#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   4
#define PBUF_POOL_SIZE                  256
#define PBUF_POOL_BUFSIZE               1700

#define LWIP_STATS                      0
#define LWIP_DEBUG                      0
#define LWIP_CHECKSUM_ON_COPY           1
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_UDP                1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_UDP              1
#define CHECKSUM_CHECK_TCP              1

/* Randomize TCP ISNs, ephemeral TCP/UDP ports and DNS transaction IDs. */
#define LWIP_HOOK_TCP_ISN(local_ip, local_port, remote_ip, remote_port) \
	((void)(local_ip), (void)(local_port), (void)(remote_ip), \
	 (void)(remote_port), LWIP_RAND())

#endif /* KERNEL_LIBIPSEC_LWIPOPTS_H_ */
